//! Background networking thread.
//!
//! The UI never touches the network. It sends [`Command`]s over a bounded channel
//! and drains [`Event`]s every frame; the worker wakes the UI through the `notify`
//! callback (which calls `ctx.request_repaint()`).

use std::sync::Arc;
use std::thread;

use kikonnect_client_core::{
    run_host, CancellationToken, ClientConfig, HostConfig, HostEvent, JoinConfig, PlayerCommand,
    PlayerEvent, PlayerExit, PlayerSession, ServiceDef,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

/// Capacity of the command and event channels.
const CHANNEL_CAPACITY: usize = 256;

/// Requests from the UI.
#[derive(Debug)]
pub enum Command {
    /// Start sharing services (restarts if already running).
    StartHost {
        client: ClientConfig,
        host: HostConfig,
    },
    /// Stop sharing.
    StopHost,
    /// Join a tunnel.
    Join {
        client: ClientConfig,
        join: JoinConfig,
    },
    /// Leave the joined tunnel.
    Leave,
    /// Move a joined service to another local port.
    SetLocalPort { service_id: u8, port: u16 },
}

/// Notifications for the UI.
#[derive(Debug)]
pub enum Event {
    /// Host status or player change.
    Host(HostEvent),
    /// The host task finished (after a stop or a fatal error).
    HostEnded,
    /// Joined the tunnel; local listeners follow as [`Event::Player`] events.
    Joined {
        host_name: String,
        services: Vec<ServiceDef>,
    },
    /// Joining failed.
    JoinFailed(String),
    /// Event of a running player session.
    Player(PlayerEvent),
    /// The player session ended.
    JoinEnded(Result<PlayerExit, String>),
}

/// UI-side handle to the worker.
pub struct Worker {
    commands: mpsc::Sender<Command>,
    /// Events produced by the worker.
    pub events: mpsc::Receiver<Event>,
}

impl Worker {
    /// Spawns the worker thread. `notify` is called after every event.
    pub fn spawn(notify: Arc<dyn Fn() + Send + Sync>) -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("kikonnect-net")
            .build()?;
        thread::Builder::new()
            .name("kikonnect-worker".into())
            .spawn(move || runtime.block_on(run(cmd_rx, Sink { event_tx, notify })))?;
        Ok(Self {
            commands: cmd_tx,
            events: event_rx,
        })
    }

    /// Sends a command without blocking. Returns `false` if the queue is full or
    /// the worker is gone.
    pub fn send(&self, cmd: Command) -> bool {
        self.commands.try_send(cmd).is_ok()
    }
}

/// Where tasks deliver events.
#[derive(Clone)]
struct Sink {
    event_tx: mpsc::Sender<Event>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl Sink {
    async fn emit(&self, event: Event) {
        // A closed channel means the UI is shutting down.
        let _ = self.event_tx.send(event).await;
        (self.notify)();
    }
}

struct Task {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl Task {
    async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

async fn run(mut commands: mpsc::Receiver<Command>, sink: Sink) {
    let mut host: Option<Task> = None;
    let mut player: Option<Task> = None;
    let mut player_cmds: Option<mpsc::Sender<PlayerCommand>> = None;

    while let Some(cmd) = commands.recv().await {
        match cmd {
            Command::StartHost { client, host: cfg } => {
                if let Some(old) = host.take() {
                    old.stop().await;
                }
                host = Some(start_host(client, cfg, sink.clone()));
            }
            Command::StopHost => {
                if let Some(old) = host.take() {
                    old.stop().await;
                }
            }
            Command::Join { client, join } => {
                if let Some(old) = player.take() {
                    old.stop().await;
                }
                let (tx, rx) = mpsc::channel(16);
                player_cmds = Some(tx);
                player = Some(start_join(client, join, rx, sink.clone()));
            }
            Command::Leave => {
                player_cmds = None;
                if let Some(old) = player.take() {
                    old.stop().await;
                }
            }
            Command::SetLocalPort { service_id, port } => {
                if let Some(tx) = &player_cmds {
                    if tx
                        .try_send(PlayerCommand::SetLocalPort { service_id, port })
                        .is_err()
                    {
                        warn!("could not change local port: session busy or ended");
                    }
                }
            }
        }
    }
    // The UI is gone: stop everything so listeners and connections close cleanly.
    if let Some(t) = host {
        t.stop().await;
    }
    if let Some(t) = player {
        t.stop().await;
    }
}

fn start_host(client: ClientConfig, config: HostConfig, sink: Sink) -> Task {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let handle = tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
        let forward = {
            let sink = sink.clone();
            async move {
                while let Some(event) = rx.recv().await {
                    sink.emit(Event::Host(event)).await;
                }
            }
        };
        // `run_host` consumes `tx`, so the forwarder ends when it returns.
        let (result, ()) = tokio::join!(run_host(client, config, tx, token), forward);
        if let Err(e) = result {
            warn!("host stopped: {e}");
        }
        sink.emit(Event::HostEnded).await;
    });
    Task { cancel, handle }
}

fn start_join(
    client: ClientConfig,
    config: JoinConfig,
    commands: mpsc::Receiver<PlayerCommand>,
    sink: Sink,
) -> Task {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let handle = tokio::spawn(async move {
        let session = tokio::select! {
            _ = token.cancelled() => return,
            r = PlayerSession::connect(&client, &config) => r,
        };
        let session = match session {
            Ok(s) => s,
            Err(e) => {
                sink.emit(Event::JoinFailed(e.to_string())).await;
                return;
            }
        };
        sink.emit(Event::Joined {
            host_name: session.host_name().to_owned(),
            services: session.services().to_vec(),
        })
        .await;
        let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
        let forward = {
            let sink = sink.clone();
            async move {
                while let Some(event) = rx.recv().await {
                    sink.emit(Event::Player(event)).await;
                }
            }
        };
        let (result, ()) = tokio::join!(session.run(tx, Some(commands), token), forward);
        sink.emit(Event::JoinEnded(result.map_err(|e| e.to_string())))
            .await;
    });
    Task { cancel, handle }
}

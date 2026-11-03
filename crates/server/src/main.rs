//! `kikonnect-server` command line interface.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use kikonnect_server::{health, reload, tls, Server, ServerConfig};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "kikonnect-server", version, about = "Kikonnect relay server")]
struct Cli {
    /// Log output format.
    #[arg(
        long,
        global = true,
        env = "KIKONNECT_LOG_FORMAT",
        value_enum,
        default_value_t = LogFormat::Text
    )]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the relay server.
    Serve(ServeArgs),
    /// Generate a self-signed certificate for development.
    GenCert(GenCertArgs),
    /// Check a running server on this machine (exit code 0 = healthy). Used by the
    /// Docker HEALTHCHECK.
    Healthcheck(HealthcheckArgs),
}

#[derive(Debug, Args)]
struct HealthcheckArgs {
    /// Address of the server to check. The default is derived from
    /// KIKONNECT_LISTEN (same port, on 127.0.0.1).
    #[arg(long, env = "KIKONNECT_HEALTHCHECK_ADDR")]
    addr: Option<SocketAddr>,
    /// The listen address of the server, used to find the port when --addr is not set.
    #[arg(long, env = "KIKONNECT_LISTEN", default_value = "0.0.0.0:7000")]
    listen: SocketAddr,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// UDP address to listen on (QUIC).
    #[arg(long, env = "KIKONNECT_LISTEN", default_value = "0.0.0.0:7000")]
    listen: SocketAddr,
    /// PEM certificate chain.
    #[arg(long, env = "KIKONNECT_CERT", default_value = "/certs/fullchain.pem")]
    cert: PathBuf,
    /// PEM private key.
    #[arg(long, env = "KIKONNECT_KEY", default_value = "/certs/privkey.pem")]
    key: PathBuf,
    /// Maximum number of online tunnels.
    #[arg(long, env = "KIKONNECT_MAX_TUNNELS", default_value_t = 500)]
    max_tunnels: usize,
    /// Maximum number of players per tunnel.
    #[arg(long, env = "KIKONNECT_MAX_PLAYERS_PER_TUNNEL", default_value_t = 32)]
    max_players_per_tunnel: usize,
    /// Maximum number of concurrent UDP sessions per tunnel.
    #[arg(
        long,
        env = "KIKONNECT_MAX_UDP_SESSIONS_PER_TUNNEL",
        default_value_t = 1024
    )]
    max_udp_sessions_per_tunnel: usize,
    /// Maximum number of concurrent streams (TCP connections) per client connection.
    #[arg(
        long,
        env = "KIKONNECT_MAX_STREAMS_PER_CONNECTION",
        default_value_t = 256
    )]
    max_streams_per_connection: u32,
    /// Maximum number of concurrent QUIC connections.
    #[arg(long, env = "KIKONNECT_MAX_CONNECTIONS", default_value_t = 10_000)]
    max_connections: usize,
    /// Idle timeout of UDP sessions, in seconds.
    #[arg(long, env = "KIKONNECT_UDP_SESSION_TIMEOUT", default_value_t = 60)]
    udp_session_timeout: u64,
    /// How long a name stays reserved after its host disconnected, in seconds.
    #[arg(long, env = "KIKONNECT_NAME_GRACE_PERIOD", default_value_t = 60)]
    name_grace_period: u64,
    /// Register/Join burst allowance per source IP.
    #[arg(long, env = "KIKONNECT_RATE_LIMIT_BURST", default_value_t = 10)]
    rate_limit_burst: u32,
    /// Register/Join attempts per source IP and minute (0 disables rate limiting).
    #[arg(long, env = "KIKONNECT_RATE_LIMIT_PER_MINUTE", default_value_t = 30)]
    rate_limit_per_minute: u32,
}

#[derive(Debug, Args)]
struct GenCertArgs {
    /// Host name(s) or IP address(es) for the certificate (comma separated or repeated).
    /// localhost, 127.0.0.1 and ::1 are always included.
    #[arg(
        long = "hostname",
        env = "KIKONNECT_GEN_CERT_HOSTNAME",
        value_delimiter = ',',
        default_value = "localhost"
    )]
    hostnames: Vec<String>,
    /// Output directory for fullchain.pem and privkey.pem.
    #[arg(long, env = "KIKONNECT_GEN_CERT_OUT", default_value = "./dev-certs")]
    out: PathBuf,
}

fn init_logging(format: LogFormat) {
    let filter =
        EnvFilter::try_from_env("KIKONNECT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.log_format);
    let result = match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::GenCert(args) => gen_cert(args),
        Command::Healthcheck(args) => healthcheck(args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let (certs, key) = tls::load_pem(&args.cert, &args.key).context("loading TLS certificate")?;
    let crypto = tls::server_crypto(certs, key)?;
    let config = ServerConfig {
        listen: args.listen,
        max_tunnels: args.max_tunnels,
        max_players_per_tunnel: args.max_players_per_tunnel,
        max_udp_sessions_per_tunnel: args.max_udp_sessions_per_tunnel,
        max_streams_per_connection: args.max_streams_per_connection,
        max_connections: args.max_connections,
        udp_session_timeout: Duration::from_secs(args.udp_session_timeout.max(1)),
        name_grace_period: Duration::from_secs(args.name_grace_period),
        rate_limit_burst: args.rate_limit_burst,
        rate_limit_per_minute: args.rate_limit_per_minute,
        ..ServerConfig::default()
    };
    let server = Server::bind(config, crypto)?;
    info!(
        listen = %server.local_addr()?,
        version = env!("CARGO_PKG_VERSION"),
        "kikonnect server listening (QUIC over UDP)"
    );
    let shutdown = CancellationToken::new();
    tokio::spawn(reload::watch(
        server.crypto_updater(),
        args.cert.clone(),
        args.key.clone(),
        reload::DEFAULT_POLL_INTERVAL,
        shutdown.clone(),
    ));
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            shutdown_signal().await;
            info!("shutdown signal received");
            shutdown.cancel();
        }
    });
    server.run(shutdown).await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                error!("cannot install SIGTERM handler: {e}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn gen_cert(args: GenCertArgs) -> anyhow::Result<()> {
    let generated = tls::generate_self_signed(&args.hostnames)?;
    let (cert, key) = tls::write_generated(&generated, &args.out)
        .with_context(|| format!("writing certificate to {}", args.out.display()))?;
    info!(
        cert = %cert.display(),
        key = %key.display(),
        hostnames = ?args.hostnames,
        "generated self-signed development certificate"
    );
    Ok(())
}

async fn healthcheck(args: HealthcheckArgs) -> anyhow::Result<()> {
    let addr = args
        .addr
        .unwrap_or_else(|| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, args.listen.port())));
    health::check(addr, Duration::from_secs(args.timeout.max(1)))
        .await
        .with_context(|| format!("server at {addr} is unhealthy"))?;
    println!("healthy");
    Ok(())
}

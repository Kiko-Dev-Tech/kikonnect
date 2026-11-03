//! The egui application.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use eframe::egui::{self, Color32, RichText};
use kikonnect_client_core::protocol::{normalize_name, MAX_SERVICES};
use kikonnect_client_core::{ClientConfig, HostConfig, HostStatus, JoinConfig, ServiceDef};
use tracing::{warn, Level};

use crate::logbuf::LogBuffer;
use crate::settings::{Kind, ServiceRow, Settings};
use crate::state::{format_ago, JoinPhase, State};
use crate::worker::{Command, Worker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Host,
    Join,
    Settings,
}

/// Top-level application state.
pub struct App {
    settings: Settings,
    settings_path: Option<PathBuf>,
    worker: Worker,
    state: State,
    logs: LogBuffer,
    tab: Tab,
    host_password: String,
    join_password: String,
    /// Validation message for the host tab.
    host_input_error: Option<String>,
    join_input_error: Option<String>,
    show_log: bool,
}

impl App {
    /// Creates the app, loading settings and starting the worker thread.
    pub fn new(cc: &eframe::CreationContext<'_>, logs: LogBuffer) -> anyhow::Result<Self> {
        let settings_path = Settings::default_path();
        let settings = settings_path
            .as_deref()
            .map(Settings::load)
            .unwrap_or_default();
        let ctx = cc.egui_ctx.clone();
        let worker = Worker::spawn(Arc::new(move || ctx.request_repaint()))?;
        Ok(Self {
            settings,
            settings_path,
            worker,
            state: State::default(),
            logs,
            tab: Tab::Host,
            host_password: String::new(),
            join_password: String::new(),
            host_input_error: None,
            join_input_error: None,
            show_log: false,
        })
    }

    fn save_settings(&self) {
        if let Some(path) = &self.settings_path {
            if let Err(e) = self.settings.save(path) {
                warn!("could not save settings to {}: {e}", path.display());
            }
        }
    }

    fn client_config(&self) -> ClientConfig {
        let mut cfg = ClientConfig::new(self.settings.server_addr.trim());
        cfg.insecure = self.settings.insecure;
        cfg
    }

    fn start_host(&mut self) {
        self.host_input_error = None;
        let name = match normalize_name(&self.settings.host_name) {
            Ok(n) => n,
            Err(e) => {
                self.host_input_error = Some(format!("Invalid name: {e}"));
                return;
            }
        };
        if self.settings.services.is_empty() {
            self.host_input_error = Some("Add at least one service.".into());
            return;
        }
        if self.settings.services.iter().any(|s| s.port == 0) {
            self.host_input_error = Some("Ports must be between 1 and 65535.".into());
            return;
        }
        let services: Vec<ServiceDef> = self.settings.service_defs();
        if let Err(e) = kikonnect_client_core::protocol::validate_services(&services) {
            self.host_input_error = Some(e);
            return;
        }
        self.settings.host_name = name.clone();
        self.save_settings();
        let mut host = HostConfig::new(name, services);
        host.password = Some(self.host_password.clone()).filter(|p| !p.is_empty());
        self.state.host.last_error = None;
        self.state.host.status = Some(HostStatus::Connecting);
        if !self.worker.send(Command::StartHost {
            client: self.client_config(),
            host,
        }) {
            self.state.host.status = None;
            self.host_input_error = Some("The network thread is busy; try again.".into());
        }
    }

    fn stop_host(&mut self) {
        self.state.host.stopping = true;
        if !self.worker.send(Command::StopHost) {
            self.state.host.stopping = false;
        }
    }

    fn start_join(&mut self) {
        self.join_input_error = None;
        let name = match normalize_name(&self.settings.join_name) {
            Ok(n) => n,
            Err(e) => {
                self.join_input_error = Some(format!("Invalid name: {e}"));
                return;
            }
        };
        self.settings.join_name = name.clone();
        self.save_settings();
        let mut join = JoinConfig::new(name);
        join.password = Some(self.join_password.clone()).filter(|p| !p.is_empty());
        self.state.join.message = None;
        self.state.join.phase = JoinPhase::Connecting;
        if !self.worker.send(Command::Join {
            client: self.client_config(),
            join,
        }) {
            self.state.join.phase = JoinPhase::Idle;
            self.join_input_error = Some("The network thread is busy; try again.".into());
        }
    }

    fn leave(&mut self) {
        self.state.join.stopping = true;
        if !self.worker.send(Command::Leave) {
            self.state.join.stopping = false;
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.worker.events.try_recv() {
            self.state.apply(event);
        }
    }

    // ---- tabs ---------------------------------------------------------------

    fn host_tab(&mut self, ui: &mut egui::Ui) {
        let running = self.state.host.running();
        ui.add_enabled_ui(!running, |ui| {
            egui::Grid::new("host_form").num_columns(2).show(ui, |ui| {
                ui.label("Name");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.host_name)
                        .hint_text("e.g. kilian (a-z, 0-9, -)")
                        .desired_width(240.0),
                );
                ui.end_row();
                ui.label("Password");
                ui.add(
                    egui::TextEdit::singleline(&mut self.host_password)
                        .password(true)
                        .hint_text("optional")
                        .desired_width(240.0),
                );
                ui.end_row();
            });

            ui.add_space(6.0);
            ui.label(RichText::new("Services to share").strong());
            let mut remove = None;
            egui::Grid::new("host_services")
                .num_columns(4)
                .spacing([8.0, 4.0])
                .show(ui, |ui| {
                    for (i, row) in self.settings.services.iter_mut().enumerate() {
                        ui.add(
                            egui::TextEdit::singleline(&mut row.label)
                                .min_size(egui::vec2(260.0, 24.0))
                                .hint_text("label")
                                .desired_width(260.0),
                        );
                        egui::ComboBox::from_id_salt(("kind", i))
                            .width(60.0)
                            .selected_text(match row.kind {
                                Kind::Tcp => "TCP",
                                Kind::Udp => "UDP",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut row.kind, Kind::Tcp, "TCP");
                                ui.selectable_value(&mut row.kind, Kind::Udp, "UDP");
                            });
                        ui.add(egui::DragValue::new(&mut row.port).range(1..=65535));
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
            if let Some(i) = remove {
                self.settings.services.remove(i);
            }
            if ui
                .add_enabled(
                    self.settings.services.len() < MAX_SERVICES,
                    egui::Button::new("+ Add service"),
                )
                .clicked()
            {
                self.settings.services.push(ServiceRow {
                    label: String::new(),
                    kind: Kind::Tcp,
                    port: 25565,
                });
            }
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let host = &self.state.host;
            if running {
                if ui
                    .add_enabled(!host.stopping, egui::Button::new("Stop"))
                    .clicked()
                {
                    self.stop_host();
                }
            } else if ui.button("Start").clicked() {
                self.start_host();
            }
            ui.add_space(8.0);
            self.host_status(ui);
        });
        if let Some(e) = &self.host_input_error {
            ui.colored_label(Color32::LIGHT_RED, e);
        }

        if let Some(name) = self.state.host.online_name().map(str::to_owned) {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Join name:");
                ui.label(RichText::new(&name).monospace().strong());
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(name.clone());
                }
            });
            if !self.host_password.is_empty() {
                ui.small("Players also need the password.");
            }
        }

        ui.add_space(10.0);
        ui.label(RichText::new("Connected players").strong());
        if self.state.host.players.is_empty() {
            ui.weak("Nobody connected.");
        } else {
            let now = SystemTime::now();
            egui::Grid::new("players").striped(true).show(ui, |ui| {
                ui.strong("ID");
                ui.strong("IP");
                ui.strong("Connected");
                ui.end_row();
                for p in &self.state.host.players {
                    ui.label(p.player_id.to_string());
                    ui.label(p.addr.ip().to_string());
                    ui.label(format_ago(p.since, now));
                    ui.end_row();
                }
            });
        }
    }

    fn host_status(&self, ui: &mut egui::Ui) {
        let host = &self.state.host;
        if host.stopping {
            ui.label("Stopping...");
            return;
        }
        match &host.status {
            None => {
                if let Some(e) = &host.last_error {
                    ui.colored_label(Color32::LIGHT_RED, format!("Error: {e}"));
                } else {
                    ui.weak("Offline");
                }
            }
            Some(HostStatus::Connecting) => {
                ui.add(egui::Spinner::new());
                ui.label("Connecting...");
            }
            Some(HostStatus::Online { .. }) => {
                ui.colored_label(Color32::LIGHT_GREEN, "Online");
                if let Some(rtt) = host.latency {
                    ui.weak(format!("{} ms", rtt.as_millis()));
                }
            }
            Some(HostStatus::Reconnecting {
                attempt,
                delay,
                reason,
            }) => {
                ui.add(egui::Spinner::new());
                ui.colored_label(
                    Color32::YELLOW,
                    format!(
                        "Reconnecting (attempt {attempt}, in {}s): {reason}",
                        delay.as_secs().max(1)
                    ),
                );
            }
            Some(HostStatus::Failed(msg)) => {
                ui.colored_label(Color32::LIGHT_RED, format!("Error: {msg}"));
            }
            Some(HostStatus::Stopped) => {
                ui.weak("Offline");
            }
        }
    }

    fn join_tab(&mut self, ui: &mut egui::Ui) {
        let phase_idle = self.state.join.phase == JoinPhase::Idle && !self.state.join.stopping;
        ui.add_enabled_ui(phase_idle, |ui| {
            egui::Grid::new("join_form").num_columns(2).show(ui, |ui| {
                ui.label("Host name");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.join_name)
                        .hint_text("name of the host")
                        .desired_width(240.0),
                );
                ui.end_row();
                ui.label("Password");
                ui.add(
                    egui::TextEdit::singleline(&mut self.join_password)
                        .password(true)
                        .hint_text("if required")
                        .desired_width(240.0),
                );
                ui.end_row();
            });
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            match self.state.join.phase {
                JoinPhase::Idle if !self.state.join.stopping => {
                    if ui.button("Connect").clicked() {
                        self.start_join();
                    }
                }
                _ => {
                    if ui
                        .add_enabled(!self.state.join.stopping, egui::Button::new("Disconnect"))
                        .clicked()
                    {
                        self.leave();
                    }
                }
            }
            ui.add_space(8.0);
            match self.state.join.phase {
                JoinPhase::Connecting => {
                    ui.add(egui::Spinner::new());
                    ui.label("Connecting...");
                }
                JoinPhase::Joined => {
                    ui.colored_label(
                        Color32::LIGHT_GREEN,
                        format!("Connected to {}", self.state.join.host_name),
                    );
                    if let Some(rtt) = self.state.join.latency {
                        ui.weak(format!("{} ms", rtt.as_millis()));
                    }
                }
                JoinPhase::Idle => {
                    if let Some(msg) = &self.state.join.message {
                        ui.colored_label(Color32::LIGHT_RED, msg);
                    }
                }
            }
        });
        if let Some(e) = &self.join_input_error {
            ui.colored_label(Color32::LIGHT_RED, e);
        }

        if self.state.join.phase == JoinPhase::Joined {
            ui.add_space(10.0);
            ui.label(RichText::new("Services").strong());
            let mut change = None;
            for svc in &mut self.state.join.services {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&svc.def.label).strong());
                        ui.label("Local port:");
                        let edit = ui.add(
                            egui::TextEdit::singleline(&mut svc.port_text).desired_width(60.0),
                        );
                        let submitted =
                            edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if (submitted || ui.button("Apply").clicked())
                            && svc.port_text.trim().parse::<u16>().is_ok()
                        {
                            if let Ok(port) = svc.port_text.trim().parse::<u16>() {
                                change = Some((svc.def.id, port));
                            }
                        }
                    });
                    if let Some(text) = svc.instruction() {
                        ui.horizontal(|ui| {
                            ui.label(&text);
                            if let Some(local) = svc.local {
                                if ui.small_button("Copy address").clicked() {
                                    ui.ctx().copy_text(format!("localhost:{}", local.port()));
                                }
                            }
                        });
                    }
                    if let Some(e) = &svc.error {
                        ui.colored_label(Color32::LIGHT_RED, e);
                    }
                });
            }
            if let Some((service_id, port)) = change {
                self.worker.send(Command::SetLocalPort { service_id, port });
            }
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("settings").num_columns(2).show(ui, |ui| {
            ui.label("Server address");
            ui.add(
                egui::TextEdit::singleline(&mut self.settings.server_addr)
                    .hint_text("tunnel.example.com:7000")
                    .desired_width(260.0),
            );
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.checkbox(
            &mut self.settings.insecure,
            "Allow insecure / self-signed certificates",
        );
        if self.settings.insecure {
            ui.colored_label(
                Color32::YELLOW,
                "Development only! Anyone on the network path can impersonate the server \
                 and read your traffic.",
            );
        }
        ui.add_space(8.0);
        if let Some(path) = &self.settings_path {
            ui.weak(format!("Config file: {}", path.display()));
        }
        ui.weak("Changes apply the next time you start hosting or connect.");
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("log_panel").show(ui, |ui| {
            ui.horizontal(|ui| {
                let arrow = if self.show_log { "v" } else { ">" };
                if ui.button(format!("{arrow} Log")).clicked() {
                    self.show_log = !self.show_log;
                }
                if self.show_log && ui.button("Clear").clicked() {
                    self.logs.clear();
                }
            });
            if self.show_log {
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .stick_to_bottom(true)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for (level, line) in self.logs.snapshot() {
                            let color = match level {
                                Level::ERROR => Color32::LIGHT_RED,
                                Level::WARN => Color32::YELLOW,
                                Level::INFO => ui.visuals().text_color(),
                                _ => ui.visuals().weak_text_color(),
                            };
                            ui.label(RichText::new(line).monospace().size(11.0).color(color));
                        }
                    });
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_events();
        // Keep relative times ("connected 2 min ago") fresh while players are listed.
        if !self.state.host.players.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }

        egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Host, "Host");
                ui.selectable_value(&mut self.tab, Tab::Join, "Join");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
            });
        });
        self.log_panel(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Host => self.host_tab(ui),
                Tab::Join => self.join_tab(ui),
                Tab::Settings => self.settings_tab(ui),
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.save_settings();
        // Stopping is best effort; the OS reclaims sockets when the process exits.
        let _ = self.worker.send(Command::StopHost);
        let _ = self.worker.send(Command::Leave);
    }
}

//! Kikonnect desktop client.

mod app;
mod logbuf;
mod settings;
mod state;
mod worker;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let logs = logbuf::LogBuffer::default();
    let filter =
        EnvFilter::try_from_env("KIKONNECT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(logs.layer())
        .init();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Kikonnect")
            .with_inner_size([620.0, 640.0])
            .with_min_inner_size([480.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Kikonnect",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, logs)?))),
    )
    .map_err(|e| anyhow::anyhow!("failed to run the UI: {e}"))
}

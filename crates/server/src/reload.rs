//! Certificate hot reload: on `SIGHUP` and whenever the PEM files change, so
//! Let's Encrypt renewals do not require a restart.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::time::{interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::server::CryptoUpdater;
use crate::tls;

/// How often the certificate files are checked for changes.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Cheap change detector: modification time and size of both files.
type Fingerprint = [Option<(SystemTime, u64)>; 2];

fn fingerprint(cert: &Path, key: &Path) -> Fingerprint {
    let stat = |p: &Path| {
        fs::metadata(p)
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (t, m.len())))
    };
    [stat(cert), stat(key)]
}

fn reload(updater: &CryptoUpdater, cert: &Path, key: &Path) {
    let result = tls::load_pem(cert, key)
        .and_then(|(certs, key)| tls::server_crypto(certs, key))
        .map(|crypto| updater.set_crypto(crypto));
    match result {
        Ok(()) => {
            info!(cert = %cert.display(), "TLS certificate reloaded");
        }
        Err(e) => {
            error!("TLS certificate reload failed, keeping the previous one: {e}");
        }
    }
}

/// Reloads the certificate when the files change (checked every `poll`) or on
/// `SIGHUP`, until `shutdown` is cancelled. A failed reload keeps the old
/// certificate and is retried on the next change.
pub async fn watch(
    updater: CryptoUpdater,
    cert: PathBuf,
    key: PathBuf,
    poll: Duration,
    shutdown: CancellationToken,
) {
    let mut seen = fingerprint(&cert, &key);
    let mut ticker = interval(poll);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await; // the first tick completes immediately

    #[cfg(unix)]
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("cannot install SIGHUP handler: {e}");
            None
        }
    };

    loop {
        #[cfg(unix)]
        let signalled = async {
            match hup.as_mut() {
                Some(s) => s.recv().await.is_some(),
                None => std::future::pending().await,
            }
        };
        #[cfg(not(unix))]
        let signalled = std::future::pending::<bool>();

        let forced = tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => false,
            got = signalled => {
                if !got {
                    continue;
                }
                info!("SIGHUP received, reloading TLS certificate");
                true
            }
        };
        let now = fingerprint(&cert, &key);
        if forced || now != seen {
            // Remember the fingerprint even on failure: a half-written renewal is
            // retried once the files change again (or on SIGHUP).
            seen = now;
            reload(&updater, &cert, &key);
        }
    }
}

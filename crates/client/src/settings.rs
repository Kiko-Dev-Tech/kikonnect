//! Persistent client settings (TOML in the OS config directory).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use kikonnect_client_core::config::DEFAULT_SERVER_ADDR;
use kikonnect_client_core::{ServiceDef, ServiceKind};
use serde::{Deserialize, Serialize};

/// TCP or UDP, in a form that serializes nicely to TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tcp,
    Udp,
}

impl From<Kind> for ServiceKind {
    fn from(k: Kind) -> Self {
        match k {
            Kind::Tcp => ServiceKind::Tcp,
            Kind::Udp => ServiceKind::Udp,
        }
    }
}

/// One row of the host's service list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRow {
    pub label: String,
    pub kind: Kind,
    pub port: u16,
}

impl ServiceRow {
    pub fn minecraft() -> Self {
        Self {
            label: "Minecraft".to_owned(),
            kind: Kind::Tcp,
            port: 25565,
        }
    }
}

/// Everything that is remembered between runs. Passwords are never persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub server_addr: String,
    /// Accept any server certificate (development only).
    pub insecure: bool,
    pub host_name: String,
    pub services: Vec<ServiceRow>,
    pub join_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_addr: DEFAULT_SERVER_ADDR.to_owned(),
            insecure: false,
            host_name: String::new(),
            services: vec![ServiceRow::minecraft()],
            join_name: String::new(),
        }
    }
}

impl Settings {
    /// Location of the config file, if the OS has a config directory.
    pub fn default_path() -> Option<PathBuf> {
        ProjectDirs::from("", "", "kikonnect").map(|d| d.config_dir().join("config.toml"))
    }

    /// Loads settings; a missing or unreadable file yields defaults.
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Writes the settings, creating the directory if needed.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = toml::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(path, text)
    }

    /// Converts the service rows to protocol definitions (ids are the row index).
    pub fn service_defs(&self) -> Vec<ServiceDef> {
        self.services
            .iter()
            .enumerate()
            .map(|(i, row)| ServiceDef {
                // The UI allows at most MAX_SERVICES (16) rows; saturate anyway.
                id: u8::try_from(i).unwrap_or(u8::MAX),
                kind: row.kind.into(),
                label: row.label.clone(),
                port: row.port,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("kikonnect-settings-{}", std::process::id()));
        let path = dir.join("nested").join("config.toml");
        let s = Settings {
            server_addr: "relay.test:7000".into(),
            insecure: true,
            host_name: "kilian".into(),
            services: vec![
                ServiceRow::minecraft(),
                ServiceRow {
                    label: "Bedrock".into(),
                    kind: Kind::Udp,
                    port: 19132,
                },
            ],
            join_name: "friend".into(),
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        let defs = s.service_defs();
        assert_eq!(defs[1].id, 1);
        assert_eq!(defs[1].kind, ServiceKind::Udp);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_partial_file_gives_defaults() {
        assert_eq!(
            Settings::load(Path::new("/nonexistent/x.toml")),
            Settings::default()
        );
        let dir = std::env::temp_dir().join(format!("kikonnect-settings-p-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        fs::write(&path, "host_name = \"abc\"\n").unwrap();
        let s = Settings::load(&path);
        assert_eq!(s.host_name, "abc");
        assert_eq!(s.services, vec![ServiceRow::minecraft()]);
        let _ = fs::remove_dir_all(&dir);
    }
}

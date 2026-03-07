use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub clamav_dir: PathBuf,
    pub database_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub log_dir: PathBuf,
    pub max_file_size_mb: u64,
    pub max_scan_threads: u32,
    pub scan_archives: bool,
    pub scan_mail: bool,
    pub scan_ole2: bool,
    pub scan_pdf: bool,
    pub scan_html: bool,
    pub heuristic_alerts: bool,
    pub recursive_scan: bool,
    pub exclude_patterns: Vec<String>,
    pub auto_update: bool,
    #[serde(default)]
    pub persist_realtime_on_exit: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let base = portable_base_dir();
        Self {
            clamav_dir: base.join("clamav"),
            database_dir: base.join("clamav").join("database"),
            quarantine_dir: base.join("quarantine"),
            log_dir: base.join("logs"),
            max_file_size_mb: 100,
            max_scan_threads: 2,
            scan_archives: true,
            scan_mail: true,
            scan_ole2: true,
            scan_pdf: true,
            scan_html: true,
            heuristic_alerts: true,
            recursive_scan: true,
            exclude_patterns: vec![],
            auto_update: true,
            persist_realtime_on_exit: false,
        }
    }
}

fn portable_base_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        portable_base_dir().join("clamav-gui-config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            Self::default()
        }
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, data);
        }
    }

    pub fn ensure_dirs(&self) {
        let _ = std::fs::create_dir_all(&self.clamav_dir);
        let _ = std::fs::create_dir_all(&self.database_dir);
        let _ = std::fs::create_dir_all(&self.quarantine_dir);
        let _ = std::fs::create_dir_all(&self.log_dir);
    }

    pub fn clamscan_path(&self) -> PathBuf {
        self.clamav_dir.join("clamscan.exe")
    }

    pub fn freshclam_path(&self) -> PathBuf {
        self.clamav_dir.join("freshclam.exe")
    }

    pub fn freshclam_conf_path(&self) -> PathBuf {
        self.clamav_dir.join("freshclam.conf")
    }
}

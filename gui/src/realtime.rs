use crate::config::AppConfig;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub enum RealtimeMessage {
    ThreatFound {
        file_path: String,
        threat_name: String,
    },
    FileScanned(String),
    Error(String),
    Stopped,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RealtimeState {
    Stopped,
    Running,
}

#[derive(Clone, Debug)]
pub struct RealtimeThreat {
    pub file_path: String,
    pub threat_name: String,
    pub timestamp: String,
}

pub struct RealtimeProtection {
    pub state: RealtimeState,
    pub watch_dirs: Vec<PathBuf>,
    pub threats: Vec<RealtimeThreat>,
    pub scanned_count: u64,
    pub log_lines: Vec<String>,
    cancel_flag: Arc<Mutex<bool>>,
    receiver: Option<mpsc::Receiver<RealtimeMessage>>,
}

impl Default for RealtimeProtection {
    fn default() -> Self {
        Self {
            state: RealtimeState::Stopped,
            watch_dirs: vec![],
            threats: Vec::new(),
            scanned_count: 0,
            log_lines: Vec::new(),
            cancel_flag: Arc::new(Mutex::new(false)),
            receiver: None,
        }
    }
}

impl RealtimeProtection {
    pub fn start(&mut self, config: &AppConfig) {
        if self.state == RealtimeState::Running {
            return;
        }

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();
        self.state = RealtimeState::Running;

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let watch_dirs = if self.watch_dirs.is_empty() {
            default_watch_dirs()
        } else {
            self.watch_dirs.clone()
        };

        let clamscan = config.clamscan_path();
        let db_dir = config.database_dir.clone();

        std::thread::spawn(move || {
            realtime_watch_loop(clamscan, db_dir, watch_dirs, cancel, tx);
        });
    }

    pub fn stop(&mut self) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        self.state = RealtimeState::Stopped;
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    RealtimeMessage::ThreatFound {
                        file_path,
                        threat_name,
                    } => {
                        let ts =
                            chrono::Local::now().format("%H:%M:%S").to_string();
                        self.log_lines.push(format!(
                            "[{}] ⚠ THREAT: {} -> {}",
                            ts, file_path, threat_name
                        ));
                        self.threats.push(RealtimeThreat {
                            file_path,
                            threat_name,
                            timestamp: ts,
                        });
                        // Keep last 500
                        if self.threats.len() > 500 {
                            self.threats.drain(0..100);
                        }
                    }
                    RealtimeMessage::FileScanned(path) => {
                        self.scanned_count += 1;
                        let ts =
                            chrono::Local::now().format("%H:%M:%S").to_string();
                        self.log_lines
                            .push(format!("[{}] OK: {}", ts, path));
                        if self.log_lines.len() > 2000 {
                            self.log_lines.drain(0..500);
                        }
                    }
                    RealtimeMessage::Error(e) => {
                        self.log_lines.push(format!("ERROR: {}", e));
                    }
                    RealtimeMessage::Stopped => {
                        self.state = RealtimeState::Stopped;
                    }
                }
            }
        }
    }
}

fn default_watch_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let downloads = home.join("Downloads");
        if downloads.exists() {
            dirs.push(downloads);
        }
        let desktop = home.join("Desktop");
        if desktop.exists() {
            dirs.push(desktop);
        }
        let documents = home.join("Documents");
        if documents.exists() {
            dirs.push(documents);
        }
    }
    dirs
}

/// Polling-based real-time protection: periodically scans new/modified files
fn realtime_watch_loop(
    clamscan: PathBuf,
    db_dir: PathBuf,
    watch_dirs: Vec<PathBuf>,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<RealtimeMessage>,
) {
    if !clamscan.exists() {
        let _ = tx.send(RealtimeMessage::Error(format!(
            "clamscan not found: {}",
            clamscan.display()
        )));
        let _ = tx.send(RealtimeMessage::Stopped);
        return;
    }

    let mut known_files: HashSet<PathBuf> = HashSet::new();
    let scan_interval = Duration::from_secs(5);

    loop {
        if let Ok(flag) = cancel.lock() {
            if *flag {
                let _ = tx.send(RealtimeMessage::Stopped);
                return;
            }
        }

        let cycle_start = Instant::now();
        let mut new_files: Vec<PathBuf> = Vec::new();

        for dir in &watch_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() {
                        if !known_files.contains(&path) {
                            // Check if modified recently (last 30s) or never seen
                            let is_recent = entry
                                .metadata()
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .and_then(|t| t.elapsed().ok())
                                .map(|elapsed| elapsed < Duration::from_secs(30))
                                .unwrap_or(false); // If we can't get time, assume not recent

                            if is_recent || !known_files.contains(&path) {
                                new_files.push(path.clone());
                            }
                            known_files.insert(path);
                        }
                    }
                }
            }
        }

        // Scan new files in batches
        if !new_files.is_empty() {
            for chunk in new_files.chunks(20) {
                if let Ok(flag) = cancel.lock() {
                    if *flag {
                        let _ = tx.send(RealtimeMessage::Stopped);
                        return;
                    }
                }

                let mut cmd = Command::new(&clamscan);
                cmd.arg("--stdout").arg("--no-summary");

                if db_dir.exists() {
                    cmd.arg(format!("--database={}", db_dir.display()));
                }

                for file in chunk {
                    cmd.arg(file);
                }

                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x08000000);
                }

                match cmd.spawn() {
                    Ok(child) => {
                        if let Some(stdout) = child.stdout {
                            let reader = BufReader::new(stdout);
                            for line in reader.lines().filter_map(|l| l.ok()) {
                                if line.contains("FOUND") {
                                    let parts: Vec<&str> =
                                        line.splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        let file_path =
                                            parts[0].trim().to_string();
                                        let threat_name = parts[1]
                                            .trim()
                                            .trim_end_matches("FOUND")
                                            .trim()
                                            .to_string();
                                        let _ = tx.send(
                                            RealtimeMessage::ThreatFound {
                                                file_path,
                                                threat_name,
                                            },
                                        );
                                    }
                                } else if line.contains(": OK") {
                                    let path = line
                                        .split(':')
                                        .next()
                                        .unwrap_or("")
                                        .trim()
                                        .to_string();
                                    let _ = tx.send(
                                        RealtimeMessage::FileScanned(path),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(RealtimeMessage::Error(format!(
                            "Scan error: {}",
                            e
                        )));
                    }
                }
            }
        }

        // Sleep until next cycle
        let elapsed = cycle_start.elapsed();
        if elapsed < scan_interval {
            std::thread::sleep(scan_interval - elapsed);
        }
    }
}

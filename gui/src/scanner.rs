use crate::config::AppConfig;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub enum ScanMessage {
    Progress(String),
    ThreatFound(ThreatInfo),
    Stats(ScanStats),
    Finished(ScanStats),
    Error(String),
}

#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    pub scanned_files: u64,
    pub infected_files: u64,
    pub scanned_data_mb: f64,
    pub elapsed_secs: f64,
}

#[derive(Clone, Debug)]
pub struct ThreatInfo {
    pub file_path: String,
    pub threat_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScanState {
    Idle,
    Scanning,
    Paused,
    Finished,
}

pub struct ScanEngine {
    pub state: ScanState,
    pub receiver: Option<mpsc::Receiver<ScanMessage>>,
    pub threats: Vec<ThreatInfo>,
    pub stats: ScanStats,
    pub log_lines: Vec<String>,
    pub cancel_flag: Arc<Mutex<bool>>,
    pub current_file: String,
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self {
            state: ScanState::Idle,
            receiver: None,
            threats: Vec::new(),
            stats: ScanStats::default(),
            log_lines: Vec::new(),
            cancel_flag: Arc::new(Mutex::new(false)),
            current_file: String::new(),
        }
    }
}

impl ScanEngine {
    pub fn start_scan(&mut self, target: PathBuf, config: &AppConfig) {
        self.state = ScanState::Scanning;
        self.threats.clear();
        self.stats = ScanStats::default();
        self.log_lines.clear();
        self.current_file.clear();

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let clamscan = config.clamscan_path();
        let db_dir = config.database_dir.clone();
        let recursive = config.recursive_scan;
        let max_size = config.max_file_size_mb;
        let scan_archives = config.scan_archives;
        let excludes = config.exclude_patterns.clone();

        std::thread::spawn(move || {
            run_clamscan(
                clamscan,
                target,
                db_dir,
                recursive,
                max_size,
                scan_archives,
                excludes,
                cancel,
                tx,
            );
        });
    }

    pub fn cancel_scan(&mut self) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        self.state = ScanState::Idle;
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMessage::Progress(file) => {
                        self.current_file = file.clone();
                        self.log_lines.push(file);
                        if self.log_lines.len() > 5000 {
                            self.log_lines.drain(0..1000);
                        }
                    }
                    ScanMessage::ThreatFound(info) => {
                        self.log_lines.push(format!(
                            "⚠ THREAT: {} -> {}",
                            info.file_path, info.threat_name
                        ));
                        self.threats.push(info);
                    }
                    ScanMessage::Stats(s) => {
                        self.stats = s;
                    }
                    ScanMessage::Finished(s) => {
                        self.stats = s;
                        self.state = ScanState::Finished;
                    }
                    ScanMessage::Error(e) => {
                        self.log_lines.push(format!("ERROR: {}", e));
                        self.state = ScanState::Finished;
                    }
                }
            }
        }
    }

    pub fn quarantine_threat(
        &self,
        threat: &ThreatInfo,
        quarantine_dir: &std::path::Path,
    ) -> Result<(), String> {
        let src = PathBuf::from(&threat.file_path);
        if !src.exists() {
            return Err("File not found".into());
        }
        let _ = std::fs::create_dir_all(quarantine_dir);
        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let dest = quarantine_dir.join(format!("{}.{}.quarantine", name, ts));
        std::fs::rename(&src, &dest).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn run_clamscan(
    clamscan_path: PathBuf,
    target: PathBuf,
    db_dir: PathBuf,
    recursive: bool,
    max_size_mb: u64,
    scan_archives: bool,
    excludes: Vec<String>,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<ScanMessage>,
) {
    if !clamscan_path.exists() {
        let _ = tx.send(ScanMessage::Error(format!(
            "clamscan.exe not found at: {}",
            clamscan_path.display()
        )));
        return;
    }

    let mut cmd = Command::new(&clamscan_path);
    cmd.arg("--stdout");

    if db_dir.exists() {
        cmd.arg(format!("--database={}", db_dir.display()));
    }

    if recursive {
        cmd.arg("--recursive");
    }

    cmd.arg(format!("--max-filesize={}M", max_size_mb));
    cmd.arg(format!("--max-scansize={}M", max_size_mb * 4));

    if !scan_archives {
        cmd.arg("--no-archive");
    }

    for pat in &excludes {
        if !pat.is_empty() {
            cmd.arg(format!("--exclude={}", pat));
        }
    }

    cmd.arg(target.to_string_lossy().as_ref());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Hide console window on Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let start = std::time::Instant::now();

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(ScanMessage::Error(format!(
                "Failed to start clamscan: {}",
                e
            )));
            return;
        }
    };

    let stdout = match child.stdout {
        Some(s) => s,
        None => {
            let _ = tx.send(ScanMessage::Error("No stdout from clamscan".into()));
            return;
        }
    };

    let reader = BufReader::new(stdout);
    let mut scanned: u64 = 0;
    let mut infected: u64 = 0;

    for line in reader.lines() {
        if let Ok(cancelled) = cancel.lock() {
            if *cancelled {
                let _ = tx.send(ScanMessage::Finished(ScanStats {
                    scanned_files: scanned,
                    infected_files: infected,
                    scanned_data_mb: 0.0,
                    elapsed_secs: start.elapsed().as_secs_f64(),
                }));
                return;
            }
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.contains("FOUND") {
            infected += 1;
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let file_path = parts[0].trim().to_string();
                let threat_name = parts[1].trim().trim_end_matches("FOUND").trim().to_string();
                let _ = tx.send(ScanMessage::ThreatFound(ThreatInfo {
                    file_path,
                    threat_name,
                }));
            }
        } else if line.contains(": OK") || line.contains("Scanning") {
            scanned += 1;
            let _ = tx.send(ScanMessage::Progress(line.clone()));
        } else if line.starts_with("-------") {
            // Summary section begins
        } else if line.contains("Scanned files:") {
            if let Some(n) = extract_number(&line) {
                scanned = n;
            }
        } else if line.contains("Infected files:") {
            if let Some(n) = extract_number(&line) {
                infected = n;
            }
        }

        let _ = tx.send(ScanMessage::Stats(ScanStats {
            scanned_files: scanned,
            infected_files: infected,
            scanned_data_mb: 0.0,
            elapsed_secs: start.elapsed().as_secs_f64(),
        }));
    }

    let _ = tx.send(ScanMessage::Finished(ScanStats {
        scanned_files: scanned,
        infected_files: infected,
        scanned_data_mb: 0.0,
        elapsed_secs: start.elapsed().as_secs_f64(),
    }));
}

fn extract_number(line: &str) -> Option<u64> {
    line.split(':')
        .nth(1)?
        .trim()
        .parse::<u64>()
        .ok()
}

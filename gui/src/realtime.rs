use crate::config::AppConfig;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::Watcher;

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

/// 基于 notify (Windows: ReadDirectoryChangesW) 的实时文件系统监控
fn realtime_watch_loop(
    clamscan: PathBuf,
    db_dir: PathBuf,
    watch_dirs: Vec<PathBuf>,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<RealtimeMessage>,
) {
    if !clamscan.exists() {
        let _ = tx.send(RealtimeMessage::Error(format!(
            "扫描器未找到: {}",
            clamscan.display()
        )));
        let _ = tx.send(RealtimeMessage::Stopped);
        return;
    }

    // 创建文件系统事件通道
    let (event_tx, event_rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = match notify::RecommendedWatcher::new(
        move |res| {
            let _ = event_tx.send(res);
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "无法创建文件系统监控器: {}",
                e
            )));
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }
    };

    // 注册监控目录
    for dir in &watch_dirs {
        match watcher.watch(dir, notify::RecursiveMode::Recursive) {
            Ok(_) => {
                let _ = tx.send(RealtimeMessage::FileScanned(format!(
                    "开始监控: {}",
                    dir.display()
                )));
            }
            Err(e) => {
                let _ = tx.send(RealtimeMessage::Error(format!(
                    "无法监控目录 {}: {}",
                    dir.display(),
                    e
                )));
            }
        }
    }

    let mut pending_files: HashSet<PathBuf> = HashSet::new();
    let mut last_scan = Instant::now();
    let debounce = Duration::from_secs(2);

    loop {
        // 检查取消标志
        if cancel.lock().map(|f| *f).unwrap_or(false) {
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }

        // 接收文件系统事件（超时500ms）
        match event_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(event)) => {
                match event.kind {
                    notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.is_file()
                                && !path.to_string_lossy().ends_with(".quarantine")
                                && !path.to_string_lossy().ends_with(".meta")
                            {
                                pending_files.insert(path);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Err(e)) => {
                let _ = tx.send(RealtimeMessage::Error(format!(
                    "监控错误: {}",
                    e
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // 正常超时，继续循环
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = tx.send(RealtimeMessage::Error(
                    "文件监控通道断开".to_string(),
                ));
                let _ = tx.send(RealtimeMessage::Stopped);
                return;
            }
        }

        // 去抖动: 积累文件后批量扫描
        if !pending_files.is_empty() && last_scan.elapsed() >= debounce {
            let files: Vec<PathBuf> = pending_files.drain().collect();

            for chunk in files.chunks(20) {
                if cancel.lock().map(|f| *f).unwrap_or(false) {
                    let _ = tx.send(RealtimeMessage::Stopped);
                    return;
                }
                scan_batch(&clamscan, &db_dir, chunk, &tx);
            }

            last_scan = Instant::now();
        }
    }
}

/// 批量扫描文件
fn scan_batch(
    clamscan: &PathBuf,
    db_dir: &PathBuf,
    files: &[PathBuf],
    tx: &mpsc::Sender<RealtimeMessage>,
) {
    let mut cmd = Command::new(clamscan);
    cmd.arg("--stdout").arg("--no-summary");

    if db_dir.exists() {
        cmd.arg(format!("--database={}", db_dir.display()));
    }

    for file in files {
        cmd.arg(file);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    match cmd.spawn() {
        Ok(mut child) => {
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines().filter_map(|l| l.ok()) {
                    if line.contains("FOUND") {
                        let parts: Vec<&str> = line.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            let file_path = parts[0].trim().to_string();
                            let threat_name = parts[1]
                                .trim()
                                .trim_end_matches("FOUND")
                                .trim()
                                .to_string();
                            let _ = tx.send(RealtimeMessage::ThreatFound {
                                file_path,
                                threat_name,
                            });
                        }
                    } else if line.contains(": OK") {
                        let path =
                            line.split(':').next().unwrap_or("").trim().to_string();
                        let _ = tx.send(RealtimeMessage::FileScanned(path));
                    }
                }
            }
            let _ = child.wait();
        }
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "扫描出错: {}",
                e
            )));
        }
    }
}

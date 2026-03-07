use crate::config::AppConfig;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Clamd 守护进程管理器
pub struct ClamdDaemon {
    process: Option<Child>,
    pub is_running: bool,
}

impl ClamdDaemon {
    pub fn new() -> Self {
        Self {
            process: None,
            is_running: false,
        }
    }

    /// 启动 clamd 守护进程
    pub fn start(&mut self, config: &AppConfig) -> Result<(), String> {
        if self.is_running {
            return Ok(());
        }

        let clamd_path = config.clamd_path();
        if !clamd_path.exists() {
            return Err(format!("clamd.exe 未找到: {}", clamd_path.display()));
        }

        // 生成 clamd.conf 配置文件
        if let Err(e) = config.generate_clamd_conf() {
            return Err(format!("生成 clamd.conf 失败: {}", e));
        }

        let conf_path = config.clamd_conf_path();

        let mut cmd = Command::new(&clamd_path);
        cmd.arg("-c").arg(&conf_path);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        // 隐藏窗口
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        match cmd.spawn() {
            Ok(child) => {
                self.process = Some(child);
                self.is_running = true;
                
                // 等待 clamd 初始化（加载病毒库需要几秒）
                std::thread::sleep(std::time::Duration::from_secs(3));
                
                Ok(())
            }
            Err(e) => Err(format!("启动 clamd 失败: {}", e)),
        }
    }

    /// 停止 clamd 守护进程
    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.is_running = false;
    }

    /// 检查 clamd 是否正在运行
    pub fn check_status(&mut self) -> bool {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // 进程已退出
                    self.process = None;
                    self.is_running = false;
                    false
                }
                Ok(None) => {
                    // 进程仍在运行
                    true
                }
                Err(_) => {
                    self.is_running = false;
                    false
                }
            }
        } else {
            self.is_running = false;
            false
        }
    }
}

impl Drop for ClamdDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

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
    pub scan_started_at: Option<std::time::Instant>,
    pub clamd_daemon: ClamdDaemon,
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
            scan_started_at: None,
            clamd_daemon: ClamdDaemon::new(),
        }
    }
}

impl ScanEngine {
    pub fn start_scan(&mut self, target: PathBuf, config: &AppConfig) {
        self.start_scan_targets(vec![target], config);
    }

    pub fn start_scan_targets(&mut self, targets: Vec<PathBuf>, config: &AppConfig) {
        if self.state == ScanState::Scanning {
            self.log_lines.push("INFO: 扫描正在进行中，请先停止当前扫描".to_string());
            return;
        }

        if targets.is_empty() {
            self.state = ScanState::Finished;
            self.log_lines.push("ERROR: No valid scan targets found".to_string());
            return;
        }

        // 确保 clamd 守护进程正在运行
        if !self.clamd_daemon.is_running {
            self.log_lines.push("INFO: 启动 ClamAV 守护进程...".to_string());
            match self.clamd_daemon.start(config) {
                Ok(_) => {
                    self.log_lines.push("INFO: ClamAV 守护进程已启动（使用高性能模式）".to_string());
                }
                Err(e) => {
                    self.log_lines.push(format!("ERROR: 启动 clamd 失败: {}", e));
                    self.log_lines.push("INFO: 回退到传统扫描模式...".to_string());
                }
            }
        }

        self.state = ScanState::Scanning;
        self.threats.clear();
        self.stats = ScanStats::default();
        self.log_lines.clear();
        self.current_file.clear();
        self.scan_started_at = Some(std::time::Instant::now());

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        // 优先使用 clamdscan（高性能），如果不可用则使用 clamscan
        let use_daemon = self.clamd_daemon.is_running && config.clamdscan_path().exists();
        let scanner_path = if use_daemon {
            config.clamdscan_path()
        } else {
            config.clamscan_path()
        };

        let db_dir = config.database_dir.clone();
        let recursive = config.recursive_scan;
        let max_size = config.max_file_size_mb;
        let scan_archives = config.scan_archives;
        let excludes = config.exclude_patterns.clone();

        std::thread::spawn(move || {
            run_scanner(
                scanner_path,
                use_daemon,
                targets,
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
        self.scan_started_at = None;
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMessage::Progress(file) => {
                        self.current_file = file;
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
                        self.scan_started_at = None;
                    }
                    ScanMessage::Error(e) => {
                        self.log_lines.push(format!("ERROR: {}", e));
                        self.state = ScanState::Finished;
                        self.scan_started_at = None;
                    }
                }
            }
        }

        if self.state == ScanState::Scanning {
            if let Some(started) = self.scan_started_at {
                self.stats.elapsed_secs = started.elapsed().as_secs_f64();
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

fn run_scanner(
    scanner_path: PathBuf,
    use_daemon: bool,
    targets: Vec<PathBuf>,
    db_dir: PathBuf,
    recursive: bool,
    max_size_mb: u64,
    scan_archives: bool,
    excludes: Vec<String>,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<ScanMessage>,
) {
    if !scanner_path.exists() {
        let _ = tx.send(ScanMessage::Error(format!(
            "扫描器未找到: {}",
            scanner_path.display()
        )));
        return;
    }

    let mut cmd = Command::new(&scanner_path);
    
    if use_daemon {
        // clamdscan 参数（通过 clamd 守护进程扫描）
        cmd.arg("--verbose");
        cmd.arg("--stdout");
        
        if recursive {
            cmd.arg("--multiscan");  // 多线程扫描
        }

        // clamdscan 不需要指定数据库路径，由 clamd 管理
    } else {
        // clamscan 参数（独立扫描）
        cmd.arg("--verbose");  // 启用详细输出以获取完整统计信息
        cmd.arg("--stdout");

        if db_dir.exists() {
            cmd.arg(format!("--database={}", db_dir.display()));
        }

        if recursive {
            cmd.arg("--recursive");
        }

        // 文件大小限制
        cmd.arg(format!("--max-filesize={}M", max_size_mb));
        cmd.arg(format!("--max-scansize={}M", max_size_mb * 4));

        // 性能优化选项
        cmd.arg("--max-dir-recursion=15");
        cmd.arg("--pcre-match-limit=10000");
        cmd.arg("--pcre-recmatch-limit=5000");

        if !scan_archives {
            cmd.arg("--no-archive");
        }
    }

    // 排除模式（两种扫描器都支持）
    for pat in &excludes {
        if !pat.is_empty() {
            cmd.arg(format!("--exclude={}", pat));
        }
    }

    // 添加扫描目标
    for target in &targets {
        cmd.arg(target.to_string_lossy().as_ref());
    }
    
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Hide console window on Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let start = std::time::Instant::now();

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(ScanMessage::Error(format!(
                "Failed to start clamscan: {}",
                e
            )));
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = tx.send(ScanMessage::Error("No stdout from clamscan".into()));
            return;
        }
    };

    let stderr = child.stderr.take();
    let stderr_handle = std::thread::spawn(move || {
        if let Some(stderr) = stderr {
            let reader = BufReader::new(stderr);
            let mut lines = Vec::new();
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    lines.push(line);
                }
            }
            lines.join("\n")
        } else {
            String::new()
        }
    });

    let reader = BufReader::new(stdout);
    let mut scanned: u64 = 0;
    let mut infected: u64 = 0;
    let mut scanned_data_mb: f64 = 0.0;
    let mut last_stats_update = std::time::Instant::now();

    for line in reader.lines() {
        if let Ok(cancelled) = cancel.lock() {
            if *cancelled {
                let _ = tx.send(ScanMessage::Finished(ScanStats {
                    scanned_files: scanned,
                    infected_files: infected,
                    scanned_data_mb,
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
        } else if line.contains(": OK") {
            // 仅在 verbose 模式下更新扫描文件统计（减少消息频率）
            scanned += 1;
            
            // 定期发送进度更新（每秒一次）
            if last_stats_update.elapsed().as_secs_f64() > 1.0 {
                let _ = tx.send(ScanMessage::Stats(ScanStats {
                    scanned_files: scanned,
                    infected_files: infected,
                    scanned_data_mb,
                    elapsed_secs: start.elapsed().as_secs_f64(),
                }));
                last_stats_update = std::time::Instant::now();
            }
        } else if line.starts_with("Scanning") {
            // 更新当前正在扫描的文件
            let file = line.replace("Scanning", "").trim().to_string();
            if !file.is_empty() {
                let _ = tx.send(ScanMessage::Progress(file));
            }
        } else if line.starts_with("-------") {
            // Summary section begins，准备等待统计行
        } else if line.contains("Scanned files:") {
            if let Some(n) = extract_number(&line) {
                scanned = n;
            }
        } else if line.contains("Infected files:") {
            if let Some(n) = extract_number(&line) {
                infected = n;
            }
        } else if line.contains("Data scanned:") {
            if let Some(mb) = extract_data_scanned_mb(&line) {
                scanned_data_mb = mb;
            }
        }
    }

    let status = child.wait();
    let stderr_text = stderr_handle.join().unwrap_or_default();

    // 发送最终统计信息
    let _ = tx.send(ScanMessage::Stats(ScanStats {
        scanned_files: scanned,
        infected_files: infected,
        scanned_data_mb,
        elapsed_secs: start.elapsed().as_secs_f64(),
    }));

    if let Ok(exit_status) = status {
        if !exit_status.success() {
            let code = exit_status.code().map_or("unknown".to_string(), |c| c.to_string());
            let details = if stderr_text.is_empty() {
                "扫描器退出时返回非零状态".to_string()
            } else {
                stderr_text
            };

            let _ = tx.send(ScanMessage::Error(format!(
                "扫描失败 (exit code {}): {}",
                code, details
            )));
            return;
        }
    } else if let Err(e) = status {
        let _ = tx.send(ScanMessage::Error(format!("等待扫描器失败: {}", e)));
        return;
    }

    let _ = tx.send(ScanMessage::Finished(ScanStats {
        scanned_files: scanned,
        infected_files: infected,
        scanned_data_mb,
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

fn extract_data_scanned_mb(line: &str) -> Option<f64> {
    let rhs = line.split(':').nth(1)?.trim();
    let mut parts = rhs.split_whitespace();
    let value = parts.next()?.parse::<f64>().ok()?;
    let unit = parts.next().unwrap_or("MB").to_ascii_uppercase();

    match unit.as_str() {
        "TB" => Some(value * 1024.0 * 1024.0),
        "GB" => Some(value * 1024.0),
        "MB" => Some(value),
        "KB" => Some(value / 1024.0),
        "B" => Some(value / (1024.0 * 1024.0)),
        _ => Some(value),
    }
}

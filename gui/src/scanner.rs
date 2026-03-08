use crate::config::AppConfig;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// 隔离文件的元数据，保存在 .meta JSON 文件中
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuarantineMeta {
    pub original_path: String,
    pub threat_name: String,
    pub quarantine_date: String,
}

/// 隔离区中的条目，包含文件路径和元数据
#[derive(Clone, Debug)]
pub struct QuarantineEntry {
    pub quarantine_path: PathBuf,
    pub file_size: u64,
    pub meta: Option<QuarantineMeta>,
}

#[derive(Clone, Debug)]
pub enum ScanMessage {
    Progress(String),
    ThreatFound(ThreatInfo),
    Stats(ScanStats),
    Finished(ScanStats),
    Error(String),
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub scanned_files: u64,
    pub infected_files: u64,
    pub scanned_data_mb: f64,
    pub elapsed_secs: f64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ThreatInfo {
    pub file_path: String,
    pub threat_name: String,
}

/// 持久化的扫描历史记录
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanHistory {
    pub threats: Vec<ThreatInfo>,
    pub stats: ScanStats,
    pub log_lines: Vec<String>,
    pub scan_target: String,
    #[serde(default)]
    pub scan_target_paths: Vec<String>,
    pub last_scan_time: String,
    pub was_completed: bool,
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
    pub was_cancelled: bool,
    /// 实际的扫描目标路径列表（用于继续扫描）
    pub scan_target_paths: Vec<PathBuf>,
    stats_base: ScanStats,
    scan_child_id: Arc<Mutex<Option<u32>>>,
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
            was_cancelled: false,
            scan_target_paths: Vec::new(),
            stats_base: ScanStats::default(),
            scan_child_id: Arc::new(Mutex::new(None)),
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

        self.state = ScanState::Scanning;
        self.was_cancelled = false;
        self.threats.clear();
        self.stats = ScanStats::default();
        self.stats_base = ScanStats::default();
        self.log_lines.clear();
        self.current_file.clear();
        self.scan_started_at = Some(std::time::Instant::now());
        self.scan_target_paths = targets.clone();

        self.spawn_scan_thread(targets, config);
    }

    /// 使用已存储的目标路径继续扫描
    pub fn continue_scan_previous(&mut self, config: &AppConfig) {
        let targets = self.scan_target_paths.clone();
        self.continue_scan_targets(targets, config);
}

    pub fn continue_scan_targets(&mut self, targets: Vec<PathBuf>, config: &AppConfig) {
        if self.state == ScanState::Scanning {
            self.log_lines.push("INFO: 扫描正在进行中，请先停止当前扫描".to_string());
            return;
        }

        if targets.is_empty() {
            self.state = ScanState::Finished;
            self.log_lines.push("ERROR: No valid scan targets found".to_string());
            return;
        }

        self.state = ScanState::Scanning;
        self.was_cancelled = false;
        // 保留已有的 threats 和 log_lines
        // 将当前统计作为基准，后续累加
        self.stats_base = self.stats.clone();
        self.current_file.clear();
        self.scan_started_at = Some(std::time::Instant::now());
        self.log_lines.push("INFO: 继续扫描...".to_string());

        self.spawn_scan_thread(targets, config);
    }

    fn spawn_scan_thread(&mut self, targets: Vec<PathBuf>, config: &AppConfig) {
        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let scanner_path = config.clamscan_path();
        let db_dir = config.database_dir.clone();
        let recursive = config.recursive_scan;
        let max_size = config.max_file_size_mb;
        let scan_archives = config.scan_archives;
        let excludes = config.exclude_patterns.clone();
        let scan_child_id = self.scan_child_id.clone();

        std::thread::spawn(move || {
            run_scanner(
                scanner_path,
                targets,
                db_dir,
                recursive,
                max_size,
                scan_archives,
                excludes,
                cancel,
                scan_child_id,
                tx,
            );
        });
    }

    pub fn cancel_scan(&mut self) {
        let was_scanning = self.state == ScanState::Scanning;
        // Set cancel flag
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        // Kill the scan process directly via PID (unblocks reader.lines())
        if let Ok(mut pid) = self.scan_child_id.lock() {
            if let Some(id) = pid.take() {
                kill_process_tree(id);
            }
        }
        // 断开 receiver，丢弃扫描线程后续发送的消息
        self.receiver = None;
        // 更新最终用时
        if let Some(started) = self.scan_started_at {
            self.stats.elapsed_secs = self.stats_base.elapsed_secs + started.elapsed().as_secs_f64();
        }
        if was_scanning {
            self.was_cancelled = true;
        }
        self.state = ScanState::Finished;
        self.scan_started_at = None;
        self.current_file.clear();
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMessage::Progress(file) => {
                        self.current_file = file;
                    }
                    ScanMessage::ThreatFound(info) => {
                        // 去重：跳过已知的威胁（继续扫描时避免重复）
                        if !self.threats.iter().any(|t| t.file_path == info.file_path) {
                            self.log_lines.push(format!(
                                "⚠ THREAT: {} -> {}",
                                info.file_path, info.threat_name
                            ));
                            self.threats.push(info);
                        }
                    }
                    ScanMessage::Stats(s) => {
                        self.stats = ScanStats {
                            scanned_files: self.stats_base.scanned_files + s.scanned_files,
                            infected_files: self.stats_base.infected_files + s.infected_files,
                            scanned_data_mb: self.stats_base.scanned_data_mb + s.scanned_data_mb,
                            elapsed_secs: self.stats_base.elapsed_secs + s.elapsed_secs,
                        };
                    }
                    ScanMessage::Finished(s) => {
                        self.stats = ScanStats {
                            scanned_files: self.stats_base.scanned_files + s.scanned_files,
                            infected_files: self.stats_base.infected_files + s.infected_files,
                            scanned_data_mb: self.stats_base.scanned_data_mb + s.scanned_data_mb,
                            elapsed_secs: self.stats_base.elapsed_secs + s.elapsed_secs,
                        };
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
                self.stats.elapsed_secs = self.stats_base.elapsed_secs + started.elapsed().as_secs_f64();
            }
        }
    }

    /// 保存扫描历史到文件
    pub fn save_history(&self, path: &std::path::Path, scan_target: &str) {
        let history = ScanHistory {
            threats: self.threats.clone(),
            stats: self.stats.clone(),
            log_lines: self.log_lines.clone(),
            scan_target: scan_target.to_string(),
            scan_target_paths: self.scan_target_paths.iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            last_scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            was_completed: self.state == ScanState::Finished && !self.was_cancelled,
        };
        if let Ok(json) = serde_json::to_string_pretty(&history) {
            let _ = std::fs::write(path, json);
        }
    }

    /// 从文件加载扫描历史，返回扫描目标路径
    pub fn load_history(&mut self, path: &std::path::Path) -> Option<String> {
        let data = std::fs::read_to_string(path).ok()?;
        let history: ScanHistory = serde_json::from_str(&data).ok()?;
        if history.threats.is_empty() && history.stats.scanned_files == 0 && history.log_lines.is_empty() {
            return None;
        }
        self.threats = history.threats;
        self.stats = history.stats.clone();
        self.stats_base = history.stats;
        self.log_lines = history.log_lines;
        self.was_cancelled = !history.was_completed;
        self.scan_target_paths = history.scan_target_paths.iter()
            .map(|s| PathBuf::from(s))
            .collect();
        self.state = ScanState::Finished;
        Some(history.scan_target)
    }

    pub fn quarantine_threat(
        &self,
        threat: &ThreatInfo,
        quarantine_dir: &std::path::Path,
    ) -> Result<PathBuf, String> {
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
        move_file_cross_drive(&src, &dest)?;

        // 保存元数据
        let meta = QuarantineMeta {
            original_path: threat.file_path.clone(),
            threat_name: threat.threat_name.clone(),
            quarantine_date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };
        let meta_path = PathBuf::from(format!("{}.meta", dest.display()));
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = std::fs::write(&meta_path, json);
        }

        Ok(dest)
    }
}

/// 移动文件，支持跨磁盘分区（rename 失败时回退到 copy + delete）
fn move_file_cross_drive(src: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // rename 跨驱动器时会失败，回退到 copy + delete
            std::fs::copy(src, dest)
                .map_err(|e| format!("复制文件失败: {}", e))?;
            std::fs::remove_file(src)
                .map_err(|e| format!("删除原文件失败: {}", e))?;
            Ok(())
        }
    }
}

/// 列出隔离区中的所有条目
pub fn list_quarantine_entries(quarantine_dir: &std::path::Path) -> Vec<QuarantineEntry> {
    let entries: Vec<_> = std::fs::read_dir(quarantine_dir)
        .ok()
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "quarantine")
                        .unwrap_or(false)
                })
                .map(|e| {
                    let path = e.path();
                    let file_size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    let meta_path = PathBuf::from(format!("{}.meta", path.display()));
                    let meta = std::fs::read_to_string(&meta_path)
                        .ok()
                        .and_then(|s| serde_json::from_str::<QuarantineMeta>(&s).ok());
                    QuarantineEntry {
                        quarantine_path: path,
                        file_size,
                        meta,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    entries
}

/// 恢复隔离文件到原始路径
pub fn restore_quarantined(entry: &QuarantineEntry) -> Result<(), String> {
    let original = entry
        .meta
        .as_ref()
        .map(|m| PathBuf::from(&m.original_path))
        .ok_or_else(|| "无法找到原始路径信息".to_string())?;

    // 如果原始目录不存在则创建
    if let Some(parent) = original.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    move_file_cross_drive(&entry.quarantine_path, &original)
        .map_err(|e| format!("恢复失败: {}", e))?;

    // 删除元数据文件
    let meta_path = PathBuf::from(format!("{}.meta", entry.quarantine_path.display()));
    let _ = std::fs::remove_file(&meta_path);

    Ok(())
}

/// 删除隔离文件及其元数据
pub fn delete_quarantined(entry: &QuarantineEntry) -> Result<(), String> {
    std::fs::remove_file(&entry.quarantine_path)
        .map_err(|e| format!("删除失败: {}", e))?;
    let meta_path = PathBuf::from(format!("{}.meta", entry.quarantine_path.display()));
    let _ = std::fs::remove_file(&meta_path);
    Ok(())
}

impl Drop for ScanEngine {
    fn drop(&mut self) {
        // Kill any running scan process on cleanup
        if let Ok(mut pid) = self.scan_child_id.lock() {
            if let Some(id) = pid.take() {
                kill_process_tree(id);
            }
        }
    }
}

fn kill_process_tree(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// 通过 clamscan 子进程执行扫描
fn run_scanner(
    scanner_path: PathBuf,
    targets: Vec<PathBuf>,
    db_dir: PathBuf,
    recursive: bool,
    max_size_mb: u64,
    scan_archives: bool,
    excludes: Vec<String>,
    cancel: Arc<Mutex<bool>>,
    scan_child_id: Arc<Mutex<Option<u32>>>,
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

    cmd.arg("--verbose");
    cmd.arg("--stdout");

    if db_dir.exists() {
        cmd.arg(format!("--database={}", db_dir.display()));
    }

    // 显式指定证书目录，覆盖编译时硬编码的路径
    let certs_dir = scanner_path.parent().map(|p| p.join("certs"));
    if let Some(ref cd) = certs_dir {
        if cd.exists() {
            cmd.arg(format!("--cvdcertsdir={}", cd.display()));
        }
    }

    if recursive {
        cmd.arg("--recursive");
    }

    cmd.arg(format!("--max-filesize={}M", max_size_mb));
    cmd.arg(format!("--max-scansize={}M", max_size_mb * 4));
    cmd.arg("--max-dir-recursion=15");
    cmd.arg("--pcre-match-limit=10000");
    cmd.arg("--pcre-recmatch-limit=5000");

    if !scan_archives {
        cmd.arg("--no-archive");
    }

    for pat in &excludes {
        if !pat.is_empty() {
            cmd.arg(format!("--exclude={}", pat));
        }
    }

    for target in &targets {
        cmd.arg(target.to_string_lossy().as_ref());
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

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
                "启动扫描器失败: {}",
                e
            )));
            return;
        }
    };

    // Store child PID for external kill (cancel_scan / Drop)
    let child_id = child.id();
    if let Ok(mut pid) = scan_child_id.lock() {
        *pid = Some(child_id);
    }

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = tx.send(ScanMessage::Error("No stdout from scanner".into()));
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
        let is_cancelled = cancel.lock().map(|f| *f).unwrap_or(false);
        if is_cancelled {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // ClamAV 输出格式 (Windows):
        //   威胁: "C:\path\to\file: ThreatName FOUND"
        //   正常: "C:\path\to\file: OK"
        //   扫描: "Scanning C:\path\to\file"
        // 注意: 必须先检查行尾 " FOUND" 再检查 ": OK"，
        //       避免文件名包含 "FOUND" 时误判。
        //       用 rfind(": ") 来定位路径与状态的分隔符，
        //       跳过 Windows 驱动器号 "C:" 中的冒号。

        if line.ends_with(" FOUND") {
            infected += 1;
            scanned += 1;
            // 去掉尾部 " FOUND"
            let without_found = &line[..line.len() - " FOUND".len()];
            // 找最后一个 ": " 作为路径与威胁名的分隔
            if let Some(sep) = without_found.rfind(": ") {
                let file_path = without_found[..sep].trim().to_string();
                let threat_name = without_found[sep + 2..].trim().to_string();
                if !file_path.is_empty() && !threat_name.is_empty() {
                    if let Ok(meta) = std::fs::metadata(&file_path) {
                        scanned_data_mb += meta.len() as f64 / (1024.0 * 1024.0);
                    }
                    let _ = tx.send(ScanMessage::ThreatFound(ThreatInfo {
                        file_path: file_path.clone(),
                        threat_name,
                    }));
                    let _ = tx.send(ScanMessage::Progress(file_path));
                }
            }
        } else if line.ends_with(": OK") {
            scanned += 1;
            let path = line[..line.len() - ": OK".len()].trim();
            if !path.is_empty() {
                if let Ok(meta) = std::fs::metadata(path) {
                    scanned_data_mb += meta.len() as f64 / (1024.0 * 1024.0);
                }
                let _ = tx.send(ScanMessage::Progress(path.to_string()));
            }
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
            let file = line.replace("Scanning", "").trim().to_string();
            if !file.is_empty() {
                let _ = tx.send(ScanMessage::Progress(file));
            }
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

    // Clear PID
    if let Ok(mut pid) = scan_child_id.lock() {
        *pid = None;
    }

    let was_cancelled = cancel.lock().map(|f| *f).unwrap_or(false);
    if was_cancelled {
        let _ = child.wait();
        let _ = stderr_handle.join();
        let _ = tx.send(ScanMessage::Finished(ScanStats {
            scanned_files: scanned,
            infected_files: infected,
            scanned_data_mb,
            elapsed_secs: start.elapsed().as_secs_f64(),
        }));
        return;
    }

    let status = child.wait();
    let stderr_text = stderr_handle.join().unwrap_or_default();

    let _ = tx.send(ScanMessage::Stats(ScanStats {
        scanned_files: scanned,
        infected_files: infected,
        scanned_data_mb,
        elapsed_secs: start.elapsed().as_secs_f64(),
    }));

    if let Ok(exit_status) = status {
        let code = exit_status.code().unwrap_or(-1);
        if code >= 2 {
            let details = if stderr_text.is_empty() {
                format!("扫描器退出代码: {}", code)
            } else {
                stderr_text
            };
            let _ = tx.send(ScanMessage::Error(details));
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

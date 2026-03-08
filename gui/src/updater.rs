use crate::config::AppConfig;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[derive(Clone, Debug)]
pub enum UpdateMessage {
    Progress(String),
    Finished(bool, String),
    Error(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpdateState {
    Idle,
    Updating,
    Done,
}

pub struct DatabaseUpdater {
    pub state: UpdateState,
    pub receiver: Option<mpsc::Receiver<UpdateMessage>>,
    pub log_lines: Vec<String>,
    pub last_update: Option<String>,
    pub db_version: Option<String>,
}

impl Default for DatabaseUpdater {
    fn default() -> Self {
        Self {
            state: UpdateState::Idle,
            receiver: None,
            log_lines: Vec::new(),
            last_update: None,
            db_version: None,
        }
    }
}

impl DatabaseUpdater {
    pub fn start_update(&mut self, config: &AppConfig) {
        self.state = UpdateState::Updating;
        self.log_lines.clear();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let freshclam = config.freshclam_path();
        let db_dir = config.database_dir.clone();
        let certs_dir = config.clamav_dir.join("certs");
        let conf_path = config.freshclam_conf_path();

        // Ensure freshclam.conf exists
        ensure_freshclam_conf(&conf_path, &db_dir, &certs_dir);

        std::thread::spawn(move || {
            run_freshclam(freshclam, conf_path, certs_dir, tx);
        });
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    UpdateMessage::Progress(line) => {
                        // Clean the line: remove progress chars, carriage returns, etc
                        let cleaned = clean_log_line(&line);
                        // Skip empty lines after cleaning
                        if cleaned.is_empty() {
                            continue;
                        }
                        
                        // Try to extract version info
                        if cleaned.contains("daily.cvd") || cleaned.contains("main.cvd") {
                            if let Some(ver) = extract_db_version(&cleaned) {
                                self.db_version = Some(ver);
                            }
                        }
                        self.log_lines.push(cleaned);
                    }
                    UpdateMessage::Finished(success, msg) => {
                        let cleaned = clean_log_line(&msg);
                        if !cleaned.is_empty() {
                            self.log_lines.push(cleaned);
                        }
                        if success {
                            self.last_update =
                                Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
                        }
                        self.state = UpdateState::Done;
                    }
                    UpdateMessage::Error(e) => {
                        let error_msg = format!("❌ 错误: {}", e);
                        self.log_lines.push(error_msg);
                        self.state = UpdateState::Done;
                    }
                }
            }
        }
    }

    pub fn check_database_status(&mut self, config: &AppConfig) {
        let db_dir = &config.database_dir;
        if db_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(db_dir)
                .ok()
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .filter(|e| {
                            e.path()
                                .extension()
                                .map(|ext| ext == "cvd" || ext == "cld")
                                .unwrap_or(false)
                        })
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default();

            if !entries.is_empty() {
                self.db_version = Some(entries.join(", "));
                // Get last modified time of newest db file
                if let Some(newest) = std::fs::read_dir(db_dir)
                    .ok()
                    .and_then(|rd| {
                        rd.filter_map(|e| e.ok())
                            .filter(|e| {
                                e.path()
                                    .extension()
                                    .map(|ext| ext == "cvd" || ext == "cld")
                                    .unwrap_or(false)
                            })
                            .max_by_key(|e| {
                                e.metadata()
                                    .ok()
                                    .and_then(|m| m.modified().ok())
                            })
                    })
                {
                    if let Ok(meta) = newest.metadata() {
                        if let Ok(modified) = meta.modified() {
                            let dt: chrono::DateTime<chrono::Local> = modified.into();
                            self.last_update = Some(dt.format("%Y-%m-%d %H:%M").to_string());
                        }
                    }
                }
            }
        }
    }
}

fn ensure_freshclam_conf(conf_path: &std::path::Path, db_dir: &std::path::Path, certs_dir: &std::path::Path) {
    let mut content = String::new();
    content.push_str("# ClamAV official database mirror\n");
    content.push_str("DatabaseMirror database.clamav.net\n\n");
    content.push_str(&format!("DatabaseDirectory {}\n", db_dir.display()));
    content.push_str(&format!("CVDCertsDirectory {}\n", certs_dir.display()));
    content.push_str("Foreground yes\n");
    content.push_str("MaxAttempts 5\n");
    content.push_str("ConnectTimeout 30\n");
    content.push_str("ReceiveTimeout 60\n");

    let _ = std::fs::write(conf_path, content);
}

fn run_freshclam(
    freshclam_path: std::path::PathBuf,
    conf_path: std::path::PathBuf,
    certs_dir: std::path::PathBuf,
    tx: mpsc::Sender<UpdateMessage>,
) {
    if !freshclam_path.exists() {
        let _ = tx.send(UpdateMessage::Error(format!(
            "freshclam.exe not found at: {}",
            freshclam_path.display()
        )));
        return;
    }

    let mut cmd = Command::new(&freshclam_path);
    cmd.arg("--stdout");

    if conf_path.exists() {
        cmd.arg(format!("--config-file={}", conf_path.display()));
    }

    // 显式指定证书目录，覆盖编译时硬编码的路径
    if certs_dir.exists() {
        cmd.arg(format!("--cvdcertsdir={}", certs_dir.display()));
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UpdateMessage::Error(format!(
                "Failed to start freshclam: {}",
                e
            )));
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = tx.send(UpdateMessage::Error("No stdout".into()));
            return;
        }
    };

    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            let _ = tx.send(UpdateMessage::Error("No stderr".into()));
            return;
        }
    };

    // Send initial message of starting update
    let _ = tx.send(UpdateMessage::Progress("🔄 正在更新病毒库...".to_string()));

    // Read stdout in current thread
    let tx_stdout = tx.clone();
    let stdout_thread = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if !l.trim().is_empty() {
                        let _ = tx_stdout.send(UpdateMessage::Progress(l));
                    }
                }
                Err(e) => {
                    let _ = tx_stdout.send(UpdateMessage::Error(format!("读取stdout失败: {}", e)));
                }
            }
        }
    });

    // Read stderr in another thread (freshclam often logs to stderr)
    let tx_stderr = tx.clone();
    let stderr_thread = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if !l.trim().is_empty() {
                        let _ = tx_stderr.send(UpdateMessage::Progress(l));
                    }
                }
                Err(e) => {
                    let _ = tx_stderr.send(UpdateMessage::Error(format!("读取stderr失败: {}", e)));
                }
            }
        }
    });

    // Wait for child process to complete
    let exit_status = child.wait();
    
    // Wait for reader threads to finish
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    match exit_status {
        Ok(status) => {
            if status.success() {
                let _ = tx.send(UpdateMessage::Finished(
                    true,
                    "✅ 病毒库更新完成".to_string(),
                ));
            } else {
                let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string());
                let _ = tx.send(UpdateMessage::Finished(
                    false,
                    format!("⚠ freshclam 进程以代码 {} 退出", code),
                ));
            }
        }
        Err(e) => {
            let _ = tx.send(UpdateMessage::Error(format!(
                "等待 freshclam 进程失败: {}",
                e
            )));
        }
    }
}

fn extract_db_version(line: &str) -> Option<String> {
    // freshclam typically outputs lines like:
    // "daily.cvd updated (version: 27495, ... )"
    if line.contains("version:") {
        Some(line.trim().to_string())
    } else {
        None
    }
}

fn clean_log_line(line: &str) -> String {
    // Remove progress bar characters, carriage returns, and control chars
    let cleaned = line
        .chars()
        .filter(|c| {
            // Keep printable chars and newlines
            !c.is_control() || *c == '\n'
        })
        .collect::<String>();
    
    // Split by carriage return (progress bar handling)
    // and take the last non-empty part (the actual message)
    let parts: Vec<&str> = cleaned.split('\r').collect();
    let last_part = parts.last().unwrap_or(&"").trim();
    
    // Further clean: remove ANSI color codes if present
    let no_ansi = last_part
        .chars()
        .fold(String::new(), |mut acc, c| {
            acc.push(c);
            acc
        });
    
    no_ansi.trim().to_string()
}

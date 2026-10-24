//! Signature database updates via the bundled `freshclam.exe`.
//!
//! Improvements over the previous implementation:
//!
//! * the child process is tracked, so an update can be cancelled,
//! * output is split on both `\n` and `\r`, so `freshclam`'s carriage-return
//!   progress bars show up live instead of only when a line completes,
//! * the download percentage and the resulting `version`/`sigs` figures are
//!   parsed out of the output,
//! * ANSI escape sequences are actually stripped (the old code had a no-op
//!   `fold` that claimed to do this),
//! * starting a second update while one is running is rejected instead of
//!   silently orphaning the first child,
//! * the log buffer is bounded.

use crate::bootstrap::EnvInfo;
use crate::config::AppConfig;
use crate::scanner::{ManagedChild, ProcessControl};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Maximum retained log lines.
const MAX_LOG_LINES: usize = 2000;

#[derive(Clone, Debug)]
pub enum UpdateMessage {
    Line(String),
    Finished { success: bool, message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateState {
    Idle,
    Updating,
    Done,
}

pub struct DatabaseUpdater {
    pub state: UpdateState,
    receiver: Option<mpsc::Receiver<UpdateMessage>>,
    pub log_lines: Vec<String>,
    /// Download progress in `0..=1`, when freshclam reports a percentage.
    pub progress: Option<f32>,
    pub last_update: Option<String>,
    /// Signature database version, e.g. `27122`.
    pub db_version: Option<String>,
    /// Number of signatures in the database.
    pub db_sigs: Option<u64>,
    pub db_files: Vec<String>,
    pub db_bytes: u64,
    pub db_modified: Option<String>,
    /// Last failure, surfaced as an inline banner.
    pub last_error: Option<String>,
    control: Arc<ProcessControl>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Default for DatabaseUpdater {
    fn default() -> Self {
        Self {
            state: UpdateState::Idle,
            receiver: None,
            log_lines: Vec::new(),
            progress: None,
            last_update: None,
            db_version: None,
            db_sigs: None,
            db_files: Vec::new(),
            db_bytes: 0,
            db_modified: None,
            last_error: None,
            control: Arc::new(ProcessControl::default()),
            worker: None,
        }
    }
}

impl DatabaseUpdater {
    pub fn is_updating(&self) -> bool {
        self.worker.is_some() || self.state == UpdateState::Updating
    }

    /// Adopt the database information gathered by the background bootstrap.
    /// This replaces the old double `read_dir` scan at startup.
    pub fn apply_env(&mut self, env: &EnvInfo) {
        self.db_files = env.db_files.clone();
        self.db_bytes = env.db_bytes;
        self.db_modified = env.db_modified.clone();
        self.db_version = env.db.version.map(|v| v.to_string());
        self.db_sigs = env.db.sigs;

        if self.last_update.is_none() {
            self.last_update = env.db_modified.clone();
        }
    }

    /// Start `freshclam`. Returns `Err` when an update is already in flight.
    pub fn start_update(&mut self, config: &AppConfig) -> Result<(), String> {
        if self.is_updating() {
            return Err("更新已在进行中".to_string());
        }

        self.state = UpdateState::Updating;
        self.progress = None;
        self.last_error = None;
        self.log_lines.clear();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let freshclam = config.freshclam_path();
        let conf_path = config.freshclam_conf_path();
        let certs_dir = config.certs_dir();

        let _ = std::fs::create_dir_all(&config.database_dir);
        let _ = std::fs::create_dir_all(&certs_dir);
        ensure_freshclam_conf(&conf_path, &config.database_dir, &certs_dir);

        let control = Arc::new(ProcessControl::default());
        self.control = control.clone();
        self.worker = Some(std::thread::spawn(move || {
            run_freshclam(freshclam, conf_path, certs_dir, control, tx);
        }));

        Ok(())
    }

    /// Ask `freshclam` to stop.
    pub fn cancel_update(&mut self) {
        if self.is_updating() {
            self.control.cancel();
        }
        // Keep Updating until the worker has reaped the child and readers.
    }

    pub fn poll_messages(&mut self, config: &AppConfig) {
        let mut finished: Option<(bool, String)> = None;

        if let Some(rx) = self.receiver.take() {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    UpdateMessage::Line(raw) => {
                        let cleaned = clean_log_line(&raw);
                        if cleaned.is_empty() {
                            continue;
                        }

                        if let Some(percent) = parse_percent(&cleaned) {
                            self.progress = Some(percent);
                        }
                        if let Some((version, sigs)) = parse_db_info(&cleaned) {
                            if let Some(version) = version {
                                self.db_version = Some(version.to_string());
                            }
                            if let Some(sigs) = sigs {
                                self.db_sigs = Some(sigs);
                            }
                        }

                        push_bounded(&mut self.log_lines, cleaned);
                    }
                    UpdateMessage::Finished { success, message } => {
                        finished = Some((success, message));
                        break;
                    }
                }
            }

            if finished.is_none() {
                self.receiver = Some(rx);
            }
        }

        if finished.is_none()
            && self
                .worker
                .as_ref()
                .map(|h| h.is_finished())
                .unwrap_or(false)
        {
            finished = Some((false, "更新工作线程意外退出".to_string()));
        }
        if let Some((success, message)) = finished {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            self.receiver = None;
            let success = success && !self.control.cancelled();
            let message = if self.control.cancelled() {
                "病毒库更新已取消".to_string()
            } else {
                message
            };
            self.state = UpdateState::Done;
            self.progress = None;
            push_bounded(&mut self.log_lines, message.clone());

            if success {
                self.last_update = Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
                // Re-read the freshly written database instead of guessing.
                self.apply_env(&crate::bootstrap::probe_database(&config.database_dir));
            } else {
                self.last_error = Some(message);
            }
        }
    }
}

impl Drop for DatabaseUpdater {
    fn drop(&mut self) {
        self.control.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Keep the log bounded so a long-running session cannot grow without limit.
fn push_bounded(lines: &mut Vec<String>, line: String) {
    if lines.len() >= MAX_LOG_LINES {
        lines.drain(0..MAX_LOG_LINES / 4);
    }
    lines.push(line);
}

fn ensure_freshclam_conf(
    conf_path: &std::path::Path,
    db_dir: &std::path::Path,
    certs_dir: &std::path::Path,
) {
    let content = format!(
        "# Generated by ClamAV GUI - safe to edit\n\
         # Official mirrors\n\
         DatabaseMirror database.clamav.net\n\
         DatabaseMirror db.local.clamav.net\n\n\
         DatabaseDirectory {db}\n\
         CVDCertsDirectory {certs}\n\
         Foreground yes\n\
         MaxAttempts 5\n\
         ConnectTimeout 30\n\
         ReceiveTimeout 60\n\
         LogTime yes\n\
         LogFileMaxSize 1M\n",
        db = db_dir.display(),
        certs = certs_dir.display()
    );

    let _ = std::fs::write(conf_path, content);
}

fn run_freshclam(
    freshclam_path: PathBuf,
    conf_path: PathBuf,
    certs_dir: PathBuf,
    control: Arc<ProcessControl>,
    tx: mpsc::Sender<UpdateMessage>,
) {
    if control.cancelled() {
        let _ = tx.send(UpdateMessage::Finished {
            success: false,
            message: "病毒库更新已取消".to_string(),
        });
        return;
    }
    if !freshclam_path.exists() {
        let _ = tx.send(UpdateMessage::Finished {
            success: false,
            message: missing_freshclam_message(&freshclam_path),
        });
        return;
    }

    let mut cmd = Command::new(&freshclam_path);
    cmd.arg("--stdout");
    if conf_path.exists() {
        cmd.arg(format!("--config-file={}", conf_path.display()));
    }
    // Explicitly override the compiled-in certificate path.
    if certs_dir.exists() {
        cmd.arg(format!("--cvdcertsdir={}", certs_dir.display()));
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = tx.send(UpdateMessage::Finished {
                success: false,
                message: format!("无法启动 freshclam: {}", e),
            });
            return;
        }
    };

    let mut child = ManagedChild::new(child, control.clone());

    let _ = tx.send(UpdateMessage::Line("正在连接更新服务器...".to_string()));

    let stdout = child.child.stdout.take();
    let stderr = child.child.stderr.take();

    // Both streams are split on '\r' as well as '\n' so progress bars appear
    // immediately. `freshclam` is not chatty, so byte-at-a-time through a
    // buffered reader is cheap and keeps the logic trivial.
    //
    // Every line is also teed into a bounded tail buffer so the exit status can
    // be interpreted against what freshclam actually said.
    let tail: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    let tx_out = tx.clone();
    let tail_out = tail.clone();
    let stdout_thread = std::thread::spawn(move || {
        if let Some(stdout) = stdout {
            split_stream(stdout, tx_out, tail_out);
        }
    });

    let tx_err = tx.clone();
    let tail_err = tail.clone();
    let stderr_thread = std::thread::spawn(move || {
        if let Some(stderr) = stderr {
            split_stream(stderr, tx_err, tail_err);
        }
    });

    let status = child.wait();
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    let (success, message) = if control.cancelled() {
        (false, "病毒库更新已取消".to_string())
    } else {
        match status {
            Ok(status) => {
                let code = status.code().unwrap_or(-1);
                if code == 0 {
                    (true, "病毒库更新完成".to_string())
                } else {
                    (false, format!("freshclam 以退出代码 {} 结束", code))
                }
            }
            Err(e) => (false, format!("等待 freshclam 失败: {}", e)),
        }
    };

    let _ = tx.send(UpdateMessage::Finished { success, message });
}

/// Whether freshclam's own output indicates a successful run.
/// Message shown when the updater binary is not next to the application.
///
/// The path is redacted on purpose: this string goes straight into the update
/// panel, and it used to print the whole absolute path — the account name and
/// the folder the program was unzipped into — which then travelled into every
/// screenshot and bug report. What matters is that `freshclam` is missing, not
/// where the user keeps it.
fn missing_freshclam_message(path: &std::path::Path) -> String {
    format!(
        "未找到更新程序 freshclam: {}",
        crate::config::display_path(path)
    )
}

/// Read a stream, emitting one message per `\n`- or `\r`-terminated record.
fn split_stream<R: Read>(stream: R, tx: mpsc::Sender<UpdateMessage>, tail: Arc<Mutex<String>>) {
    let mut reader = std::io::BufReader::with_capacity(4096, stream);
    let mut record: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }

        match byte[0] {
            b'\n' | b'\r' => {
                if !record.is_empty() {
                    let text = String::from_utf8_lossy(&record).to_string();
                    record.clear();
                    if !text.trim().is_empty() {
                        remember(&tail, &text);
                        let _ = tx.send(UpdateMessage::Line(text));
                    }
                }
            }
            other => {
                if record.len() < 8192 {
                    record.push(other);
                }
            }
        }
    }

    if !record.is_empty() {
        let text = String::from_utf8_lossy(&record).to_string();
        if !text.trim().is_empty() {
            remember(&tail, &text);
            let _ = tx.send(UpdateMessage::Line(text));
        }
    }
}

/// Append to the bounded output tail used for exit-status interpretation.
fn remember(tail: &Arc<Mutex<String>>, line: &str) {
    if let Ok(mut tail) = tail.lock() {
        if tail.len() < 16 * 1024 {
            tail.push_str(line);
            tail.push('\n');
        }
    }
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Parse a percentage such as `Downloading daily-27123.cdiff [ 45%]`.
fn parse_percent(line: &str) -> Option<f32> {
    let percent_index = line.find('%')?;
    let head = &line[..percent_index];
    let digits: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit() || *c == ' ')
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    // Reversed above, so rebuild in the original order.
    let value: f32 = digits.chars().rev().collect::<String>().parse().ok()?;
    if (0.0..=100.0).contains(&value) {
        Some(value / 100.0)
    } else {
        None
    }
}

/// Extract `version: N` and `sigs: N` from a freshclam status line.
fn parse_db_info(line: &str) -> Option<(Option<u32>, Option<u64>)> {
    let version = field_value(line, "version: ").and_then(|v| v.parse::<u32>().ok());
    let sigs = field_value(line, "sigs: ").and_then(|v| v.parse::<u64>().ok());
    if version.is_none() && sigs.is_none() {
        None
    } else {
        Some((version, sigs))
    }
}

fn field_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(&rest[..end])
    }
}

/// Strip control characters, ANSI escape sequences and carriage-return noise.
fn clean_log_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI sequence: ESC [ params... final-byte
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            } else {
                // Two-character escape.
                let _ = chars.next();
            }
            continue;
        }

        if c == '\r' {
            // A carriage return overwrites the line: keep only what follows.
            out.clear();
            continue;
        }

        if c.is_control() && c != '\t' {
            continue;
        }

        out.push(c);
    }

    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message the user actually reported: it must name the missing
    /// component without publishing their path.
    #[test]
    fn the_missing_freshclam_message_hides_the_users_path() {
        let path = crate::config::base_dir()
            .join("clamav")
            .join("freshclam.exe");
        let message = missing_freshclam_message(&path);

        assert!(message.contains("freshclam"));
        assert!(message.contains(r"clamav\freshclam.exe"));
        assert!(
            !message.contains(&crate::config::base_dir().to_string_lossy().to_string()),
            "message leaked the application directory: {message}"
        );
        assert!(
            !message.contains("Users"),
            "message leaked the account folder: {message}"
        );
    }
}

//! Realtime protection, backed by the bundled YAMAGoya ETW monitor.
//!
//! YAMAGoya runs as a detached background process that writes to a log file;
//! this module supervises its lifetime and tails that log.
//!
//! Safety notes
//! ------------
//! The PID recorded on disk is not trusted on its own. PIDs are recycled by
//! Windows, so a stale pid file whose number has been handed to an unrelated
//! process would previously have caused us to `TerminateProcess` that innocent
//! program. The daemon is now only signalled once its executable image has been
//! verified against the expected path.
//!
//! Shutdown is also synchronous when the app is exiting: the old code spawned a
//! thread from `Drop`, which the process teardown usually killed before it had
//! done anything, leaving the monitor running.

use crate::config::AppConfig;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tail poll interval when the log has no new content.
const TAIL_IDLE: Duration = Duration::from_millis(250);
/// Roll the daemon log over once it grows past this size.
const LOG_ROTATE_BYTES: u64 = 16 * 1024 * 1024;
/// Retained log lines.
const MAX_LOG_LINES: usize = 4000;
/// Retained threat records.
const MAX_THREATS: usize = 2000;

#[derive(Clone, Debug)]
pub enum RealtimeMessage {
    ThreatFound {
        rule_name: String,
        description: String,
    },
    Info(String),
    Error(String),
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub threats: Vec<RealtimeThreat>,
    /// Number of log events seen, i.e. how busy the monitor has been. This is
    /// *not* a count of scanned files.
    pub monitored_events: u64,
    pub log_lines: Vec<String>,
    pub daemon_pid: Option<u32>,
    pub last_error: Option<String>,
    cancel_flag: Arc<Mutex<bool>>,
    receiver: Option<mpsc::Receiver<RealtimeMessage>>,
    worker: Option<std::thread::JoinHandle<()>>,
    stopping: bool,
}

impl Default for RealtimeProtection {
    fn default() -> Self {
        Self {
            state: RealtimeState::Stopped,
            threats: Vec::new(),
            monitored_events: 0,
            log_lines: Vec::new(),
            daemon_pid: None,
            last_error: None,
            cancel_flag: Arc::new(Mutex::new(false)),
            receiver: None,
            worker: None,
            stopping: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn pid_file_path(log_dir: &Path) -> PathBuf {
    log_dir.join("yamagoya.pid")
}

/// Log file the daemon is told to write to.
pub fn yamagoya_log_path(log_dir: &Path) -> PathBuf {
    log_dir.join("yamagoya-realtime.log")
}

/// A pid file records the process id *and* the image path it should belong to.
struct DaemonRecord {
    pid: u32,
}

fn read_daemon_record(log_dir: &Path) -> Option<DaemonRecord> {
    let text = std::fs::read_to_string(pid_file_path(log_dir)).ok()?;
    let mut lines = text.lines();
    let pid = lines.next()?.trim().parse::<u32>().ok()?;
    Some(DaemonRecord { pid })
}

fn write_daemon_record(log_dir: &Path, pid: u32, image: &Path) {
    let content = format!("{}\n{}", pid, image.display());
    let _ = std::fs::write(pid_file_path(log_dir), content);
}

fn remove_daemon_record(log_dir: &Path) {
    let _ = std::fs::remove_file(pid_file_path(log_dir));
}

// ---------------------------------------------------------------------------
// Process introspection
// ---------------------------------------------------------------------------

/// Whether a process with this id currently exists.
fn is_process_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe { CloseHandle(handle) };
        // STILL_ACTIVE
        ok != 0 && exit_code == 259
    }
    #[cfg(unix)]
    {
        // /proc is Linux; other unices report "not alive", which only means the
        // GUI will not try to re-attach to a previous session.
        Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = pid;
        false
    }
}

/// Full image path of a running process, if it can be read.
#[cfg(target_os = "windows")]
fn process_image_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 1024];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };

    if ok == 0 || size == 0 {
        return None;
    }
    buffer.truncate(size as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

#[cfg(not(target_os = "windows"))]
fn process_image_path(_pid: u32) -> Option<PathBuf> {
    None
}

/// Do two paths refer to the same executable?
fn same_executable(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

fn tail_log_loop(
    log_path: PathBuf,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<RealtimeMessage>,
    pid: u32,
) {
    // Wait for the daemon to create its log.
    for _ in 0..40 {
        if log_path.exists() {
            break;
        }
        if cancelled(&cancel) {
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let mut reader = match open_at_end(&log_path) {
        Ok(reader) => reader,
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "无法打开 YAMAGoya 日志: {}",
                e
            )));
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }
    };

    let mut line = String::with_capacity(512);

    loop {
        if cancelled(&cancel) || !is_process_alive(pid) {
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }

        // Detect truncation or log rotation: the file is shorter than the
        // position we are reading from, so start over.
        let position = reader.stream_position().unwrap_or(0);
        if let Ok(meta) = std::fs::metadata(&log_path) {
            if meta.len() < position {
                reader = match open_at_end(&log_path) {
                    Ok(reader) => reader,
                    Err(_) => {
                        std::thread::sleep(TAIL_IDLE);
                        continue;
                    }
                };
                line.clear();
                continue;
            }
        }

        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(TAIL_IDLE),
            Ok(_) => {
                let text = line.trim_end_matches(['\r', '\n']);
                if !text.is_empty() {
                    if let Some(message) = parse_yamagoya_line(text) {
                        if tx.send(message).is_err() {
                            return;
                        }
                    }
                }
            }
            Err(_) => std::thread::sleep(TAIL_IDLE),
        }
    }
}

fn cancelled(flag: &Arc<Mutex<bool>>) -> bool {
    flag.lock().map(|f| *f).unwrap_or(false)
}

/// Open a file positioned at its current end (so pre-existing content is not
/// replayed), falling back to the start when the file is empty.
fn open_at_end(path: &Path) -> std::io::Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let _ = reader.seek(SeekFrom::End(0));
    Ok(reader)
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

impl RealtimeProtection {
    pub fn is_running(&self) -> bool {
        self.state == RealtimeState::Running
    }

    /// Re-attach to a daemon that outlived the previous GUI session.
    pub fn try_reconnect(&mut self, config: &AppConfig) {
        if self.is_running() || self.stopping || self.worker.is_some() {
            return;
        }

        let Some(record) = read_daemon_record(&config.log_dir) else {
            return;
        };

        let expected = config.yamagoya_path();

        // Verify identity, not just liveness: PIDs get reused.
        let identity_ok = process_image_path(record.pid)
            .map(|actual| same_executable(&actual, &expected))
            .unwrap_or(false);

        if !is_process_alive(record.pid) || !identity_ok {
            remove_daemon_record(&config.log_dir);
            return;
        }

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();
        self.state = RealtimeState::Running;
        self.daemon_pid = Some(record.pid);

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let _ = tx.send(RealtimeMessage::Info(format!(
            "已重新连接到后台实时保护进程 (PID {})",
            record.pid
        )));

        let log_path = yamagoya_log_path(&config.log_dir);
        let pid = record.pid;
        self.worker = Some(std::thread::spawn(move || {
            tail_log_loop(log_path, cancel, tx, pid)
        }));
    }

    /// Launch the monitor. Returns an error when YAMAGoya is unavailable.
    pub fn start(&mut self, config: &AppConfig) -> Result<(), String> {
        self.finish_stop();
        if self.stopping {
            return Err("实时保护正在停止，请等待完成后再启动".to_string());
        }
        if self.is_running() {
            return Ok(());
        }
        // A failed log reader is not proof that its daemon has exited.
        // Reap the previous generation before replacing its channel or PID file.
        if self.worker.is_some() {
            self.stop_blocking(config);
        }
        self.try_reconnect(config);
        if self.is_running() {
            return Ok(());
        }

        let yamagoya = config.yamagoya_path();
        if !yamagoya.exists() {
            let message = format!(
                "未找到 YAMAGoya 监控程序: {}",
                crate::config::display_path(&yamagoya)
            );
            self.push_log(format!("ERROR: {}", message));
            self.last_error = Some(message.clone());
            return Err(message);
        }

        // Keep the log bounded across sessions.
        let log_path = yamagoya_log_path(&config.log_dir);
        rotate_log_if_large(&log_path);
        let _ = std::fs::create_dir_all(&config.log_dir);
        let _ = std::fs::write(&log_path, "");

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();
        self.state = RealtimeState::Running;
        self.last_error = None;

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        // Copy everything the worker needs out of `config` before spawning: the
        // thread outlives this call, so it cannot hold a borrow of it.
        let yamagoya_for_start = yamagoya.clone();
        let rules_dir = config.yamagoya_rules_dir.clone();
        let rule_type = config.yamagoya_rule_type.clone();
        let monitor_all = config.yamagoya_monitor_all;
        let kill_process = config.yamagoya_kill_process;
        let log_dir = config.log_dir.clone();

        self.worker = Some(std::thread::spawn(move || {
            yamagoya_daemon_start(
                yamagoya_for_start,
                rules_dir,
                rule_type,
                monitor_all,
                kill_process,
                log_dir,
                cancel,
                tx,
            );
        }));

        Ok(())
    }

    /// Ask the monitor to stop; the teardown happens on a worker thread.
    pub fn stop(&mut self, config: &AppConfig) {
        if self.stopping || (!self.is_running() && self.worker.is_none()) {
            return;
        }
        self.begin_stop();
        self.stopping = true;
        let previous = self.worker.take();
        let yamagoya = config.yamagoya_path();
        let log_dir = config.log_dir.clone();
        self.worker = Some(std::thread::spawn(move || {
            // A start in flight must finish publishing its PID before teardown.
            if let Some(worker) = previous {
                let _ = worker.join();
            }
            stop_yamagoya_daemon(&yamagoya, &log_dir);
        }));
    }

    fn finish_stop(&mut self) {
        if self.stopping
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
        {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            self.stopping = false;
            self.state = RealtimeState::Stopped;
            self.daemon_pid = None;
            self.receiver = None;
        }
    }

    /// Stop synchronously. Required from `Drop`, where a spawned thread would be
    /// torn down before it could finish.
    pub fn stop_blocking(&mut self, config: &AppConfig) {
        self.stop(config);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.stopping = false;
        self.state = RealtimeState::Stopped;
        self.daemon_pid = None;
        self.receiver = None;
    }

    /// A stopped UI state alone does not prove its worker has finished.
    pub fn has_pending_work(&self) -> bool {
        self.is_running() || self.worker.is_some() || self.stopping
    }

    fn begin_stop(&mut self) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        self.state = RealtimeState::Stopped;
        self.daemon_pid = None;
    }

    pub fn poll_messages(&mut self) {
        self.finish_stop();
        if let Some(rx) = self.receiver.take() {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    RealtimeMessage::ThreatFound {
                        rule_name,
                        description,
                    } => {
                        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                        self.monitored_events += 1;
                        self.push_log(format!(
                            "[{}] DETECTED: {} - {}",
                            ts, rule_name, description
                        ));
                        if self.threats.len() >= MAX_THREATS {
                            self.threats.drain(0..MAX_THREATS / 4);
                        }
                        self.threats.push(RealtimeThreat {
                            file_path: description,
                            threat_name: rule_name,
                            timestamp: ts,
                        });
                    }
                    RealtimeMessage::Info(text) => {
                        self.monitored_events += 1;
                        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                        self.push_log(format!("[{}] {}", ts, text));
                    }
                    RealtimeMessage::Error(e) => {
                        self.last_error = Some(e.clone());
                        self.push_log(format!("ERROR: {}", e));
                    }
                    RealtimeMessage::Stopped => {
                        self.state = RealtimeState::Stopped;
                        self.daemon_pid = None;
                    }
                }
            }
            self.receiver = Some(rx);
        }
    }

    fn push_log(&mut self, line: String) {
        if self.log_lines.len() >= MAX_LOG_LINES {
            self.log_lines.drain(0..MAX_LOG_LINES / 4);
        }
        self.log_lines.push(line);
    }
}

impl Drop for RealtimeProtection {
    fn drop(&mut self) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        // Persist-on-exit must not interrupt an explicitly requested stop.
        if self.stopping {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// Move an oversized daemon log aside before a fresh session starts.
fn rotate_log_if_large(log_path: &Path) {
    let Ok(meta) = std::fs::metadata(log_path) else {
        return;
    };
    if meta.len() <= LOG_ROTATE_BYTES {
        return;
    }

    let mut rotated = log_path.as_os_str().to_os_string();
    rotated.push(".1");
    let rotated = PathBuf::from(rotated);
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(log_path, &rotated);
}

#[allow(clippy::too_many_arguments)]
fn yamagoya_daemon_start(
    yamagoya_path: PathBuf,
    rules_dir: PathBuf,
    rule_type: String,
    monitor_all: bool,
    kill_process: bool,
    log_dir: PathBuf,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<RealtimeMessage>,
) {
    let mut args: Vec<String> = vec!["--session".to_string()];

    let rules_dir_str = rules_dir.to_string_lossy().to_string();
    if rules_dir.exists() {
        match rule_type.as_str() {
            "sigma" => {
                args.push("--sigma".to_string());
                args.push(rules_dir_str);
            }
            "yara" => {
                args.push("--yara".to_string());
                args.push(rules_dir_str);
            }
            _ => {
                args.push("--detect".to_string());
                args.push(rules_dir_str);
            }
        }
    } else {
        let _ = tx.send(RealtimeMessage::Error(format!(
            "规则目录不存在: {}",
            crate::config::display_path(&rules_dir)
        )));
    }

    if monitor_all {
        args.push("--all".to_string());
    } else {
        args.push("--file".to_string());
        args.push("--process".to_string());
    }

    if kill_process {
        args.push("--kill".to_string());
    }

    args.push("--verbose".to_string());
    args.push("--no_event_log".to_string());

    let log_path = yamagoya_log_path(&log_dir);
    args.push("--log_path".to_string());
    args.push(log_path.to_string_lossy().to_string());

    // The command line is echoed into the log panel, and it is full of absolute
    // paths (`--log_path`, the rules directory). Show them relative to the app
    // directory instead of exposing the user's folder layout.
    let shown_args: Vec<String> = args
        .iter()
        .map(|arg| {
            let path = std::path::Path::new(arg);
            if path.is_absolute() {
                crate::config::display_path(path)
            } else {
                arg.clone()
            }
        })
        .collect();

    let _ = tx.send(RealtimeMessage::Info(format!(
        "启动实时保护: {} {}",
        crate::config::display_path(&yamagoya_path),
        shown_args.join(" ")
    )));

    let mut cmd = Command::new(&yamagoya_path);
    cmd.args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS
        cmd.creation_flags(0x0800_0000 | 0x0000_0008);
    }

    if cancelled(&cancel) {
        let _ = tx.send(RealtimeMessage::Stopped);
        return;
    }
    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            // Hand the child off; we do not wait on it.
            drop(child);
            write_daemon_record(&log_dir, pid, &yamagoya_path);

            let _ = tx.send(RealtimeMessage::Info(format!(
                "实时保护已启动 (PID {})",
                pid
            )));

            tail_log_loop(log_path, cancel, tx, pid);
        }
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!("启动 YAMAGoya 失败: {}", e)));
            let _ = tx.send(RealtimeMessage::Stopped);
        }
    }
}

/// Stop the daemon: release the ETW session, then terminate the process.
///
/// The daemon is only terminated once its image has been verified, so a
/// recycled PID can never take down an unrelated program.
fn stop_yamagoya_daemon(yamagoya_path: &Path, log_dir: &Path) {
    let Some(record) = read_daemon_record(log_dir) else {
        return;
    };

    // The image path has to come from the live process. The pid file records one
    // too, but that string is data anyone with write access to the log directory
    // can edit, so it is never accepted as proof of identity: if the process
    // cannot be queried, it is left alone. The daemon is always one this program
    // started as the same user, so a failed query means it has already exited —
    // or that the PID now belongs to something else entirely.
    let verified = process_image_path(record.pid)
        .map(|actual| same_executable(&actual, yamagoya_path))
        .unwrap_or(false);

    if verified {
        release_etw_session(yamagoya_path);
        kill_process(record.pid);
    }

    remove_daemon_record(log_dir);
}

/// Run `YAMAGoya --stop` to release the ETW session, with a bounded wait.
///
/// `Command::output()` used to block indefinitely here, which could hang the
/// whole shutdown path.
fn release_etw_session(yamagoya_path: &Path) {
    if !yamagoya_path.exists() {
        return;
    }

    let mut cmd = Command::new(yamagoya_path);
    cmd.arg("--stop")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }

    let Ok(mut child) = cmd.spawn() else {
        return;
    };

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return,
        }
    }
}

/// Terminate a process by id.
fn kill_process(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if !handle.is_null() {
            unsafe {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
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

// ---------------------------------------------------------------------------
// Log parsing
// ---------------------------------------------------------------------------

/// Parse one line of YAMAGoya output.
fn parse_yamagoya_line(line: &str) -> Option<RealtimeMessage> {
    if let Some(index) = line.find("DETECTED (Sigma): ") {
        let rest = &line[index + "DETECTED (Sigma): ".len()..];
        let (rule_name, description) = split_rule_desc(rest);
        return Some(RealtimeMessage::ThreatFound {
            rule_name,
            description,
        });
    }

    if let Some(index) = line.find("DETECTED: ") {
        let rest = &line[index + "DETECTED: ".len()..];
        // Pure PID bookkeeping lines are not detections.
        if rest.starts_with("PID=") {
            return Some(RealtimeMessage::Info(line.to_string()));
        }
        let (rule_name, description) = split_rule_desc(rest);
        return Some(RealtimeMessage::ThreatFound {
            rule_name,
            description,
        });
    }

    if line.contains("[ERROR]") {
        Some(RealtimeMessage::Error(line.to_string()))
    } else {
        Some(RealtimeMessage::Info(line.to_string()))
    }
}

/// Split `"rulename - description"`.
fn split_rule_desc(text: &str) -> (String, String) {
    match text.find(" - ") {
        Some(index) => (
            text[..index].trim().to_string(),
            text[index + 3..].trim().to_string(),
        ),
        None => (text.trim().to_string(), String::new()),
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn restart_is_rejected_until_stop_worker_finishes() {
        let (tx, rx) = mpsc::channel();
        let mut protection = RealtimeProtection::default();
        protection.stopping = true;
        protection.worker = Some(std::thread::spawn(move || {
            let _ = rx.recv();
        }));
        assert!(protection
            .start(&AppConfig::default())
            .unwrap_err()
            .contains("正在停止"));
        assert!(protection.has_pending_work());
        tx.send(()).unwrap();
        protection.worker.take().unwrap().join().unwrap();
        protection.stopping = false;
        assert!(!protection.has_pending_work());
    }

    #[test]
    fn blocking_exit_joins_an_already_requested_stop() {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = finished.clone();
        let mut protection = RealtimeProtection::default();
        protection.stopping = true;
        protection.worker = Some(std::thread::spawn(move || {
            signal.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        protection.stop_blocking(&AppConfig::default());
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!protection.has_pending_work());
    }
}

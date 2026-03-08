use crate::config::AppConfig;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

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
            threats: Vec::new(),
            scanned_count: 0,
            log_lines: Vec::new(),
            cancel_flag: Arc::new(Mutex::new(false)),
            receiver: None,
        }
    }
}

/// PID 文件路径（用于追踪后台常驻进程）
fn pid_file_path(log_dir: &std::path::Path) -> PathBuf {
    log_dir.join("yamagoya.pid")
}

/// YAMAGoya 日志文件路径
fn yamagoya_log_path(log_dir: &std::path::Path) -> PathBuf {
    log_dir.join("yamagoya-realtime.log")
}

/// 读取 PID 文件
fn read_pid(log_dir: &std::path::Path) -> Option<u32> {
    let path = pid_file_path(log_dir);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// 写入 PID 文件
fn write_pid(log_dir: &std::path::Path, pid: u32) {
    let path = pid_file_path(log_dir);
    let _ = std::fs::write(&path, pid.to_string());
}

/// 删除 PID 文件
fn remove_pid(log_dir: &std::path::Path) {
    let path = pid_file_path(log_dir);
    let _ = std::fs::remove_file(&path);
}

/// 检查 PID 对应的进程是否仍在运行（Windows）
fn is_process_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        // OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(0x1000, 0, pid)
        };
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let result = unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                handle,
                &mut exit_code,
            )
        };
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        // STILL_ACTIVE = 259
        result != 0 && exit_code == 259
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

impl RealtimeProtection {
    /// 尝试重新连接到已运行的后台 YAMAGoya 进程
    pub fn try_reconnect(&mut self, config: &AppConfig) {
        if self.state == RealtimeState::Running {
            return;
        }
        if let Some(pid) = read_pid(&config.log_dir) {
            if is_process_alive(pid) {
                // 进程仍在运行，重新连接日志轮询
                let cancel = Arc::new(Mutex::new(false));
                self.cancel_flag = cancel.clone();
                self.state = RealtimeState::Running;

                let (tx, rx) = mpsc::channel();
                self.receiver = Some(rx);

                let log_path = yamagoya_log_path(&config.log_dir);

                let _ = tx.send(RealtimeMessage::Info(format!(
                    "重新连接到后台 YAMAGoya 进程 (PID: {})",
                    pid
                )));

                std::thread::spawn(move || {
                    tail_log_loop(log_path, cancel, tx);
                });
            } else {
                // PID 文件存在但进程已退出，清理
                remove_pid(&config.log_dir);
            }
        }
    }

    pub fn start(&mut self, config: &AppConfig) {
        if self.state == RealtimeState::Running {
            return;
        }

        let yamagoya = config.yamagoya_path();
        if !yamagoya.exists() {
            self.log_lines.push(format!(
                "ERROR: YAMAGoya 未找到: {}",
                yamagoya.display()
            ));
            return;
        }

        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();
        self.state = RealtimeState::Running;

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let rules_dir = config.yamagoya_rules_dir.clone();
        let rule_type = config.yamagoya_rule_type.clone();
        let monitor_all = config.yamagoya_monitor_all;
        let kill_process = config.yamagoya_kill_process;
        let log_dir = config.log_dir.clone();

        std::thread::spawn(move || {
            yamagoya_daemon_start(
                yamagoya,
                rules_dir,
                rule_type,
                monitor_all,
                kill_process,
                log_dir,
                cancel,
                tx,
            );
        });
    }

    pub fn stop(&mut self, config: &AppConfig) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        self.state = RealtimeState::Stopped;

        // 后台终止 YAMAGoya 进程
        let yamagoya = config.yamagoya_path();
        let log_dir = config.log_dir.clone();
        std::thread::spawn(move || {
            stop_yamagoya_daemon(&yamagoya, &log_dir);
        });
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    RealtimeMessage::ThreatFound {
                        rule_name,
                        description,
                    } => {
                        let ts =
                            chrono::Local::now().format("%H:%M:%S").to_string();
                        self.log_lines.push(format!(
                            "[{}] ⚠ DETECTED: {} - {}",
                            ts, rule_name, description
                        ));
                        self.threats.push(RealtimeThreat {
                            file_path: description,
                            threat_name: rule_name,
                            timestamp: ts,
                        });
                        if self.threats.len() > 500 {
                            self.threats.drain(0..100);
                        }
                    }
                    RealtimeMessage::Info(text) => {
                        self.scanned_count += 1;
                        let ts =
                            chrono::Local::now().format("%H:%M:%S").to_string();
                        self.log_lines
                            .push(format!("[{}] {}", ts, text));
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

/// 启动 YAMAGoya 后台常驻进程，并开始轮询其日志文件
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
    // 构建命令行参数
    let mut args: Vec<String> = vec!["--session".to_string()];

    // 添加规则类型和目录
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
    }

    // 监控类别
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

    // 使用日志文件输出（后台常驻模式）
    let log_path = yamagoya_log_path(&log_dir);
    args.push("--log_path".to_string());
    args.push(log_path.to_string_lossy().to_string());

    let _ = tx.send(RealtimeMessage::Info(format!(
        "启动 YAMAGoya 后台进程: {} {}",
        yamagoya_path.display(),
        args.join(" ")
    )));

    // 先清理可能残留的旧日志
    let _ = std::fs::write(&log_path, "");

    let mut cmd = Command::new(&yamagoya_path);
    cmd.args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS
        cmd.creation_flags(0x08000000 | 0x00000008);
    }

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            write_pid(&log_dir, pid);

            let _ = tx.send(RealtimeMessage::Info(format!(
                "YAMAGoya 后台进程已启动 (PID: {})",
                pid
            )));

            // 开始轮询日志文件
            tail_log_loop(log_path, cancel, tx);
        }
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "启动 YAMAGoya 失败: {}",
                e
            )));
            let _ = tx.send(RealtimeMessage::Stopped);
        }
    }
}

/// 轮询日志文件，解析新增行（tail -f 模式）
fn tail_log_loop(
    log_path: PathBuf,
    cancel: Arc<Mutex<bool>>,
    tx: mpsc::Sender<RealtimeMessage>,
) {
    // 等待日志文件出现
    for _ in 0..30 {
        if log_path.exists() {
            break;
        }
        if cancel.lock().map(|f| *f).unwrap_or(false) {
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "无法打开 YAMAGoya 日志: {}",
                e
            )));
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }
    };

    let mut reader = BufReader::new(file);
    // 跳到文件末尾，只读取新内容
    let _ = reader.seek(SeekFrom::End(0));

    loop {
        if cancel.lock().map(|f| *f).unwrap_or(false) {
            let _ = tx.send(RealtimeMessage::Stopped);
            return;
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // 没有新内容，休眠后重试
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Ok(_) => {
                let line = line.trim_end().to_string();
                if !line.is_empty() {
                    if let Some(msg) = parse_yamagoya_line(&line) {
                        if tx.send(msg).is_err() {
                            return;
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

/// 停止 YAMAGoya 后台进程
fn stop_yamagoya_daemon(yamagoya_path: &std::path::Path, log_dir: &std::path::Path) {
    // 先发送 --stop 停止 ETW 会话
    stop_etw_session(yamagoya_path);

    // 通过 PID 终止进程
    if let Some(pid) = read_pid(log_dir) {
        kill_process_by_pid(pid);
        remove_pid(log_dir);
    }
}

/// 终止指定 PID 的进程
fn kill_process_by_pid(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(0x0001, 0, pid) // PROCESS_TERMINATE
        };
        if !handle.is_null() {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(handle, 1);
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
    }
}

/// 停止 YAMAGoya ETW 会话
fn stop_etw_session(yamagoya_path: &std::path::Path) {
    let mut cmd = Command::new(yamagoya_path);
    cmd.arg("--stop");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }

    let _ = cmd.output();
}

/// 解析 YAMAGoya 的输出行
fn parse_yamagoya_line(line: &str) -> Option<RealtimeMessage> {
    // [INFO] {timestamp} DETECTED (Sigma): {title} - {description}
    if let Some(idx) = line.find("DETECTED (Sigma): ") {
        let rest = &line[idx + "DETECTED (Sigma): ".len()..];
        let (rule_name, description) = split_rule_desc(rest);
        return Some(RealtimeMessage::ThreatFound {
            rule_name,
            description,
        });
    }

    // [INFO] {timestamp} DETECTED: {rulename} - {description}
    if let Some(idx) = line.find("DETECTED: ") {
        let rest = &line[idx + "DETECTED: ".len()..];
        // 跳过纯 PID 信息行
        if rest.starts_with("PID=") {
            return Some(RealtimeMessage::Info(line.to_string()));
        }
        let (rule_name, description) = split_rule_desc(rest);
        return Some(RealtimeMessage::ThreatFound {
            rule_name,
            description,
        });
    }

    if line.starts_with("[ERROR]") {
        Some(RealtimeMessage::Error(line.to_string()))
    } else {
        Some(RealtimeMessage::Info(line.to_string()))
    }
}

/// 从 "rulename - description" 格式中提取规则名和描述
fn split_rule_desc(s: &str) -> (String, String) {
    if let Some(dash_idx) = s.find(" - ") {
        (
            s[..dash_idx].to_string(),
            s[dash_idx + 3..].to_string(),
        )
    } else {
        (s.to_string(), String::new())
    }
}

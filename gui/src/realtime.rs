use crate::config::AppConfig;
use std::io::{BufRead, BufReader};
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

impl RealtimeProtection {
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

        std::thread::spawn(move || {
            yamagoya_watch_loop(
                yamagoya,
                rules_dir,
                rule_type,
                monitor_all,
                kill_process,
                cancel,
                tx,
            );
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

/// 使用 YAMAGoya (ETW) 的实时监控循环
fn yamagoya_watch_loop(
    yamagoya_path: PathBuf,
    rules_dir: PathBuf,
    rule_type: String,
    monitor_all: bool,
    kill_process: bool,
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

    let _ = tx.send(RealtimeMessage::Info(format!(
        "启动 YAMAGoya: {} {}",
        yamagoya_path.display(),
        args.join(" ")
    )));

    let mut cmd = Command::new(&yamagoya_path);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

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
                    if cancel.lock().map(|f| *f).unwrap_or(false) {
                        break;
                    }

                    if let Some(msg) = parse_yamagoya_line(&line) {
                        if tx.send(msg).is_err() {
                            break;
                        }
                    }
                }
            }

            // 终止子进程
            let _ = child.kill();
            let _ = child.wait();

            // 清理 ETW 会话
            stop_etw_session(&yamagoya_path);
        }
        Err(e) => {
            let _ = tx.send(RealtimeMessage::Error(format!(
                "启动 YAMAGoya 失败: {}",
                e
            )));
        }
    }

    let _ = tx.send(RealtimeMessage::Stopped);
}

/// 停止 YAMAGoya ETW 会话
fn stop_etw_session(yamagoya_path: &PathBuf) {
    let mut cmd = Command::new(yamagoya_path);
    cmd.arg("--stop");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }

    let _ = cmd.output();
}

/// 解析 YAMAGoya 的 stdout 输出行
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

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
        let conf_path = config.freshclam_conf_path();

        // Ensure freshclam.conf exists
        ensure_freshclam_conf(&conf_path, &db_dir);

        std::thread::spawn(move || {
            run_freshclam(freshclam, conf_path, tx);
        });
    }

    pub fn poll_messages(&mut self) {
        if let Some(ref rx) = self.receiver {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    UpdateMessage::Progress(line) => {
                        // Try to extract version info
                        if line.contains("daily.cvd") || line.contains("main.cvd") {
                            if let Some(ver) = extract_db_version(&line) {
                                self.db_version = Some(ver);
                            }
                        }
                        self.log_lines.push(line);
                    }
                    UpdateMessage::Finished(success, msg) => {
                        self.log_lines.push(msg);
                        if success {
                            self.last_update =
                                Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
                        }
                        self.state = UpdateState::Done;
                    }
                    UpdateMessage::Error(e) => {
                        self.log_lines.push(format!("Error: {}", e));
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

fn ensure_freshclam_conf(conf_path: &std::path::Path, db_dir: &std::path::Path) {
    if !conf_path.exists() {
        let content = format!(
            "DatabaseMirror database.clamav.net\n\
             DatabaseDirectory {}\n\
             Foreground yes\n\
             MaxAttempts 3\n\
             ConnectTimeout 30\n",
            db_dir.display()
        );
        let _ = std::fs::write(conf_path, content);
    }
}

fn run_freshclam(
    freshclam_path: std::path::PathBuf,
    conf_path: std::path::PathBuf,
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

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UpdateMessage::Error(format!(
                "Failed to start freshclam: {}",
                e
            )));
            return;
        }
    };

    let stdout = match child.stdout {
        Some(s) => s,
        None => {
            let _ = tx.send(UpdateMessage::Error("No stdout".into()));
            return;
        }
    };

    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        match line {
            Ok(l) => {
                let _ = tx.send(UpdateMessage::Progress(l));
            }
            Err(e) => {
                let _ = tx.send(UpdateMessage::Error(e.to_string()));
            }
        }
    }

    let _ = tx.send(UpdateMessage::Finished(
        true,
        "Database update complete.".into(),
    ));
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

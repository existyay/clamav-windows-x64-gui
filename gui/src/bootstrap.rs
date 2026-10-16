//! First-run preparation, performed off the UI thread.
//!
//! The standalone build carries the whole ClamAV toolchain (and YAMAGoya)
//! inside the executable as zstd streams. Unpacking them used to happen inside
//! `ClamAvApp::new`, which meant the user stared at nothing for several seconds
//! before the first frame appeared. It now runs on a worker thread while the
//! window is already up and showing progress.
//!
//! The same worker also reads the signature database version straight out of the
//! CVD header, which is far cheaper than spawning `clamscan --version`.

use crate::config::AppConfig;
use std::sync::mpsc;

/// Version information scraped from the local signature database.
#[derive(Clone, Debug, Default)]
pub struct DbHeader {
    /// Creation time string as written in the header, e.g. `19 Mar 2024 09-20-08 +0000`.
    pub time: Option<String>,
    /// Signature database version, e.g. `27122`.
    pub version: Option<u32>,
    /// Number of signatures.
    pub sigs: Option<u64>,
}

/// Everything the bootstrap phase learned.
#[derive(Clone, Debug, Default)]
pub struct EnvInfo {
    pub db: DbHeader,
    pub db_files: Vec<String>,
    /// Total bytes of signature files on disk.
    pub db_bytes: u64,
    /// Newest modification time across the signature files.
    pub db_modified: Option<String>,
}

#[derive(Clone, Debug)]
pub enum BootMessage {
    /// A new step started; `total` is the number of units for this step.
    Step { label: String, done: usize, total: usize },
    /// Progress within the current step.
    Progress { done: usize },
    Info(String),
    Done(EnvInfo),
    Failed(String),
}

/// Tracks the background preparation of the runtime directory.
pub struct Bootstrap {
    pub receiver: Option<mpsc::Receiver<BootMessage>>,
    pub label: String,
    pub done: usize,
    pub total: usize,
    pub finished: bool,
    pub failed: Option<String>,
    pub info: EnvInfo,
    /// Messages worth showing on the dashboard.
    pub notes: Vec<String>,
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self {
            receiver: None,
            label: "准备中".to_string(),
            done: 0,
            total: 0,
            finished: false,
            failed: None,
            info: EnvInfo::default(),
            notes: Vec::new(),
        }
    }
}

impl Bootstrap {
    /// Kick off directory creation, unpacking and the version probe.
    pub fn start(config: &AppConfig) -> Self {
        let (tx, rx) = mpsc::channel();

        let clamav_dir = config.clamav_dir.clone();
        let database_dir = config.database_dir.clone();
        let quarantine_dir = config.quarantine_dir.clone();
        let log_dir = config.log_dir.clone();
        let yamagoya_dir = config.yamagoya_dir.clone();
        let yamagoya_rules_dir = config.yamagoya_rules_dir.clone();

        std::thread::spawn(move || {
            let result = prepare(
                &clamav_dir,
                &database_dir,
                &quarantine_dir,
                &log_dir,
                &yamagoya_dir,
                &yamagoya_rules_dir,
                &tx,
            );

            match result {
                Ok(info) => {
                    let _ = tx.send(BootMessage::Done(info));
                }
                Err(e) => {
                    let _ = tx.send(BootMessage::Failed(e));
                }
            }
        });

        Self {
            receiver: Some(rx),
            ..Default::default()
        }
    }

    pub fn poll(&mut self) {
        if let Some(rx) = self.receiver.take() {
            let mut keep = true;
            loop {
                match rx.try_recv() {
                    Ok(BootMessage::Step { label, done, total }) => {
                        self.label = label;
                        self.done = done;
                        self.total = total;
                    }
                    Ok(BootMessage::Progress { done }) => {
                        self.done = done;
                    }
                    Ok(BootMessage::Info(text)) => {
                        if self.notes.len() < 40 {
                            self.notes.push(text);
                        }
                    }
                    Ok(BootMessage::Done(info)) => {
                        self.info = info;
                        self.finished = true;
                        keep = false;
                        break;
                    }
                    Ok(BootMessage::Failed(e)) => {
                        self.failed = Some(e);
                        self.finished = true;
                        keep = false;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.finished = true;
                        keep = false;
                        break;
                    }
                }
            }
            if keep {
                self.receiver = Some(rx);
            }
        }
    }

    /// Fraction complete in `0..=1`, or `None` when nothing has been reported.
    pub fn fraction(&self) -> Option<f32> {
        if self.finished {
            return Some(1.0);
        }
        if self.total == 0 {
            return None;
        }
        Some((self.done as f32 / self.total as f32).clamp(0.0, 1.0))
    }
}

fn prepare(
    clamav_dir: &std::path::Path,
    database_dir: &std::path::Path,
    quarantine_dir: &std::path::Path,
    log_dir: &std::path::Path,
    yamagoya_dir: &std::path::Path,
    yamagoya_rules_dir: &std::path::Path,
    tx: &mpsc::Sender<BootMessage>,
) -> Result<EnvInfo, String> {
    for dir in [clamav_dir, database_dir, quarantine_dir, log_dir, yamagoya_dir, yamagoya_rules_dir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return Err(format!(
                "无法创建目录 {}: {}",
                crate::config::display_path(dir),
                e
            ));
        }
    }

    // --- Unpack the embedded ClamAV toolchain ---------------------------
    let clamav_files = crate::embedded::embedded_file_count();
    let yamagoya_files = crate::embedded::yamagoya_file_count();
    let total = clamav_files + yamagoya_files;

    if total > 0 {
        let _ = tx.send(BootMessage::Step {
            label: "释放内置组件".to_string(),
            done: 0,
            total,
        });
    }

    let mut done = 0usize;
    if clamav_files > 0 {
        crate::embedded::extract_embedded_binaries_reporting(clamav_dir, |_name| {
            done += 1;
            let _ = tx.send(BootMessage::Progress { done });
        });
    }
    crate::embedded::extract_certs(clamav_dir);

    if yamagoya_files > 0 {
        crate::embedded::extract_yamagoya_reporting(yamagoya_dir, |_name| {
            done += 1;
            let _ = tx.send(BootMessage::Progress { done });
        });
    }

    // --- Probe the signature database -----------------------------------
    let _ = tx.send(BootMessage::Step {
        label: "读取病毒库".to_string(),
        done: 0,
        total: 1,
    });

    let info = probe_database(database_dir);
    let _ = tx.send(BootMessage::Progress { done: 1 });

    if info.db_files.is_empty() {
        let _ = tx.send(BootMessage::Info(
            "尚未安装病毒库，请先执行一次在线更新".to_string(),
        ));
    }

    Ok(info)
}

/// Read the version information out of the local signature database.
///
/// `.cvd` files start with a 512 byte ASCII header of the form
/// `ClamAV-VDB:<time>:<version>:<sigs>:<fl>:<md5>:<builder>:<stime>`
/// (see `libclamav/cvd.c`). `.cld` files are plain archives with no header, so
/// those are reported by name only.
pub fn probe_database(database_dir: &std::path::Path) -> EnvInfo {
    let mut info = EnvInfo::default();

    let Ok(entries) = std::fs::read_dir(database_dir) else {
        return info;
    };

    let mut best_version: Option<u32> = None;
    let mut newest: Option<std::time::SystemTime> = None;
    let mut files: Vec<(String, u64, Option<std::time::SystemTime>)> = Vec::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let is_db = path
            .extension()
            .map(|ext| {
                let ext = ext.to_string_lossy().to_ascii_lowercase();
                ext == "cvd" || ext == "cld"
            })
            .unwrap_or(false);
        if !is_db {
            continue;
        }

        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        let name = entry.file_name().to_string_lossy().to_string();

        if name.to_ascii_lowercase().ends_with(".cvd") {
            if let Some(header) = read_cvd_header(&path) {
                if let Some(v) = header.version {
                    if best_version.map(|b| v > b).unwrap_or(true) {
                        best_version = Some(v);
                    }
                }
                if info.db.time.is_none() {
                    info.db.time = header.time;
                }
                if info.db.sigs.is_none() {
                    info.db.sigs = header.sigs;
                }
            }
        }

        if let Some(m) = modified {
            if newest.map(|n| m > n).unwrap_or(true) {
                newest = Some(m);
            }
        }

        info.db_bytes = info.db_bytes.saturating_add(size);
        files.push((name, size, modified));
    }

    if !files.is_empty() {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        info.db_files = files.into_iter().map(|(name, _, _)| name).collect();
    }

    info.db.version = best_version;
    info.db_modified = newest.map(|t| {
        let dt: chrono::DateTime<chrono::Local> = t.into();
        dt.format("%Y-%m-%d %H:%M").to_string()
    });

    info
}

/// Parse the 512 byte header of a `.cvd` file.
pub fn read_cvd_header(path: &std::path::Path) -> Option<DbHeader> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 512];
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    if filled < 11 || &buf[..11] != b"ClamAV-VDB:" {
        return None;
    }

    let header = String::from_utf8_lossy(&buf[..filled]);
    let head = header.trim_end_matches('\0');
    let mut fields = head.split(':');

    // field 0 is the "ClamAV-VDB" magic.
    let time = fields.nth(1).map(|s| s.trim().to_string());
    let version = fields.next().and_then(|s| s.trim().parse::<u32>().ok());
    let sigs = fields.next().and_then(|s| s.trim().parse::<u64>().ok());

    Some(DbHeader {
        time: time.filter(|t| !t.is_empty()),
        version,
        sigs,
    })
}

//! Scan orchestration around the bundled `clamscan.exe`.
//!
//! Design notes
//! ------------
//! * **One process per worker.** Loading the signature database is the single
//!   most expensive part of starting `clamscan`, so a worker hands *all* of its
//!   targets to a single child process. Parallelism (opt-in) therefore scales
//!   the number of *processes*, not the number of database loads per target.
//! * **No per-file `stat`.** Byte accounting comes from the process summary
//!   rather than a `metadata()` call per scanned file, which used to cost one
//!   extra syscall for every one of potentially millions of files.
//! * **Throttled progress.** `clamscan --verbose` prints one line per file.
//!   Progress updates are coalesced to ~8 per second so a full-disk scan does
//!   not flood the UI channel with a million allocations.
//! * **Directories are pruned with `--exclude-dir`**, which stops ClamAV from
//!   walking into trees such as `WinSxS` at all.

use crate::config::AppConfig;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Upper bound on how often a worker reports progress to the UI.
const PUBLISH_INTERVAL: Duration = Duration::from_millis(120);
/// Hard cap on retained threat records, so a pathological scan cannot exhaust
/// memory.
const MAX_THREATS: usize = 20_000;
/// Hard cap on retained log lines.
const MAX_LOG_LINES: usize = 20_000;
/// How many non-per-file output lines a single worker forwards to the UI.
const MAX_FORWARDED: usize = 400;

// ---------------------------------------------------------------------------
// Quarantine model
// ---------------------------------------------------------------------------

/// Metadata stored next to a quarantined file as `<file>.meta`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuarantineMeta {
    pub original_path: String,
    pub threat_name: String,
    pub quarantine_date: String,
}

/// One entry in the quarantine directory.
#[derive(Clone, Debug)]
pub struct QuarantineEntry {
    pub quarantine_path: PathBuf,
    pub file_size: u64,
    pub meta: Option<QuarantineMeta>,
}

// ---------------------------------------------------------------------------
// Scan model
// ---------------------------------------------------------------------------

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

/// Persisted scan history, restored on the next launch.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Scanning,
    Finished,
}

/// Live counters for a single `clamscan` child process.
#[derive(Clone, Debug, Default)]
pub struct WorkerStat {
    /// Path currently being scanned (empty once the worker is done).
    pub file: String,
    pub scanned: u64,
    pub infected: u64,
    /// Bytes reported by the process summary.
    pub bytes: u64,
    pub finished: bool,
}

/// Summed view of all workers.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanTotals {
    pub scanned: u64,
    pub infected: u64,
    pub bytes: u64,
    pub workers_done: usize,
    pub workers_total: usize,
}

/// State shared between the scan workers and the UI.
#[derive(Debug, Default)]
pub struct ScanShared {
    pub workers: Vec<WorkerStat>,
}

impl ScanShared {
    pub fn new(workers: usize) -> Self {
        Self {
            workers: vec![WorkerStat::default(); workers],
        }
    }

    /// Sum the worker counters. Cheap: no allocation.
    pub fn totals(&self) -> ScanTotals {
        let mut t = ScanTotals {
            workers_total: self.workers.len(),
            ..Default::default()
        };
        for w in &self.workers {
            t.scanned += w.scanned;
            t.infected += w.infected;
            t.bytes += w.bytes;
            if w.finished {
                t.workers_done += 1;
            }
        }
        t
    }
}

/// Messages sent from the scan workers to the UI thread.
#[derive(Clone, Debug)]
pub enum ScanMessage {
    /// Throttled "worker N is currently on this file".
    CurrentFile { worker: usize, file: String },
    Threat(ThreatInfo),
    Log(String),
    /// A worker failed; the scan as a whole may still make progress.
    WorkerFailed(String),
    /// Every worker has exited.
    Finished,
    /// Fatal: the scan never started.
    Error(String),
}

/// Everything needed to build a `clamscan` command line.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub scanner: PathBuf,
    pub database: PathBuf,
    pub certs: Option<PathBuf>,
    pub recursive: bool,
    pub max_file_size_mb: u64,
    pub scan_archives: bool,
    pub scan_mail: bool,
    pub scan_ole2: bool,
    pub scan_pdf: bool,
    pub scan_html: bool,
    pub heuristic_alerts: bool,
    pub exclude_patterns: Vec<String>,
    /// Number of concurrent `clamscan` processes (1 disables parallelism).
    pub parallel: usize,
}

impl ScanOptions {
    pub fn from_config(config: &AppConfig) -> Self {
        let scanner = config.clamscan_path();
        let certs = scanner
            .parent()
            .map(|p| p.join("certs"))
            .filter(|p| p.exists());

        Self {
            scanner,
            database: config.database_dir.clone(),
            certs,
            recursive: config.recursive_scan,
            max_file_size_mb: config.max_file_size_mb.clamp(1, 4096),
            scan_archives: config.scan_archives,
            scan_mail: config.scan_mail,
            scan_ole2: config.scan_ole2,
            scan_pdf: config.scan_pdf,
            scan_html: config.scan_html,
            heuristic_alerts: config.heuristic_alerts,
            exclude_patterns: config
                .exclude_patterns
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            parallel: config.max_scan_threads.clamp(1, 8) as usize,
        }
    }
}

/// Build the `clamscan` command line for a set of targets.
///
/// Exposed separately so the exact arguments can be unit-tested and reviewed.
pub fn build_command(opts: &ScanOptions, targets: &[PathBuf]) -> Command {
    let mut cmd = Command::new(&opts.scanner);

    // --verbose turns on LOGG_INFO; --stdout routes it to stdout so we can read
    // per-file results instead of only the final summary.
    cmd.arg("--verbose");
    cmd.arg("--stdout");

    if opts.database.exists() {
        cmd.arg(format!("--database={}", opts.database.display()));
    }
    if let Some(certs) = &opts.certs {
        cmd.arg(format!("--cvdcertsdir={}", certs.display()));
    }

    if opts.recursive {
        cmd.arg("--recursive");
    }

    let max_mb = opts.max_file_size_mb.max(1);
    cmd.arg(format!("--max-filesize={}M", max_mb));
    cmd.arg(format!("--max-scansize={}M", max_mb.saturating_mul(4)));
    cmd.arg("--max-dir-recursion=15");
    cmd.arg("--pcre-match-limit=10000");
    cmd.arg("--pcre-recmatch-limit=5000");

    // Content types. These were previously collected in the settings UI but
    // never reached the command line, so the toggles silently did nothing.
    cmd.arg(format!(
        "--scan-archive={}",
        bool_arg(opts.scan_archives)
    ));
    cmd.arg(format!("--scan-mail={}", bool_arg(opts.scan_mail)));
    cmd.arg(format!("--scan-ole2={}", bool_arg(opts.scan_ole2)));
    cmd.arg(format!("--scan-pdf={}", bool_arg(opts.scan_pdf)));
    cmd.arg(format!("--scan-html={}", bool_arg(opts.scan_html)));
    cmd.arg(format!(
        "--heuristic-alerts={}",
        bool_arg(opts.heuristic_alerts)
    ));

    // Patterns are applied to both directories and files. `--exclude-dir` is
    // checked *before* recursion, so a match there skips an entire subtree
    // (the difference between walking and not walking `WinSxS`).
    for pattern in &opts.exclude_patterns {
        cmd.arg(format!("--exclude-dir={}", pattern));
        cmd.arg(format!("--exclude={}", pattern));
    }

    for target in targets {
        cmd.arg(target.as_os_str());
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    cmd
}

fn bool_arg(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct ScanEngine {
    pub state: ScanState,
    receiver: Option<mpsc::Receiver<ScanMessage>>,
    pub threats: Vec<ThreatInfo>,
    pub stats: ScanStats,
    pub log_lines: Vec<String>,
    cancel_flag: Arc<Mutex<bool>>,
    /// File currently being scanned, for the progress banner.
    pub current_file: String,
    /// Which worker reported `current_file`.
    pub current_worker: usize,
    scan_started_at: Option<Instant>,
    pub was_cancelled: bool,
    /// Targets of the running (or last) scan, used by "continue scan".
    pub scan_target_paths: Vec<PathBuf>,
    /// Stats carried over from a previous, continued scan.
    stats_base: ScanStats,
    /// Live counters shared with the workers.
    shared: Option<Arc<Mutex<ScanShared>>>,
    /// PIDs of every live `clamscan` child.
    child_ids: Arc<Mutex<Vec<u32>>>,
    /// Deduplication index for [`Self::threats`].
    threat_paths: HashSet<String>,
    /// Set when history was restored, so a stale threat list is not
    /// re-quarantined on the next frame.
    pub restored_from_history: bool,
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
            current_worker: 0,
            scan_started_at: None,
            was_cancelled: false,
            scan_target_paths: Vec::new(),
            stats_base: ScanStats::default(),
            shared: None,
            child_ids: Arc::new(Mutex::new(Vec::new())),
            threat_paths: HashSet::new(),
            restored_from_history: false,
        }
    }
}

impl ScanEngine {
    pub fn is_scanning(&self) -> bool {
        self.state == ScanState::Scanning
    }

    /// Live totals straight from the workers, for the progress display.
    pub fn totals(&self) -> ScanTotals {
        self.shared
            .as_ref()
            .and_then(|s| s.lock().ok().map(|s| s.totals()))
            .unwrap_or_default()
    }

    /// Fraction of *worker processes* that have finished.
    ///
    /// Only meaningful with more than one worker; a single process gives no
    /// granularity, so the UI falls back to an indeterminate bar.
    pub fn progress_fraction(&self) -> Option<f32> {
        let totals = self.totals();
        if totals.workers_total > 1 {
            Some(totals.workers_done as f32 / totals.workers_total as f32)
        } else {
            None
        }
    }

    pub fn start_scan_targets(&mut self, targets: Vec<PathBuf>, config: &AppConfig) {
        if self.is_scanning() {
            self.push_log("INFO: 扫描正在进行中，请先停止当前扫描");
            return;
        }
        if targets.is_empty() {
            self.state = ScanState::Finished;
            self.push_log("ERROR: 未找到可扫描的目标");
            return;
        }

        self.threats.clear();
        self.threat_paths.clear();
        self.stats = ScanStats::default();
        self.stats_base = ScanStats::default();
        self.log_lines.clear();
        self.current_file.clear();
        self.was_cancelled = false;
        self.restored_from_history = false;
        self.scan_target_paths = targets.clone();
        self.scan_started_at = Some(Instant::now());
        self.state = ScanState::Scanning;

        self.spawn(targets, ScanOptions::from_config(config));
    }

    /// Resume using the targets recorded for the last scan.
    pub fn continue_scan_previous(&mut self, config: &AppConfig) {
        let targets = self.scan_target_paths.clone();
        self.continue_scan_targets(targets, config);
    }

    pub fn continue_scan_targets(&mut self, targets: Vec<PathBuf>, config: &AppConfig) {
        if self.is_scanning() {
            self.push_log("INFO: 扫描正在进行中，请先停止当前扫描");
            return;
        }
        if targets.is_empty() {
            self.state = ScanState::Finished;
            self.push_log("ERROR: 未找到可扫描的目标");
            return;
        }

        // Keep the threats and log lines we already have, and accumulate the
        // new run's counters on top of the previous ones.
        self.stats_base = self.stats.clone();
        self.current_file.clear();
        self.was_cancelled = false;
        self.restored_from_history = false;
        self.scan_started_at = Some(Instant::now());
        self.state = ScanState::Scanning;
        self.push_log("INFO: 继续扫描...");

        self.spawn(targets, ScanOptions::from_config(config));
    }

    fn spawn(&mut self, targets: Vec<PathBuf>, opts: ScanOptions) {
        let cancel = Arc::new(Mutex::new(false));
        self.cancel_flag = cancel.clone();

        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);

        let workers = effective_workers(targets.len(), opts.parallel);
        let shared = Arc::new(Mutex::new(ScanShared::new(workers)));
        self.shared = Some(shared.clone());

        let child_ids = self.child_ids.clone();
        let chunks = split_targets(targets, workers);

        std::thread::spawn(move || {
            if !opts.scanner.exists() {
                let _ = tx.send(ScanMessage::Error(format!(
                    "扫描引擎未找到: {}",
                    crate::config::display_path(&opts.scanner)
                )));
                return;
            }

            let mut handles = Vec::with_capacity(chunks.len());
            for (index, chunk) in chunks.into_iter().enumerate() {
                let opts = opts.clone();
                let shared = shared.clone();
                let cancel = cancel.clone();
                let child_ids = child_ids.clone();
                let tx = tx.clone();

                handles.push(std::thread::spawn(move || {
                    run_worker(index, chunk, opts, shared, cancel, child_ids, tx);
                }));
            }

            for handle in handles {
                let _ = handle.join();
            }

            let _ = tx.send(ScanMessage::Finished);
        });
    }

    pub fn cancel_scan(&mut self) {
        let was_scanning = self.is_scanning();

        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }

        // Fold the live worker counters into the base *before* dropping the
        // shared state, otherwise the numbers would collapse back to whatever
        // the previous scan reported.
        let totals = self.totals();
        self.stats_base.scanned_files += totals.scanned;
        self.stats_base.infected_files += totals.infected;
        self.stats_base.scanned_data_mb += totals.bytes as f64 / (1024.0 * 1024.0);

        // Kill every live child; this also unblocks the blocking readers.
        let pids: Vec<u32> = self
            .child_ids
            .lock()
            .map(|mut ids| std::mem::take(&mut *ids))
            .unwrap_or_default();
        for pid in pids {
            kill_process_tree(pid);
        }

        // Drop the receiver so late messages are discarded.
        self.receiver = None;
        self.shared = None;

        if let Some(started) = self.scan_started_at {
            self.stats_base.elapsed_secs += started.elapsed().as_secs_f64();
        }

        if was_scanning {
            self.was_cancelled = true;
        }

        self.state = ScanState::Finished;
        self.scan_started_at = None;
        self.current_file.clear();
        self.stats = self.stats_base.clone();
    }

    pub fn poll_messages(&mut self) {
        let mut finished = false;

        // The receiver is taken out of `self` for the duration of the drain so
        // that the handlers below can freely mutate the engine.
        if let Some(rx) = self.receiver.take() {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMessage::CurrentFile { worker, file } => {
                        self.current_worker = worker;
                        self.current_file = file;
                    }
                    ScanMessage::Threat(info) => {
                        if self.threat_paths.insert(info.file_path.clone()) {
                            self.push_log(format!(
                                "THREAT: {} -> {}",
                                info.file_path, info.threat_name
                            ));
                            if self.threats.len() < MAX_THREATS {
                                self.threats.push(info);
                            }
                        }
                    }
                    ScanMessage::Log(line) => self.push_log(line),
                    ScanMessage::WorkerFailed(text) => {
                        self.push_log(format!("ERROR: {}", text));
                    }
                    ScanMessage::Finished => finished = true,
                    ScanMessage::Error(e) => {
                        self.push_log(format!("ERROR: {}", e));
                        finished = true;
                    }
                }
            }

            // Keep listening while the scan is live; drop the receiver once it
            // is over so the channel is released.
            if !finished {
                self.receiver = Some(rx);
            }
        }

        if finished {
            self.state = ScanState::Finished;
            self.scan_started_at = None;
            self.current_file.clear();
        }

        // Live counters.
        let totals = self.totals();
        let elapsed = self
            .scan_started_at
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);

        self.stats = ScanStats {
            scanned_files: self.stats_base.scanned_files + totals.scanned,
            infected_files: self.stats_base.infected_files + totals.infected,
            scanned_data_mb: self.stats_base.scanned_data_mb
                + totals.bytes as f64 / (1024.0 * 1024.0),
            elapsed_secs: if self.is_scanning() {
                self.stats_base.elapsed_secs + elapsed
            } else {
                self.stats.elapsed_secs.max(self.stats_base.elapsed_secs)
            },
        };
    }

    fn push_log(&mut self, line: impl Into<String>) {
        if self.log_lines.len() >= MAX_LOG_LINES {
            self.log_lines.drain(0..MAX_LOG_LINES / 4);
        }
        self.log_lines.push(line.into());
    }

    /// Persist the current scan state.
    pub fn save_history(&self, path: &Path, scan_target: &str) {
        let history = ScanHistory {
            threats: self.threats.clone(),
            stats: self.stats.clone(),
            log_lines: self.log_lines.clone(),
            scan_target: scan_target.to_string(),
            scan_target_paths: self
                .scan_target_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            last_scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            was_completed: self.state == ScanState::Finished && !self.was_cancelled,
        };
        if let Ok(json) = serde_json::to_string_pretty(&history) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Restore a previous scan, returning the recorded target description.
    pub fn load_history(&mut self, path: &Path) -> Option<String> {
        let data = std::fs::read_to_string(path).ok()?;
        let history: ScanHistory = serde_json::from_str(&data).ok()?;
        if history.threats.is_empty()
            && history.stats.scanned_files == 0
            && history.log_lines.is_empty()
        {
            return None;
        }

        self.threat_paths = history
            .threats
            .iter()
            .map(|t| t.file_path.clone())
            .collect();
        self.threats = history.threats;
        self.stats = history.stats.clone();
        self.stats_base = history.stats;
        self.log_lines = history.log_lines;
        self.was_cancelled = !history.was_completed;
        self.scan_target_paths = history
            .scan_target_paths
            .iter()
            .map(PathBuf::from)
            .collect();
        self.state = ScanState::Finished;
        self.restored_from_history = true;
        Some(history.scan_target)
    }

    /// Move an infected file into the quarantine directory.
    pub fn quarantine_threat(
        &self,
        threat: &ThreatInfo,
        quarantine_dir: &Path,
    ) -> Result<PathBuf, String> {
        let src = PathBuf::from(&threat.file_path);
        if !src.exists() {
            return Err("文件不存在".into());
        }

        std::fs::create_dir_all(quarantine_dir)
            .map_err(|e| format!("无法创建隔离目录: {}", e))?;

        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());

        let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();

        // Two files with the same name quarantined within the same second used
        // to collide and the second one silently overwrote the first. Pick a
        // free name instead.
        let mut dest = quarantine_dir.join(format!("{}.{}.quarantine", name, stamp));
        let mut counter = 1u32;
        while dest.exists() || meta_path_for(&dest).exists() {
            dest = quarantine_dir.join(format!("{}.{}.{}.quarantine", name, stamp, counter));
            counter += 1;
            if counter > 10_000 {
                return Err("无法生成唯一的隔离文件名".into());
            }
        }

        move_file_cross_drive(&src, &dest)?;

        let meta = QuarantineMeta {
            original_path: threat.file_path.clone(),
            threat_name: threat.threat_name.clone(),
            quarantine_date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = std::fs::write(meta_path_for(&dest), json);
        }

        Ok(dest)
    }
}

impl Drop for ScanEngine {
    fn drop(&mut self) {
        let pids: Vec<u32> = self
            .child_ids
            .lock()
            .map(|mut ids| std::mem::take(&mut *ids))
            .unwrap_or_default();
        for pid in pids {
            kill_process_tree(pid);
        }
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// How many `clamscan` processes to run: never more than targets, never fewer
/// than one.
fn effective_workers(targets: usize, requested: usize) -> usize {
    requested.clamp(1, 8).min(targets.max(1)).max(1)
}

/// Round-robin the targets so expensive and cheap ones are mixed.
fn split_targets(targets: Vec<PathBuf>, workers: usize) -> Vec<Vec<PathBuf>> {
    let workers = workers.max(1);
    let mut chunks: Vec<Vec<PathBuf>> = vec![Vec::new(); workers];
    for (index, target) in targets.into_iter().enumerate() {
        chunks[index % workers].push(target);
    }
    chunks.retain(|chunk| !chunk.is_empty());
    chunks
}

fn cancelled(flag: &Arc<Mutex<bool>>) -> bool {
    flag.lock().map(|f| *f).unwrap_or(false)
}

fn run_worker(
    index: usize,
    targets: Vec<PathBuf>,
    opts: ScanOptions,
    shared: Arc<Mutex<ScanShared>>,
    cancel: Arc<Mutex<bool>>,
    child_ids: Arc<Mutex<Vec<u32>>>,
    tx: mpsc::Sender<ScanMessage>,
) {
    let mut cmd = build_command(&opts, &targets);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = tx.send(ScanMessage::WorkerFailed(format!(
                "启动扫描器失败: {}",
                e
            )));
            mark_worker_finished(&shared, index);
            return;
        }
    };

    let pid = child.id();
    if let Ok(mut ids) = child_ids.lock() {
        ids.push(pid);
    }

    let Some(stdout) = child.stdout.take() else {
        let _ = tx.send(ScanMessage::WorkerFailed("无法读取扫描器输出".into()));
        let _ = child.wait();
        remove_child(&child_ids, pid);
        mark_worker_finished(&shared, index);
        return;
    };

    // Drain stderr on its own thread so a chatty child cannot deadlock on a
    // full pipe buffer while we are reading stdout.
    let stderr = child.stderr.take();
    let stderr_handle = std::thread::spawn(move || {
        let Some(stderr) = stderr else {
            return String::new();
        };
        let mut text = String::new();
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if text.len() < 8 * 1024 {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(line);
            }
        }
        text
    });

    let mut scanned: u64 = 0;
    let mut infected: u64 = 0;
    let mut bytes: u64 = 0;
    let mut summary_scanned: Option<u64> = None;
    let mut summary_infected: Option<u64> = None;
    let mut summary_bytes: Option<u64> = None;
    // Seeded in the past so the very first line already publishes; `checked_sub`
    // avoids a panic on the (absurd) underflow case.
    let mut last_publish = Instant::now()
        .checked_sub(PUBLISH_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut last_reported = String::new();
    let mut forwarded = 0usize;

    // Reuse one buffer instead of allocating a String per output line.
    let mut reader = BufReader::with_capacity(64 * 1024, stdout);
    let mut line = String::with_capacity(1024);

    loop {
        if cancelled(&cancel) {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => continue,
        }

        let text = line.trim_end_matches(['\r', '\n']);

        if let Some((path, threat)) = parse_found(text) {
            infected += 1;
            scanned += 1;
            let _ = tx.send(ScanMessage::Threat(ThreatInfo {
                file_path: path,
                threat_name: threat,
            }));
        } else if let Some(path) = parse_ok(text) {
            scanned += 1;
            if last_publish.elapsed() >= PUBLISH_INTERVAL && path != last_reported {
                last_reported.clear();
                last_reported.push_str(path);
                let _ = tx.send(ScanMessage::CurrentFile {
                    worker: index,
                    file: path.to_string(),
                });
            }
        } else if let Some(value) = parse_metric(text, "Scanned files:") {
            summary_scanned = Some(value);
        } else if let Some(value) = parse_metric(text, "Infected files:") {
            summary_infected = Some(value);
        } else if text.starts_with("Data scanned:") {
            if let Some(kb) = parse_data_scanned_kib(text) {
                summary_bytes = Some(kb);
            }
        } else if forwarded < MAX_FORWARDED && !text.is_empty() {
            // Anything that is not a per-file result: engine banner, database
            // loading, warnings and the summary block. These are few, and they
            // are exactly what someone reading the log wants to see. The cap
            // keeps a pathologically broken run from flooding the channel.
            forwarded += 1;
            let _ = tx.send(ScanMessage::Log(text.to_string()));
        }

        if last_publish.elapsed() >= PUBLISH_INTERVAL {
            publish(&shared, index, &last_reported, scanned, infected, bytes);
            last_publish = Instant::now();
        }
    }

    // Summary values are authoritative for this process.
    if let Some(v) = summary_scanned {
        scanned = v;
    }
    if let Some(v) = summary_infected {
        infected = v;
    }
    if let Some(v) = summary_bytes {
        bytes = v;
    }

    let was_cancelled = cancelled(&cancel);
    let status = child.wait();
    let stderr_text = stderr_handle.join().unwrap_or_default();
    remove_child(&child_ids, pid);

    publish(&shared, index, "", scanned, infected, bytes);
    mark_worker_finished(&shared, index);

    if was_cancelled {
        return;
    }

    match status {
        Ok(exit) => {
            // clamscan: 0 = clean, 1 = threats found, >= 2 = error.
            let code = exit.code().unwrap_or(-1);
            if code >= 2 {
                let detail = if stderr_text.is_empty() {
                    format!("扫描器退出代码 {}", code)
                } else {
                    stderr_text
                };
                let _ = tx.send(ScanMessage::WorkerFailed(detail));
            }
        }
        Err(e) => {
            let _ = tx.send(ScanMessage::WorkerFailed(format!(
                "等待扫描器失败: {}",
                e
            )));
        }
    }
}

fn publish(
    shared: &Arc<Mutex<ScanShared>>,
    index: usize,
    file: &str,
    scanned: u64,
    infected: u64,
    bytes: u64,
) {
    if let Ok(mut shared) = shared.lock() {
        if let Some(worker) = shared.workers.get_mut(index) {
            if worker.file != file {
                worker.file.clear();
                worker.file.push_str(file);
            }
            worker.scanned = scanned;
            worker.infected = infected;
            worker.bytes = bytes;
        }
    }
}

fn mark_worker_finished(shared: &Arc<Mutex<ScanShared>>, index: usize) {
    if let Ok(mut shared) = shared.lock() {
        if let Some(worker) = shared.workers.get_mut(index) {
            worker.finished = true;
            worker.file.clear();
        }
    }
}

fn remove_child(child_ids: &Arc<Mutex<Vec<u32>>>, pid: u32) {
    if let Ok(mut ids) = child_ids.lock() {
        ids.retain(|&id| id != pid);
    }
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Parse `"<path>: <THREAT> FOUND"`.
///
/// The split point is the *last* `": "` so that a Windows drive letter and a
/// path containing colons both survive. Trailing `" FOUND"` is pure ASCII, so
/// slicing it off can never land inside a multi-byte character.
fn parse_found(line: &str) -> Option<(String, String)> {
    let without = line.strip_suffix(" FOUND")?;
    let sep = without.rfind(": ")?;
    let path = without[..sep].trim();
    let threat = without[sep + 2..].trim();
    if path.is_empty() || threat.is_empty() {
        return None;
    }
    Some((path.to_string(), threat.to_string()))
}

/// Parse `"<path>: OK"`.
fn parse_ok(line: &str) -> Option<&str> {
    let path = line.strip_suffix(": OK")?.trim();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Parse `"<label>: <number>"`.
fn parse_metric(line: &str, label: &str) -> Option<u64> {
    let rest = line.strip_prefix(label)?;
    rest.trim().parse::<u64>().ok()
}

/// Parse `"Data scanned: 1.23 GiB"` and return the size in KiB.
///
/// ClamAV prints binary units (`GiB`/`MiB`/`KiB`/`B`, see `loggBytes` in
/// `clamscan/clamscan.c`). The previous implementation only knew about `GB`
/// and friends, so a `GiB` figure fell through to a default that reported
/// gibibytes as mebibytes – a factor of 1024 out.
fn parse_data_scanned_kib(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("Data scanned:")?.trim();
    let mut parts = rest.split_whitespace();
    let value = parts.next()?.parse::<f64>().ok()?;
    let unit = parts.next().unwrap_or("B").to_ascii_uppercase();

    let unit = unit.strip_suffix('B').unwrap_or(&unit);
    let unit = unit.strip_suffix('I').unwrap_or(unit);

    let mib = match unit {
        "T" => value * 1024.0 * 1024.0,
        "G" => value * 1024.0,
        "M" => value,
        "K" => value / 1024.0,
        "" => value / (1024.0 * 1024.0),
        _ => value,
    };

    if !mib.is_finite() || mib < 0.0 {
        return None;
    }
    Some((mib * 1024.0) as u64)
}

// ---------------------------------------------------------------------------
// Process control
// ---------------------------------------------------------------------------

fn kill_process_tree(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // `taskkill /T` also reaps any grandchildren the scanner spawned.
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
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

// ---------------------------------------------------------------------------
// Quarantine helpers
// ---------------------------------------------------------------------------

/// Sibling metadata path for a quarantined file.
///
/// Built by appending to the `OsString` rather than `format!("{}.meta", path.display())`,
/// which would corrupt non-UTF-8 paths and lose the association.
fn meta_path_for(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(".meta");
    PathBuf::from(name)
}

/// Move a file, falling back to copy+delete when the destination is on another
/// volume (where `rename` fails).
fn move_file_cross_drive(src: &Path, dest: &Path) -> Result<(), String> {
    if std::fs::rename(src, dest).is_ok() {
        return Ok(());
    }

    std::fs::copy(src, dest).map_err(|e| format!("复制文件失败: {}", e))?;

    match std::fs::remove_file(src) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "文件已复制到隔离区，但无法删除原文件（可能被占用）: {}",
            e
        )),
    }
}

/// List the quarantine directory, newest first.
pub fn list_quarantine_entries(quarantine_dir: &Path) -> Vec<QuarantineEntry> {
    let Ok(dir) = std::fs::read_dir(quarantine_dir) else {
        return Vec::new();
    };

    let mut entries: Vec<(std::time::SystemTime, QuarantineEntry)> = Vec::new();

    for dir_entry in dir.filter_map(|e| e.ok()) {
        let path = dir_entry.path();
        if path.extension().map(|e| e != "quarantine").unwrap_or(true) {
            continue;
        }

        // One `metadata()` call per entry, not two.
        let (file_size, modified) = match dir_entry.metadata() {
            Ok(meta) => (
                meta.len(),
                meta.modified().unwrap_or(std::time::UNIX_EPOCH),
            ),
            Err(_) => (0, std::time::UNIX_EPOCH),
        };

        let parsed_meta = std::fs::read_to_string(meta_path_for(&path))
            .ok()
            .and_then(|s| serde_json::from_str::<QuarantineMeta>(&s).ok());

        entries.push((
            modified,
            QuarantineEntry {
                quarantine_path: path,
                file_size,
                meta: parsed_meta,
            },
        ));
    }

    entries.sort_by(|a, b| b.0.cmp(&a.0));
    entries.into_iter().map(|(_, e)| e).collect()
}

/// Put a quarantined file back where it came from.
pub fn restore_quarantined(entry: &QuarantineEntry) -> Result<(), String> {
    let original = entry
        .meta
        .as_ref()
        .map(|m| PathBuf::from(&m.original_path))
        .ok_or_else(|| "缺少原始路径信息，无法恢复".to_string())?;

    if let Some(parent) = original.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    move_file_cross_drive(&entry.quarantine_path, &original)
        .map_err(|e| format!("恢复失败: {}", e))?;

    let _ = std::fs::remove_file(meta_path_for(&entry.quarantine_path));
    Ok(())
}

/// Delete a quarantined file and its metadata.
pub fn delete_quarantined(entry: &QuarantineEntry) -> Result<(), String> {
    std::fs::remove_file(&entry.quarantine_path).map_err(|e| format!("删除失败: {}", e))?;
    let _ = std::fs::remove_file(meta_path_for(&entry.quarantine_path));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ScanOptions {
        ScanOptions {
            scanner: PathBuf::from(r"C:\clamav\clamscan.exe"),
            // A directory that really exists, so the `exists()` guard in
            // `build_command` passes and the flag is emitted.
            database: std::env::temp_dir(),
            certs: None,
            recursive: true,
            max_file_size_mb: 100,
            scan_archives: true,
            scan_mail: false,
            scan_ole2: true,
            scan_pdf: true,
            scan_html: false,
            heuristic_alerts: true,
            exclude_patterns: vec![r"[\\/]WinSxS[\\/]?$".to_string()],
            parallel: 1,
        }
    }

    fn args_of(opts: &ScanOptions, targets: &[&str]) -> Vec<String> {
        let targets: Vec<PathBuf> = targets.iter().map(PathBuf::from).collect();
        build_command(opts, &targets)
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn found_lines_split_path_and_threat() {
        let (path, threat) =
            parse_found(r"C:\Users\me\Downloads\eicar.com: Eicar-Test-Signature FOUND").unwrap();
        assert_eq!(path, r"C:\Users\me\Downloads\eicar.com");
        assert_eq!(threat, "Eicar-Test-Signature");
    }

    #[test]
    fn found_lines_split_at_the_last_separator() {
        // Windows paths really do contain ": ", so the split has to happen at
        // the *last* one, otherwise the path is cut in the middle.
        let (path, threat) = parse_found(r"C:\odd: dir\x.exe: Win.Trojan.Agent-1 FOUND").unwrap();
        assert_eq!(path, r"C:\odd: dir\x.exe");
        assert_eq!(threat, "Win.Trojan.Agent-1");
    }

    #[test]
    fn a_clean_file_named_found_is_not_a_threat() {
        // `parse_found` must not fire on a clean line for a file that happens to
        // be called "a FOUND".
        assert!(parse_found(r"C:\a FOUND: OK").is_none());
        assert_eq!(parse_ok(r"C:\a FOUND: OK"), Some(r"C:\a FOUND"));
        // ...and an infected line is never mistaken for a clean one.
        assert!(parse_ok(r"C:\x.exe: Eicar-Test-Signature FOUND").is_none());
    }

    #[test]
    fn summary_metrics_are_read() {
        assert_eq!(
            parse_metric("Scanned files: 1234", "Scanned files:"),
            Some(1234)
        );
        assert_eq!(parse_metric("Infected files: 0", "Infected files:"), Some(0));
        assert_eq!(
            parse_metric("Scanned directories: 12", "Scanned files:"),
            None
        );
    }

    #[test]
    fn data_scanned_understands_binary_units() {
        // Regression: `GiB` used to be read as megabytes, under-reporting the
        // scanned volume by a factor of 1024.
        assert_eq!(
            parse_data_scanned_kib("Data scanned: 1.50 GiB"),
            Some(1_572_864)
        );
        assert_eq!(parse_data_scanned_kib("Data scanned: 5 MiB"), Some(5 * 1024));
        assert_eq!(parse_data_scanned_kib("Data scanned: 2 KiB"), Some(2));
        assert_eq!(parse_data_scanned_kib("Data scanned: 10 MB"), Some(10 * 1024));
        assert_eq!(
            parse_data_scanned_kib("Data scanned: 3 GB"),
            Some(3 * 1024 * 1024)
        );
        assert!(parse_data_scanned_kib("Scanned files: 3").is_none());
        assert!(parse_data_scanned_kib("Data scanned: nonsense").is_none());
    }

    #[test]
    fn the_command_line_carries_every_setting() {
        let args = args_of(&opts(), &[r"C:\scan"]);

        assert!(args.contains(&"--verbose".to_string()));
        assert!(args.contains(&"--stdout".to_string()));
        assert!(args.contains(&"--recursive".to_string()));
        assert!(args.contains(&format!("--database={}", std::env::temp_dir().display())));
        assert!(args.contains(&"--max-filesize=100M".to_string()));
        assert!(args.contains(&"--max-scansize=400M".to_string()));

        // The content toggles were previously collected in the UI and then
        // never passed to the engine at all.
        assert!(args.contains(&"--scan-archive=yes".to_string()));
        assert!(args.contains(&"--scan-mail=no".to_string()));
        assert!(args.contains(&"--scan-ole2=yes".to_string()));
        assert!(args.contains(&"--scan-pdf=yes".to_string()));
        assert!(args.contains(&"--scan-html=no".to_string()));
        assert!(args.contains(&"--heuristic-alerts=yes".to_string()));

        // A pattern is applied to directories *and* files.
        let pattern = r"[\\/]WinSxS[\\/]?$";
        assert!(args.contains(&format!("--exclude-dir={pattern}")));
        assert!(args.contains(&format!("--exclude={pattern}")));

        // Targets come last so a target can never be swallowed by an option.
        assert_eq!(args.last().unwrap().as_str(), r"C:\scan");
    }

    #[test]
    fn the_recursive_flag_follows_the_setting() {
        let mut o = opts();
        o.recursive = false;
        assert!(!args_of(&o, &[r"C:\scan"]).contains(&"--recursive".to_string()));
    }

    #[test]
    fn certs_are_only_passed_when_present() {
        let mut o = opts();
        o.certs = Some(PathBuf::from(r"C:\clamav\certs"));
        assert!(args_of(&o, &[r"C:\scan"]).contains(&r"--cvdcertsdir=C:\clamav\certs".to_string()));
    }

    #[test]
    fn a_missing_database_directory_is_not_pointed_at() {
        // Before the first update there is no database on disk. Passing the flag
        // anyway would make the engine fail on a path that does not exist, so
        // the flag is omitted and the engine falls back to its own default.
        let mut o = opts();
        o.database = PathBuf::from(r"C:\definitely\not\here\clamav-db");

        assert!(!args_of(&o, &[r"C:\scan"])
            .iter()
            .any(|a| a.starts_with("--database=")));
    }

    #[test]
    fn worker_count_is_clamped() {
        assert_eq!(effective_workers(0, 4), 1, "one worker for an empty list");
        assert_eq!(effective_workers(1, 4), 1, "never more workers than targets");
        assert_eq!(effective_workers(2, 8), 2);
        assert_eq!(effective_workers(100, 64), 8, "capped at 8 processes");
        assert_eq!(effective_workers(100, 0), 1);
    }

    #[test]
    fn splitting_targets_never_loses_or_empties_anything() {
        let targets: Vec<PathBuf> = (0..7)
            .map(|i| PathBuf::from(format!(r"C:\t{i}")))
            .collect();

        for requested in 1..=8 {
            let workers = effective_workers(targets.len(), requested);
            let chunks = split_targets(targets.clone(), workers);

            assert!(
                chunks.iter().all(|chunk| !chunk.is_empty()),
                "empty chunk with {workers} workers"
            );
            assert_eq!(
                chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
                7,
                "targets lost with {workers} workers"
            );
        }
    }
}

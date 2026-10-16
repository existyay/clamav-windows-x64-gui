//! Persisted application settings.
//!
//! The configuration lives next to the executable so the app stays portable.
//! If that directory is read-only (a very common situation when someone drops
//! the binary into `Program Files`), writes transparently fall back to the
//! per-user config directory instead of failing silently.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default window size used the first time the app runs.
pub const DEFAULT_WINDOW_W: f32 = 1140.0;
/// Default window height.
pub const DEFAULT_WINDOW_H: f32 = 780.0;
/// Smallest usable window.
pub const MIN_WINDOW_W: f32 = 900.0;
/// Smallest usable window height.
pub const MIN_WINDOW_H: f32 = 580.0;

/// Remembered window geometry.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct WindowState {
    pub width: f32,
    pub height: f32,
    pub maximized: bool,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            width: DEFAULT_WINDOW_W,
            height: DEFAULT_WINDOW_H,
            maximized: false,
        }
    }
}

/// Everything the GUI persists between runs.
///
/// `#[serde(default)]` is applied to the *struct*, not individual fields. That
/// makes every missing key fall back to [`AppConfig::default`] — which resolves
/// real, exe-relative paths. Marking individual fields with `#[serde(default)]`
/// (as an earlier version did for the YAMAGoya paths) makes a missing key
/// produce an *empty* `PathBuf` that then resolves relative to the current
/// working directory, quietly pointing the app at the wrong place.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AppConfig {
    /// Directory holding `clamscan.exe`, `freshclam.exe`, ….
    pub clamav_dir: PathBuf,
    /// Signature database.
    pub database_dir: PathBuf,
    /// Quarantine vault.
    pub quarantine_dir: PathBuf,
    /// Logs and scan history.
    pub log_dir: PathBuf,

    pub max_file_size_mb: u64,
    /// Number of concurrent `clamscan` processes (1 = sequential).
    pub max_scan_threads: u32,

    pub scan_archives: bool,
    pub scan_mail: bool,
    pub scan_ole2: bool,
    pub scan_pdf: bool,
    pub scan_html: bool,
    pub heuristic_alerts: bool,
    pub recursive_scan: bool,

    /// Regular expressions matched against full paths by both `--exclude-dir`
    /// and `--exclude`.
    pub exclude_patterns: Vec<String>,

    pub auto_update: bool,
    /// Move detected files to the quarantine vault as soon as a scan finishes.
    pub auto_quarantine: bool,
    /// Leave the YAMAGoya ETW session running after the GUI exits.
    pub persist_realtime_on_exit: bool,
    /// Hide to the tray instead of exiting when the window is closed. Ignored
    /// when no tray icon could be created.
    pub close_to_tray: bool,
    /// Paper (light) vs ink-board (dark).
    pub dark_mode: bool,

    pub yamagoya_dir: PathBuf,
    pub yamagoya_rules_dir: PathBuf,
    /// `sigma`, `yaml` or `yara`.
    pub yamagoya_rule_type: String,
    pub yamagoya_monitor_all: bool,
    pub yamagoya_kill_process: bool,

    pub window: WindowState,
}

fn portable_base_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Directory this executable lives in.
pub fn base_dir() -> PathBuf {
    portable_base_dir()
}

/// Render a path for a message without leaking the user's private layout.
///
/// Diagnostics used to print the whole path, for example
/// `未找到 freshclam: C:\Users\alice\Documents\clamav-gui\clamav\freshclam.exe`.
/// That puts the account name and the folder structure into the window, every
/// screenshot and every bug report, while telling the user nothing useful: what
/// matters is *which component* is missing, not where the program was unzipped.
///
/// Paths inside the application directory are shown relative to it
/// (`clamav\freshclam.exe`). Anything else keeps only its last two components
/// with the rest replaced by an ellipsis (`…\Desktop\scan.log`).
pub fn display_path(path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(base_dir()) {
        let text = relative.to_string_lossy().replace('/', "\\");
        if !text.is_empty() {
            return text;
        }
    }

    let mut tail: Vec<String> = path
        .components()
        .rev()
        .take(2)
        .map(|part| part.as_os_str().to_string_lossy().to_string())
        .collect();
    tail.reverse();

    if tail.is_empty() {
        return path.to_string_lossy().to_string();
    }
    format!("…\\{}", tail.join("\\"))
}

/// Exclusions that are safe by default: the Windows component store (protected
/// and enormous) plus files that cannot usefully be scanned.
///
/// These are regular expressions matched against the full path, which is what
/// `clamscan` does (see `match_regex` in `common/misc.c`). Note that the values
/// are PCRE — the previous defaults such as `target\debug` were silently
/// wrong, because `\d` is a *digit class*, not a path separator.
fn default_exclude_patterns() -> Vec<String> {
    vec![
        r"[\\/]WinSxS[\\/]?$".to_string(),
        r"[\\/]DriverStore[\\/]?$".to_string(),
        r"pagefile\.sys$".to_string(),
        r"hiberfil\.sys$".to_string(),
        r"swapfile\.sys$".to_string(),
    ]
}

/// Patterns shipped by earlier versions that can never match a real path.
///
/// In a regular expression `\d` is a *digit* and `\r` a carriage return, so
/// `target\debug` never matched `…\target\debug\…`. Anyone who upgraded kept the
/// dead patterns in their config file, so repair them in place instead of
/// throwing away a hand-edited list.
const LEGACY_EXCLUSION_FIXES: [(&str, &str); 4] = [
    (r"target\debug", r"[\\/]target[\\/]debug[\\/]?$"),
    (r"target\release", r"[\\/]target[\\/]release[\\/]?$"),
    (r"C:\Windows\WinSxS", r"[\\/]WinSxS[\\/]?$"),
    (
        r"C:\Windows\System32\DriverStore",
        r"[\\/]DriverStore[\\/]?$",
    ),
];

/// Extra exclusions offered as a one-click preset for developer machines.
///
/// Deliberately *not* on by default: skipping a user directory is a decision
/// that should be made explicitly.
pub fn developer_exclusions() -> Vec<String> {
    vec![
        r"[\\/]node_modules[\\/]?$".to_string(),
        r"[\\/]\.git[\\/]?$".to_string(),
        r"[\\/]target[\\/](debug|release)[\\/]?$".to_string(),
        r"[\\/]\.venv[\\/]?$".to_string(),
        r"[\\/]__pycache__[\\/]?$".to_string(),
    ]
}

impl Default for AppConfig {
    fn default() -> Self {
        let base = portable_base_dir();
        Self {
            clamav_dir: base.join("clamav"),
            database_dir: base.join("clamav").join("database"),
            quarantine_dir: base.join("quarantine"),
            log_dir: base.join("logs"),

            max_file_size_mb: 100,
            // Sequential by default: each extra process loads its own copy of
            // the signature database.
            max_scan_threads: 1,

            scan_archives: true,
            scan_mail: true,
            scan_ole2: true,
            scan_pdf: true,
            scan_html: true,
            heuristic_alerts: true,
            recursive_scan: true,

            exclude_patterns: default_exclude_patterns(),

            auto_update: true,
            auto_quarantine: true,
            persist_realtime_on_exit: false,
            close_to_tray: true,
            dark_mode: false,

            yamagoya_dir: base.join("yamagoya"),
            yamagoya_rules_dir: base.join("yamagoya").join("rules"),
            yamagoya_rule_type: "sigma".to_string(),
            yamagoya_monitor_all: true,
            yamagoya_kill_process: false,

            window: WindowState::default(),
        }
    }
}

impl AppConfig {
    /// Portable config location, next to the executable.
    pub fn primary_config_path() -> PathBuf {
        portable_base_dir().join("clamav-gui-config.json")
    }

    /// Per-user fallback used when the portable location is not writable.
    pub fn fallback_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("ClamAV GUI").join("clamav-gui-config.json"))
    }

    /// Load settings, trying the portable location first and then the per-user
    /// one. A corrupt file falls through to the next candidate rather than
    /// silently discarding the user's configuration.
    pub fn load() -> Self {
        let mut candidates = vec![Self::primary_config_path()];
        if let Some(fallback) = Self::fallback_config_path() {
            candidates.push(fallback);
        }

        for path in candidates {
            let Ok(data) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(config) = serde_json::from_str::<Self>(&data) {
                return config.normalized();
            }
        }

        Self::default()
    }

    /// Persist settings atomically, returning a message on failure.
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;

        let primary = Self::primary_config_path();
        if write_atomic(&primary, &json).is_ok() {
            return Ok(());
        }

        if let Some(fallback) = Self::fallback_config_path() {
            if let Some(dir) = fallback.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if write_atomic(&fallback, &json).is_ok() {
                return Ok(());
            }
        }

        Err(format!("无法写入配置文件: {}", display_path(&primary)))
    }

    /// Repair values that a hand-edited or older config file could leave in a
    /// nonsensical state.
    pub fn normalized(mut self) -> Self {
        let base = portable_base_dir();

        if self.clamav_dir.as_os_str().is_empty() {
            self.clamav_dir = base.join("clamav");
        }
        if self.database_dir.as_os_str().is_empty() {
            self.database_dir = self.clamav_dir.join("database");
        }
        if self.quarantine_dir.as_os_str().is_empty() {
            self.quarantine_dir = base.join("quarantine");
        }
        if self.log_dir.as_os_str().is_empty() {
            self.log_dir = base.join("logs");
        }
        if self.yamagoya_dir.as_os_str().is_empty() {
            self.yamagoya_dir = base.join("yamagoya");
        }
        if self.yamagoya_rules_dir.as_os_str().is_empty() {
            self.yamagoya_rules_dir = self.yamagoya_dir.join("rules");
        }

        self.max_file_size_mb = self.max_file_size_mb.clamp(1, 4096);
        self.max_scan_threads = self.max_scan_threads.clamp(1, 8);

        if !matches!(self.yamagoya_rule_type.as_str(), "sigma" | "yaml" | "yara") {
            self.yamagoya_rule_type = "sigma".to_string();
        }

        self.window.width = self
            .window
            .width
            .clamp(MIN_WINDOW_W, 16_384.0);
        self.window.height = self
            .window
            .height
            .clamp(MIN_WINDOW_H, 16_384.0);

        // Repair exclusion patterns that earlier versions shipped broken.
        for pattern in &mut self.exclude_patterns {
            if let Some((_, replacement)) = LEGACY_EXCLUSION_FIXES
                .iter()
                .find(|(legacy, _)| pattern == legacy)
            {
                *pattern = (*replacement).to_string();
            }
        }
        self.exclude_patterns.dedup();

        self
    }

    /// Create the runtime directory tree. Unpacking the embedded binaries is
    /// handled by [`crate::bootstrap`] on a worker thread.
    pub fn ensure_dirs(&self) {
        for dir in [
            &self.clamav_dir,
            &self.database_dir,
            &self.quarantine_dir,
            &self.log_dir,
            &self.yamagoya_dir,
            &self.yamagoya_rules_dir,
        ] {
            let _ = std::fs::create_dir_all(dir);
        }
    }

    pub fn clamscan_path(&self) -> PathBuf {
        self.clamav_dir.join("clamscan.exe")
    }

    pub fn freshclam_path(&self) -> PathBuf {
        self.clamav_dir.join("freshclam.exe")
    }

    pub fn freshclam_conf_path(&self) -> PathBuf {
        self.clamav_dir.join("freshclam.conf")
    }

    pub fn certs_dir(&self) -> PathBuf {
        self.clamav_dir.join("certs")
    }

    pub fn yamagoya_path(&self) -> PathBuf {
        self.yamagoya_dir.join("YAMAGoya.exe")
    }

    pub fn scan_history_path(&self) -> PathBuf {
        self.log_dir.join("scan-history.json")
    }

    /// Fast preset: smallest surface, quickest result.
    pub fn apply_fast_scan_preset(&mut self) {
        self.max_file_size_mb = 25;
        self.scan_archives = false;
        self.scan_mail = false;
        self.scan_ole2 = false;
        self.scan_pdf = false;
        self.scan_html = false;
        self.heuristic_alerts = false;
    }

    /// Balanced preset: the sensible default.
    pub fn apply_balanced_scan_preset(&mut self) {
        self.max_file_size_mb = 50;
        self.scan_archives = true;
        self.scan_mail = false;
        self.scan_ole2 = true;
        self.scan_pdf = true;
        self.scan_html = true;
        self.heuristic_alerts = true;
    }

    /// Thorough preset: everything on, largest files.
    pub fn apply_thorough_scan_preset(&mut self) {
        self.max_file_size_mb = 500;
        self.scan_archives = true;
        self.scan_mail = true;
        self.scan_ole2 = true;
        self.scan_pdf = true;
        self.scan_html = true;
        self.heuristic_alerts = true;
    }
}

/// Write a file by way of a temporary sibling plus a rename.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "config".to_string());
    let tmp = path.with_file_name(format!(".{}.tmp", file_name));

    std::fs::write(&tmp, contents)?;

    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_window_size_is_raised_to_the_minimum() {
        let mut config = AppConfig::default();
        config.window.width = 10.0;
        config.window.height = 100_000.0;

        let fixed = config.normalized();

        assert!(fixed.window.width >= MIN_WINDOW_W);
        assert!(fixed.window.height <= 16_384.0);
    }

    #[test]
    fn empty_paths_fall_back_to_the_defaults() {
        // A config written by an older version deserialised `PathBuf` fields as
        // empty strings, which produced a GUI that could not find its engine.
        let mut config = AppConfig::default();
        config.clamav_dir = PathBuf::new();
        config.log_dir = PathBuf::new();
        config.quarantine_dir = PathBuf::new();

        let fixed = config.normalized();

        assert!(!fixed.clamav_dir.as_os_str().is_empty());
        assert!(!fixed.log_dir.as_os_str().is_empty());
        assert!(!fixed.quarantine_dir.as_os_str().is_empty());
    }

    #[test]
    fn legacy_broken_exclusions_are_repaired_in_place() {
        let mut config = AppConfig::default();
        config.exclude_patterns = vec![
            r"target\debug".to_string(),
            r"target\release".to_string(),
            r"C:\Windows\WinSxS".to_string(),
            r"my own pattern".to_string(),
        ];

        let fixed = config.normalized();

        // The dead regexes are gone...
        assert!(!fixed.exclude_patterns.iter().any(|p| p == r"target\debug"));
        assert!(!fixed.exclude_patterns.iter().any(|p| p == r"target\release"));
        // ...and replaced with anchored forms.
        assert!(fixed
            .exclude_patterns
            .contains(&r"[\\/]target[\\/]debug[\\/]?$".to_string()));
        assert!(fixed
            .exclude_patterns
            .contains(&r"[\\/]target[\\/]release[\\/]?$".to_string()));
        assert!(fixed
            .exclude_patterns
            .contains(&r"[\\/]WinSxS[\\/]?$".to_string()));
        // A hand-written entry must survive untouched.
        assert!(fixed
            .exclude_patterns
            .contains(&"my own pattern".to_string()));
    }

    #[test]
    fn a_custom_exclusion_list_is_left_alone() {
        let expected = vec![r"[\\/]node_modules[\\/]?$".to_string()];
        let mut config = AppConfig::default();
        config.exclude_patterns = expected.clone();

        let fixed = config.normalized();

        assert_eq!(fixed.exclude_patterns, expected);
    }

    #[test]
    fn default_exclusions_are_anchored_and_properly_escaped() {
        let defaults = default_exclude_patterns();
        assert!(!defaults.is_empty());

        for pattern in &defaults {
            assert!(pattern.ends_with('$'), "{pattern} should be anchored");
            // `\d` is a digit and `\r` a carriage return: neither is ever a
            // literal path separator, which is how the old defaults broke.
            assert!(!pattern.contains(r"\d"), "{pattern} contains a bare \\d");
            assert!(!pattern.contains(r"\r"), "{pattern} contains a bare \\r");
        }

        // The dot in a file name has to be escaped or it matches any character.
        assert!(defaults.contains(&r"pagefile\.sys$".to_string()));
        assert!(defaults.contains(&r"hiberfil\.sys$".to_string()));
    }

    #[test]
    fn diagnostic_paths_do_not_leak_the_users_layout() {
        let base = base_dir();

        // Inside the application directory the path is shown relative to it, so
        // neither the account name nor the unzip location reaches the window.
        let inside = base.join("clamav").join("freshclam.exe");
        let shown = display_path(&inside);
        assert_eq!(shown, r"clamav\freshclam.exe");
        assert!(!shown.contains(&base.to_string_lossy().to_string()));
        assert!(!shown.contains("Users"));
        assert!(!shown.contains(':'));

        // Anything else keeps only its last two components.
        let outside = PathBuf::from("alice")
            .join("Documents")
            .join("scans")
            .join("report.log");
        let shown = display_path(&outside);
        assert_eq!(shown, r"…\scans\report.log");
        assert!(!shown.contains("alice"));

        // The application directory itself has nothing relative to show, but it
        // still must not come back empty.
        assert!(!display_path(&base).is_empty());
    }

    #[test]
    fn developer_exclusions_target_build_output_only() {
        let dev = developer_exclusions();
        assert!(dev.iter().any(|p| p.contains("node_modules")));
        assert!(dev.iter().any(|p| p.contains(r"target[\\/](debug|release)")));
        for pattern in &dev {
            assert!(pattern.ends_with('$'), "{pattern} should be anchored");
        }
    }

    #[test]
    fn scan_presets_are_ordered_from_fast_to_thorough() {
        let mut fast = AppConfig::default();
        fast.apply_fast_scan_preset();
        let mut thorough = AppConfig::default();
        thorough.apply_thorough_scan_preset();

        assert!(fast.max_file_size_mb <= thorough.max_file_size_mb);
        assert!(!fast.scan_archives, "a quick scan should not unpack archives");
        assert!(thorough.scan_archives);
    }
}

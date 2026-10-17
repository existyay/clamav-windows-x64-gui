//! The application shell and its seven panels.
//!
//! Layout
//! ------
//! A fixed navigation rail on the left, a scrolling page on the right. The page
//! is centred and capped at [`widgets::MAX_CONTENT_W`] so lines of text stay
//! readable on a wide monitor instead of stretching across the whole screen.
//!
//! Interaction rules that this file follows, and why
//! -------------------------------------------------
//! * No `&mut self` work happens inside a rendering closure. List rows publish
//!   their intent into a local enum and the intent is applied afterwards. This
//!   is what keeps "click a row while that same list is being drawn" from
//!   becoming a borrow-checker fight or, worse, a re-entrant mutation.
//! * Expensive reads are cached and invalidated explicitly. The quarantine
//!   directory used to be re-scanned and JSON-parsed for every entry on *every
//!   frame*, i.e. sixty times a second.
//! * Repaints are requested on a schedule that matches what is on screen, not
//!   unconditionally at 60 Hz.

use crate::bootstrap::Bootstrap;
use crate::config::{self, AppConfig};
use crate::icons::{self, Icon};
use crate::realtime::RealtimeProtection;
use crate::scanner::{self, QuarantineEntry, ScanEngine, ScanState};
use crate::theme::{self, Palette, Tone};
use crate::tray::{SystemTray, TrayAction};
use crate::updater::DatabaseUpdater;
use crate::widgets;
use eframe::egui::{self, Align, Color32, Layout, RichText, ScrollArea, Sense, Vec2};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const APP_NAME: &str = "ClamAV 安全中心";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Scan,
    Realtime,
    Update,
    Quarantine,
    Logs,
    Settings,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Dashboard,
        Tab::Scan,
        Tab::Realtime,
        Tab::Update,
        Tab::Quarantine,
        Tab::Logs,
        Tab::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "总览",
            Tab::Scan => "病毒扫描",
            Tab::Realtime => "实时保护",
            Tab::Update => "病毒库",
            Tab::Quarantine => "隔离区",
            Tab::Logs => "日志",
            Tab::Settings => "设置",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Tab::Dashboard => Icon::Layout,
            Tab::Scan => Icon::Magnifier,
            Tab::Realtime => Icon::Pulse,
            Tab::Update => Icon::Download,
            Tab::Quarantine => Icon::Lock,
            Tab::Logs => Icon::FileDoc,
            Tab::Settings => Icon::Sliders,
        }
    }
}

// ---------------------------------------------------------------------------
// Transient UI state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToastKind {
    Info,
    Success,
    Warning,
    Danger,
}

impl ToastKind {
    fn tone(self) -> Tone {
        match self {
            ToastKind::Info => Tone::Info,
            ToastKind::Success => Tone::Success,
            ToastKind::Warning => Tone::Warning,
            ToastKind::Danger => Tone::Danger,
        }
    }

    fn icon(self) -> Icon {
        match self {
            ToastKind::Info => Icon::Info,
            ToastKind::Success => Icon::Check,
            ToastKind::Warning => Icon::Alert,
            ToastKind::Danger => Icon::ShieldAlert,
        }
    }
}

struct Toast {
    kind: ToastKind,
    text: String,
    expires_at: f64,
}

/// A destructive action awaiting confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    DeleteAllQuarantine,
    /// Index into `quarantine`; the entry itself is what gets deleted.
    DeleteQuarantine(usize),
    ClearScanHistory,
    ResetSettings,
}

/// Intent produced by a list row, applied after the list has been drawn.
enum ScanIntent {
    QuarantineOne(usize),
    QuarantineAll,
    Stop,
    Start(Vec<PathBuf>),
    RemoveTarget(usize),
    ClearTargets,
}

enum QuarantineIntent {
    Restore(usize),
    Delete(usize),
    DeleteAll,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogSource {
    Scan,
    Realtime,
    Update,
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

pub struct ClamAvApp {
    config: AppConfig,
    tab: Tab,

    bootstrap: Bootstrap,
    scan_engine: ScanEngine,
    realtime: RealtimeProtection,
    updater: DatabaseUpdater,

    grain: Option<egui::TextureHandle>,
    /// The appearance currently applied to the context, so the (fairly
    /// expensive) style and grain rebuild only happens on an actual change.
    applied_dark: Option<bool>,
    tray: Option<SystemTray>,
    tray_tooltip: String,

    // Cached quarantine listing, invalidated on every mutation.
    quarantine: Vec<QuarantineEntry>,
    quarantine_loaded: bool,

    // Scan targets chosen by the user (files, folders, dropped items).
    target_paths: Vec<PathBuf>,

    // Restored from the previous session.
    scan_target_label: String,

    toast: Option<Toast>,
    confirm: Option<Confirm>,

    log_source: LogSource,
    quarantine_filter: String,
    exclude_draft: String,
    show_scan_log: bool,

    // Deferred config persistence.
    config_dirty: bool,
    config_dirty_since: Option<Instant>,

    // Whether the automatic quarantine pass has already run for this scan.
    auto_quarantine_done: bool,

    // Window geometry, captured each frame and written on exit.
    window_size: Option<(f32, f32)>,
    window_maximized: bool,

    /// Set when the user really wants to exit, so the close handler stops
    /// diverting to the tray.
    quitting: bool,
    /// Set while the window is retreated to the tray (minimised, not drawn).
    hidden: bool,
}

impl ClamAvApp {
    pub fn new(cc: &eframe::CreationContext<'_>, config: AppConfig) -> Self {
        theme::apply(&cc.egui_ctx, config.dark_mode);

        config.ensure_dirs();

        let mut scan_engine = ScanEngine::default();
        let history_path = config.scan_history_path();
        let scan_target_label = scan_engine
            .load_history(&history_path)
            .unwrap_or_else(|| "尚未执行扫描".to_string());
        // History is restored for display only; it must never trigger the
        // automatic quarantine pass again.
        scan_engine.restored_from_history = true;

        let mut realtime = RealtimeProtection::default();
        realtime.try_reconnect(&config);

        let bootstrap = Bootstrap::start(&config);

        let tray = SystemTray::new(cc.egui_ctx.clone());
        let tray_tooltip = format!("{} · 正在启动", APP_NAME);

        let window_size = Some((config.window.width, config.window.height));
        let window_maximized = config.window.maximized;

        Self {
            config,
            tab: Tab::Dashboard,
            bootstrap,
            scan_engine,
            realtime,
            updater: DatabaseUpdater::default(),
            grain: None,
            applied_dark: None,
            tray,
            tray_tooltip,
            quarantine: Vec::new(),
            quarantine_loaded: false,
            target_paths: Vec::new(),
            scan_target_label,
            toast: None,
            confirm: None,
            log_source: LogSource::Scan,
            quarantine_filter: String::new(),
            exclude_draft: String::new(),
            show_scan_log: false,
            config_dirty: false,
            config_dirty_since: None,
            auto_quarantine_done: false,
            window_size,
            window_maximized,
            quitting: false,
            hidden: false,
        }
    }

    // -- helpers ----------------------------------------------------------

    fn toast(&mut self, kind: ToastKind, text: impl Into<String>) {
        self.toast = Some(Toast {
            kind,
            text: text.into(),
            expires_at: 0.0,
        });
        // The deadline is filled in on the next frame, where the context clock
        // is available.
    }

    fn mark_config_dirty(&mut self) {
        self.config_dirty = true;
        self.config_dirty_since = Some(Instant::now());
    }

    /// Re-read the quarantine directory. Only ever called on invalidation.
    fn reload_quarantine(&mut self) {
        self.quarantine = scanner::list_quarantine_entries(&self.config.quarantine_dir);
        self.quarantine_loaded = true;
    }

    fn invalidate_quarantine(&mut self) {
        self.quarantine_loaded = false;
    }

    fn ensure_quarantine(&mut self) {
        if !self.quarantine_loaded {
            self.reload_quarantine();
        }
    }

    fn database_ready(&self) -> bool {
        !self.updater.db_files.is_empty()
    }

    /// How long until the next frame is needed.
    fn repaint_delay(&self) -> Duration {
        if !self.bootstrap.finished || self.scan_engine.is_scanning() || self.updater.is_updating()
        {
            // Progress bars and scrolling logs.
            Duration::from_millis(90)
        } else if self.realtime.is_running() {
            // Only a status light and a tail-following log.
            Duration::from_millis(650)
        } else if self.toast.is_some() {
            Duration::from_millis(250)
        } else {
            // Idle: still wake occasionally so dates and watchful states stay
            // honest, but at a cost nobody can measure.
            Duration::from_secs(2)
        }
    }

    fn apply_scan_intent(&mut self, intent: ScanIntent) {
        match intent {
            ScanIntent::Stop => {
                self.scan_engine.cancel_scan();
                self.persist_history();
                self.toast(ToastKind::Warning, "扫描已停止");
            }
            ScanIntent::Start(targets) => {
                if targets.is_empty() {
                    self.toast(ToastKind::Warning, "请先选择要扫描的目标");
                } else if !self.database_ready() {
                    self.toast(
                        ToastKind::Warning,
                        "病毒库尚未就绪，请先到「病毒库」页面执行一次更新",
                    );
                } else {
                    self.auto_quarantine_done = false;
                    self.scan_engine.start_scan_targets(targets, &self.config);
                    self.tab = Tab::Scan;
                    self.show_scan_log = false;
                    self.persist_history();
                }
            }
            ScanIntent::QuarantineOne(index) => {
                let Some(threat) = self.scan_engine.threats.get(index).cloned() else {
                    return;
                };
                match self
                    .scan_engine
                    .quarantine_threat(&threat, &self.config.quarantine_dir)
                {
                    Ok(dest) => {
                        let name = dest
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        self.scan_engine.threats.remove(index);
                        self.invalidate_quarantine();
                        self.persist_history();
                        self.toast(ToastKind::Success, format!("已隔离: {}", name));
                    }
                    Err(e) => {
                        self.toast(ToastKind::Danger, format!("隔离失败: {}", e));
                    }
                }
            }
            ScanIntent::QuarantineAll => {
                let threats = std::mem::take(&mut self.scan_engine.threats);
                let mut moved = 0usize;
                let mut failed = 0usize;
                let mut remaining = Vec::new();

                for threat in threats {
                    match self
                        .scan_engine
                        .quarantine_threat(&threat, &self.config.quarantine_dir)
                    {
                        Ok(_) => moved += 1,
                        Err(_) => {
                            failed += 1;
                            remaining.push(threat);
                        }
                    }
                }

                self.scan_engine.threats = remaining;
                self.invalidate_quarantine();
                self.persist_history();

                if failed == 0 {
                    self.toast(ToastKind::Success, format!("已隔离 {} 个文件", moved));
                } else {
                    self.toast(
                        ToastKind::Warning,
                        format!("已隔离 {} 个文件，{} 个失败", moved, failed),
                    );
                }
            }
            ScanIntent::RemoveTarget(index) => {
                if index < self.target_paths.len() {
                    self.target_paths.remove(index);
                }
            }
            ScanIntent::ClearTargets => self.target_paths.clear(),
        }
    }

    fn apply_quarantine_intent(&mut self, intent: QuarantineIntent) {
        match intent {
            QuarantineIntent::Restore(index) => {
                let Some(entry) = self.quarantine.get(index).cloned() else {
                    return;
                };
                match scanner::restore_quarantined(&entry) {
                    Ok(()) => {
                        self.invalidate_quarantine();
                        self.toast(ToastKind::Success, "文件已恢复到原始位置");
                    }
                    Err(e) => self.toast(ToastKind::Danger, e),
                }
            }
            QuarantineIntent::Delete(index) => {
                // Permanent, so it goes through the confirmation modal rather
                // than deleting on a single click.
                if self.quarantine.get(index).is_some() {
                    self.confirm = Some(Confirm::DeleteQuarantine(index));
                }
            }
            QuarantineIntent::DeleteAll => {
                let entries = self.quarantine.clone();
                let mut removed = 0usize;
                for entry in &entries {
                    if scanner::delete_quarantined(entry).is_ok() {
                        removed += 1;
                    }
                }
                self.invalidate_quarantine();
                self.toast(ToastKind::Success, format!("已删除 {} 个项目", removed));
            }
        }
    }

    /// Delete one quarantined file for real.
    ///
    /// Only reached from the confirmation modal: the deletion is permanent, so a
    /// single click on a list row must not be enough.
    fn delete_quarantine_entry(&mut self, index: usize) {
        let Some(entry) = self.quarantine.get(index).cloned() else {
            return;
        };
        match scanner::delete_quarantined(&entry) {
            Ok(()) => {
                self.invalidate_quarantine();
                self.toast(ToastKind::Success, "已从隔离区删除");
            }
            Err(e) => self.toast(ToastKind::Danger, e),
        }
    }

    fn persist_history(&self) {
        self.scan_engine
            .save_history(&self.config.scan_history_path(), &self.scan_target_label);
    }

    fn save_config(&mut self) {
        match self.config.save() {
            Ok(()) => {
                self.config_dirty = false;
                self.config_dirty_since = None;
            }
            Err(e) => {
                self.config_dirty = false;
                self.config_dirty_since = None;
                self.toast(ToastKind::Danger, e);
            }
        }
    }

    fn add_targets(&mut self, paths: Vec<PathBuf>) {
        for path in paths {
            if !self.target_paths.contains(&path) {
                self.target_paths.push(path);
            }
        }
    }

    fn pick_files(&mut self) {
        if let Some(files) = rfd::FileDialog::new()
            .set_title("选择要扫描的文件")
            .pick_files()
        {
            self.add_targets(files);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("选择要扫描的文件夹")
            .pick_folder()
        {
            self.add_targets(vec![folder]);
        }
    }

    fn toggle_theme(&mut self) {
        self.config.dark_mode = !self.config.dark_mode;
        self.mark_config_dirty();
        self.grain = None; // Regenerate with the other tint.
    }

    // -- chrome -----------------------------------------------------------

    fn handle_tray(&mut self, ctx: &egui::Context) {
        let Some(action) = self.tray.as_ref().and_then(|tray| tray.poll_event()) else {
            return;
        };

        match action {
            TrayAction::ShowWindow => self.restore_from_tray(ctx),
            TrayAction::StopRealtime => {
                if self.realtime.is_running() {
                    self.realtime.stop(&self.config);
                    self.toast(ToastKind::Info, "已请求停止实时保护");
                } else {
                    self.toast(ToastKind::Info, "实时保护当前未运行");
                }
            }
            TrayAction::ExitApp => {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn handle_close_request(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }

        // Diverting the close is only acceptable when a tray icon actually
        // exists; otherwise the window would vanish with no way to bring it
        // back short of Task Manager.
        let can_hide = self.tray.is_some() && self.config.close_to_tray && !self.quitting;

        if can_hide {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.retreat_to_tray(ctx);
        }
    }

    /// Retreat to the tray after a close request.
    ///
    /// The window is **minimised**, never hidden. `ViewportCommand::Visible(false)`
    /// looks tidier — no taskbar button, no Alt+Tab entry — but winit then spins
    /// on the invisible window: measured on this build, `SW_HIDE` burned 9.66 s of
    /// CPU in 10 s (97 % of a core) while `SW_MINIMIZE` used 0.000 s over the same
    /// stretch, and the hidden window stopped running frames altogether (< 20
    /// `update()` calls in 13 s), so the tray menu could not have been polled at
    /// all. A minimised window stays cheap *and* responsive, and the taskbar
    /// button it leaves behind is a second way back should the shell ever swallow
    /// the tray icon.
    fn retreat_to_tray(&mut self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        self.hidden = true;
    }

    /// Undo [`Self::retreat_to_tray`], e.g. from the tray menu.
    fn restore_from_tray(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });

        if dropped.is_empty() {
            return;
        }

        let count = dropped.len();
        self.add_targets(dropped);
        self.tab = Tab::Scan;
        self.toast(ToastKind::Info, format!("已添加 {} 个目标", count));
    }

    fn handle_bootstrap(&mut self) {
        self.bootstrap.poll();

        if self.bootstrap.finished
            && self.updater.db_files.is_empty()
            && self.bootstrap.failed.is_none()
        {
            self.updater.apply_env(&self.bootstrap.info);
        }
    }

    fn handle_auto_quarantine(&mut self) {
        if self.auto_quarantine_done
            || !self.config.auto_quarantine
            || self.scan_engine.is_scanning()
            || self.scan_engine.restored_from_history
            || self.scan_engine.was_cancelled
            || self.scan_engine.threats.is_empty()
            || self.scan_engine.state != ScanState::Finished
        {
            return;
        }

        self.auto_quarantine_done = true;
        self.apply_scan_intent(ScanIntent::QuarantineAll);
    }

    fn update_tray_tooltip(&mut self) {
        let state = if self.realtime.is_running() {
            "实时保护运行中"
        } else if self.scan_engine.is_scanning() {
            "正在扫描"
        } else {
            "实时保护未开启"
        };
        let tooltip = format!("{} · {}", APP_NAME, state);

        if tooltip != self.tray_tooltip {
            self.tray_tooltip = tooltip.clone();
            if let Some(tray) = self.tray.as_mut() {
                tray.set_tooltip(&tooltip);
            }
        }
    }

    fn maybe_save_config(&mut self) {
        let Some(since) = self.config_dirty_since else {
            return;
        };
        if !self.config_dirty || since.elapsed() < Duration::from_millis(900) {
            return;
        }
        self.save_config();
        self.toast(ToastKind::Success, "设置已保存");
    }

    // -- panels -----------------------------------------------------------

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let pal = Palette::current(ui);

        // Brand.
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
            icons::draw(ui.painter(), rect, Icon::ShieldCheck, pal.accent, 30.0);
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.add_space(1.0);
                ui.label(theme::body(APP_NAME).color(pal.ink).strong());
                ui.label(theme::small("Windows 版").color(pal.ink_faint));
            });
        });

        ui.add_space(14.0);

        let threat_count = self.scan_engine.threats.len();
        let quarantine_count = self.quarantine.len();

        let mut selected_tab = self.tab;
        for tab in Tab::ALL {
            let badge = match tab {
                Tab::Dashboard if threat_count > 0 => Some(threat_count.to_string()),
                Tab::Quarantine if quarantine_count > 0 => Some(quarantine_count.to_string()),
                _ => None,
            };

            if widgets::nav_item(ui, tab.icon(), tab.label(), self.tab == tab, badge).clicked() {
                selected_tab = tab;
            }
        }
        self.tab = selected_tab;

        // Status footer.
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(12.0);

            let mode_label = if self.config.dark_mode {
                "浅色纸面"
            } else {
                "深色墨板"
            };
            if widgets::quiet_enabled(
                ui,
                Some(if self.config.dark_mode {
                    Icon::Layout
                } else {
                    Icon::Chip
                }),
                mode_label,
                true,
            )
            .clicked()
            {
                self.toggle_theme();
            }

            ui.add_space(8.0);

            let (tone, title, detail) = if self.realtime.is_running() {
                (
                    Tone::Success,
                    "实时保护已开启",
                    self.realtime
                        .daemon_pid
                        .map(|pid| format!("进程 {}", pid))
                        .unwrap_or_else(|| "监控中".to_string()),
                )
            } else if self.scan_engine.is_scanning() {
                (Tone::Accent, "正在扫描", "实时保护已暂停".to_string())
            } else {
                (Tone::Neutral, "实时保护未开启", "点击开启".to_string())
            };

            widgets::card_tuned(
                ui,
                Some(pal.surface(tone)),
                Some(pal.tone_ink(tone).gamma_multiply(0.3)),
                Some(10.0),
                |ui| {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                        icons::draw(
                            ui.painter(),
                            rect,
                            if self.realtime.is_running() {
                                Icon::ShieldCheck
                            } else {
                                Icon::Shield
                            },
                            pal.tone_ink(tone),
                            18.0,
                        );
                        ui.add_space(2.0);
                        ui.vertical(|ui| {
                            ui.label(theme::small(title).color(pal.ink).strong());
                            ui.label(theme::small(detail).color(pal.ink_faint));
                        });
                    });
                },
            );

            ui.add_space(8.0);

            let db_text = match (&self.updater.db_version, self.updater.db_sigs) {
                (Some(version), Some(sigs)) => {
                    format!("病毒库 {} · {:.1} 万条", version, sigs as f64 / 10_000.0)
                }
                (Some(version), None) => format!("病毒库版本 {}", version),
                _ => "病毒库信息不可用".to_string(),
            };

            ui.horizontal(|ui| {
                icons::paint(ui, Icon::Database, 14.0, pal.ink_faint);
                ui.label(theme::small(db_text).color(pal.ink_faint));
            });

            if let Some(modified) = &self.updater.db_modified {
                ui.label(theme::small(format!("更新于 {}", modified)).color(pal.ink_faint));
            }
        });
    }

    fn dashboard_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);
        let scanning = self.scan_engine.is_scanning();
        let threat_count = self.scan_engine.threats.len();
        let bootstrap_running = !self.bootstrap.finished;
        let db_ready = self.database_ready();

        widgets::page_header(
            ui,
            Icon::Layout,
            "总览",
            "系统当前的安全状态",
            |ui| {
                if widgets::outline_enabled(ui, Some(Icon::Refresh), "重新检查", !scanning)
                    .clicked()
                {
                    // Re-read the signature database in place. Restarting the
                    // whole bootstrap would blank the interface behind the
                    // first-run splash for no reason.
                    let info = crate::bootstrap::probe_database(&self.config.database_dir);
                    self.updater.apply_env(&info);
                    self.toast(ToastKind::Info, "已重新读取病毒库信息");
                }
            },
        );

        // --- Bootstrap progress -----------------------------------------
        if bootstrap_running {
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    icons::paint(ui, Icon::Chip, 16.0, pal.accent);
                    ui.label(
                        theme::body(self.bootstrap.label.clone())
                            .color(pal.ink)
                            .strong(),
                    );
                });
                ui.add_space(6.0);
                let fraction = self.bootstrap.fraction().unwrap_or(-1.0);
                widgets::progress(ui, fraction, phase(ctx), pal.accent, 6.0);
                ui.add_space(4.0);
                widgets::hint(ui, "首次启动需要释放内置的扫描引擎与病毒库，请稍候。");
            });
            ui.add_space(12.0);
        }

        if let Some(error) = self.bootstrap.failed.clone() {
            widgets::tone_card(ui, Tone::Danger, |ui| {
                ui.horizontal(|ui| {
                    icons::paint(ui, Icon::Alert, 16.0, pal.danger);
                    ui.label(theme::body("初始化失败").color(pal.ink).strong());
                });
                ui.label(theme::small(error).color(pal.ink_soft));
            });
            ui.add_space(12.0);
        }

        // --- Hero status ------------------------------------------------
        let (tone, headline, detail, icon) = if !db_ready {
            (
                Tone::Warning,
                "病毒库尚未就绪".to_string(),
                "在扫描之前，请先更新一次病毒库。".to_string(),
                Icon::Database,
            )
        } else if threat_count > 0 {
            (
                Tone::Danger,
                format!("发现 {} 个威胁", threat_count),
                "受感染的文件仍在原位置，请立即隔离或删除。".to_string(),
                Icon::ShieldAlert,
            )
        } else if scanning {
            (
                Tone::Info,
                "正在扫描".to_string(),
                self.scan_engine
                    .current_file
                    .clone()
                    .pipe_if_empty("正在准备扫描目标..."),
                Icon::Magnifier,
            )
        } else if self.realtime.is_running() {
            (
                Tone::Success,
                "实时保护正在运行".to_string(),
                "文件与进程活动正在被持续监控。".to_string(),
                Icon::ShieldCheck,
            )
        } else {
            (
                Tone::Neutral,
                "实时保护未开启".to_string(),
                "开启后可在文件落地时立即拦截威胁。".to_string(),
                Icon::Shield,
            )
        };

        let mut hero_action: Option<ScanIntent> = None;

        widgets::card_tuned(
            ui,
            Some(pal.surface(tone)),
            Some(pal.tone_ink(tone).gamma_multiply(0.3)),
            Some(20.0),
            |ui| {
                ui.horizontal_top(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(52.0), Sense::hover());
                    icons::draw(ui.painter(), rect, icon, pal.tone_ink(tone), 52.0);
                    ui.add_space(6.0);

                    ui.vertical(|ui| {
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(headline.clone())
                                .font(theme::font(21.0))
                                .color(pal.ink),
                        );
                        ui.add_space(3.0);
                        ui.label(
                            RichText::new(detail.clone())
                                .font(theme::font(theme::FS_BODY))
                                .color(pal.ink_soft),
                        );
                    });

                    widgets::right_aligned(ui, |ui| {
                        if scanning {
                            if widgets::danger(ui, Some(Icon::Stop), "停止扫描").clicked() {
                                hero_action = Some(ScanIntent::Stop);
                            }
                        } else if threat_count > 0 {
                            if widgets::danger(ui, Some(Icon::Lock), "全部隔离").clicked() {
                                hero_action = Some(ScanIntent::QuarantineAll);
                            }
                            if widgets::outline(ui, Some(Icon::Magnifier), "查看详情").clicked()
                            {
                                self.tab = Tab::Scan;
                            }
                        } else if !db_ready {
                            if widgets::primary(ui, Some(Icon::Download), "更新病毒库").clicked()
                            {
                                self.tab = Tab::Update;
                            }
                        } else if self.realtime.is_running() {
                            if widgets::outline(ui, Some(Icon::Magnifier), "立即扫描").clicked()
                            {
                                self.tab = Tab::Scan;
                            }
                        } else if widgets::primary(ui, Some(Icon::Play), "开启实时保护").clicked()
                        {
                            match self.realtime.start(&self.config) {
                                Ok(()) => self.toast(ToastKind::Success, "实时保护已启动"),
                                Err(e) => self.toast(ToastKind::Danger, e),
                            }
                        }
                    });
                });
            },
        );

        if let Some(intent) = hero_action {
            self.apply_scan_intent(intent);
        }

        ui.add_space(10.0);

        // --- Stat tiles -------------------------------------------------
        let totals = self.scan_engine.totals();
        let stats = self.scan_engine.stats.clone();

        ui.columns(4, |cols| {
            widgets::stat_tile(
                &mut cols[0],
                Icon::ShieldAlert,
                &threat_count.to_string(),
                "当前威胁",
                if threat_count > 0 {
                    Tone::Danger
                } else {
                    Tone::Success
                },
            );
            widgets::stat_tile(
                &mut cols[1],
                Icon::FileDoc,
                &format_count(stats.scanned_files),
                "上次扫描文件",
                Tone::Neutral,
            );
            widgets::stat_tile(
                &mut cols[2],
                Icon::Lock,
                &self.quarantine.len().to_string(),
                "隔离区项目",
                Tone::Neutral,
            );
            widgets::stat_tile(
                &mut cols[3],
                Icon::Pulse,
                &format_count(self.realtime.monitored_events),
                "实时监控事件",
                if self.realtime.is_running() {
                    Tone::Success
                } else {
                    Tone::Neutral
                },
            );
        });

        ui.add_space(12.0);

        // --- Two columns -------------------------------------------------
        let mut quick_intent: Option<ScanIntent> = None;
        let quick = quick_scan_targets();
        let drives = logical_drives();

        ui.columns(2, |cols| {
            // Quick actions.
            widgets::card(&mut cols[0], |ui| {
                ui.label(theme::section_title("快速操作").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(10.0);

                let quick_label = format!("快速扫描（{} 个位置）", quick.len());
                if widgets::quick_action(
                    ui,
                    Icon::Magnifier,
                    &quick_label,
                    "扫描下载、桌面、文档与启动项",
                )
                .clicked()
                    && !quick.is_empty()
                {
                    quick_intent = Some(ScanIntent::Start(quick.clone()));
                }

                ui.add_space(6.0);

                if widgets::quick_action(
                    ui,
                    Icon::Chip,
                    "全盘扫描",
                    "扫描全部本地磁盘（可能需要较长时间）",
                )
                .clicked()
                    && !drives.is_empty()
                {
                    quick_intent = Some(ScanIntent::Start(drives.clone()));
                }

                ui.add_space(6.0);

                if widgets::quick_action(
                    ui,
                    Icon::Folder,
                    "自定义扫描",
                    "选择文件或文件夹后开始扫描",
                )
                .clicked()
                {
                    self.target_paths.clear();
                    self.tab = Tab::Scan;
                }
            });

            // Recent scan + database.
            widgets::card(&mut cols[1], |ui| {
                ui.label(theme::section_title("最近一次扫描").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(10.0);

                widgets::kv(
                    ui,
                    "目标",
                    &truncate_path(&self.scan_target_label, 46),
                    None,
                );
                widgets::kv(
                    ui,
                    "结果",
                    &if self.scan_engine.was_cancelled {
                        "已取消".to_string()
                    } else if threat_count > 0 {
                        format!("发现 {} 个威胁", threat_count)
                    } else if stats.scanned_files > 0 {
                        "未发现威胁".to_string()
                    } else {
                        "尚无记录".to_string()
                    },
                    Some(if threat_count > 0 {
                        pal.danger
                    } else {
                        pal.success
                    }),
                );
                widgets::kv(ui, "用时", &format_duration(stats.elapsed_secs), None);
                widgets::kv(
                    ui,
                    "已扫描数据",
                    &format_size((stats.scanned_data_mb * 1024.0 * 1024.0) as u64),
                    None,
                );

                ui.add_space(10.0);
                theme::rule(ui);
                ui.add_space(10.0);

                let db_line = match (&self.updater.db_version, self.updater.db_sigs) {
                    (Some(version), Some(sigs)) => {
                        format!("{} · {} 条签名", version, format_count(sigs))
                    }
                    (Some(version), None) => format!("版本 {}", version),
                    _ => "未知".to_string(),
                };
                widgets::kv(ui, "病毒库", &db_line, None);
                widgets::kv(
                    ui,
                    "库文件",
                    &if self.updater.db_files.is_empty() {
                        "无".to_string()
                    } else {
                        format!(
                            "{} 个 · {}",
                            self.updater.db_files.len(),
                            format_size(self.updater.db_bytes)
                        )
                    },
                    None,
                );

                let _ = totals;
            });
        });

        if let Some(intent) = quick_intent {
            self.apply_scan_intent(intent);
        }

        ui.add_space(10.0);

        // --- Threat list preview ---------------------------------------
        if threat_count > 0 {
            widgets::tone_card(ui, Tone::Danger, |ui| {
                ui.horizontal(|ui| {
                    icons::paint(ui, Icon::ShieldAlert, 16.0, pal.danger);
                    ui.label(
                        theme::body(format!("{} 个受感染文件", threat_count))
                            .color(pal.ink)
                            .strong(),
                    );
                    widgets::right_aligned(ui, |ui| {
                        if widgets::outline(ui, None, "查看全部").clicked() {
                            self.tab = Tab::Scan;
                        }
                    });
                });

                ui.add_space(8.0);

                for threat in self.scan_engine.threats.iter().take(4) {
                    ui.horizontal(|ui| {
                        icons::paint(ui, Icon::FileDoc, 14.0, pal.danger);
                        ui.label(
                            theme::mono_text(truncate_path(&threat.file_path, 58)).color(pal.ink),
                        );
                        ui.label(theme::small(&threat.threat_name).color(pal.ink_faint));
                    });
                }

                if threat_count > 4 {
                    widgets::hint(ui, &format!("另有 {} 个未显示", threat_count - 4));
                }
            });
        }

        // --- Recent activity --------------------------------------------
        ui.add_space(10.0);

        let activity: Vec<String> = self
            .scan_engine
            .log_lines
            .iter()
            .rev()
            .take(120)
            .rev()
            .cloned()
            .collect();

        // The dashboard's flexible block: the card takes whatever height the
        // blocks above left over, so the page ends at the bottom of the window
        // instead of stopping after the last card with bare paper underneath.
        let card_budget = widgets::fill_height(ui, page_height, 4.0, 90.0);
        widgets::card_tuned(ui, None, None, Some(10.0), |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section_title("最近活动").color(pal.ink));
                widgets::right_aligned(ui, |ui| {
                    if widgets::quiet(ui, None, "全部日志").clicked() {
                        self.tab = Tab::Logs;
                    }
                });
            });
            ui.add_space(6.0);
            let height = widgets::well_in_card(ui, card_budget, 20.0, 48.0);
            widgets::log_well(
                ui,
                "dashboard-activity",
                &activity,
                height,
                widgets::default_line_color,
            );
        });
    }

    fn scan_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);
        let scanning = self.scan_engine.is_scanning();
        let mut intent: Option<ScanIntent> = None;

        let subtitle = if self.scan_engine.restored_from_history {
            "以下为上次运行的记录".to_string()
        } else {
            "选择目标并开始扫描".to_string()
        };

        widgets::page_header(ui, Icon::Magnifier, "病毒扫描", &subtitle, |ui| {
            if scanning {
                if widgets::danger(ui, Some(Icon::Stop), "停止").clicked() {
                    intent = Some(ScanIntent::Stop);
                }
            } else {
                // Offer to resume when the previous run was interrupted and the
                // targets were recorded, which saves re-picking a whole tree.
                if self.scan_engine.was_cancelled
                    && !self.scan_engine.scan_target_paths.is_empty()
                    && widgets::outline(ui, Some(Icon::Refresh), "继续上次扫描").clicked()
                {
                    self.auto_quarantine_done = false;
                    self.scan_engine.continue_scan_previous(&self.config);
                    self.scan_target_label = "继续上次扫描".to_string();
                }

                if widgets::quiet_enabled(
                    ui,
                    Some(Icon::FileDoc),
                    if self.show_scan_log {
                        "隐藏日志"
                    } else {
                        "显示日志"
                    },
                    true,
                )
                .clicked()
                {
                    self.show_scan_log = !self.show_scan_log;
                }
            }
        });

        // --- Target picker ----------------------------------------------
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section_title("扫描目标").color(pal.ink));
                widgets::right_aligned(ui, |ui| {
                    if widgets::quiet_enabled(ui, None, "清空", !self.target_paths.is_empty())
                        .clicked()
                    {
                        intent = Some(ScanIntent::ClearTargets);
                    }
                    if widgets::outline_enabled(ui, Some(Icon::Folder), "添加文件夹", !scanning)
                        .clicked()
                    {
                        self.pick_folder();
                    }
                    if widgets::outline_enabled(ui, Some(Icon::FileDoc), "添加文件", !scanning)
                        .clicked()
                    {
                        self.pick_files();
                    }
                });
            });

            ui.add_space(4.0);
            theme::rule(ui);
            ui.add_space(10.0);

            // Quick presets.
            ui.horizontal_wrapped(|ui| {
                let quick = quick_scan_targets();
                if widgets::choice_chip(ui, false, Some(Icon::Magnifier), "快速扫描").clicked()
                    && !quick.is_empty()
                {
                    intent = Some(ScanIntent::Start(quick));
                }

                let drives = logical_drives();
                if widgets::choice_chip(ui, false, Some(Icon::Chip), "全盘扫描").clicked()
                    && !drives.is_empty()
                {
                    intent = Some(ScanIntent::Start(drives));
                }

                if let Some(home) = dirs::home_dir() {
                    if widgets::choice_chip(ui, false, Some(Icon::Folder), "用户目录").clicked()
                    {
                        intent = Some(ScanIntent::Start(vec![home]));
                    }
                }

                #[cfg(windows)]
                {
                    let windows_dir = std::env::var_os("SystemRoot")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
                    if windows_dir.is_dir()
                        && widgets::choice_chip(ui, false, Some(Icon::Chip), "系统目录").clicked()
                    {
                        intent = Some(ScanIntent::Start(vec![windows_dir]));
                    }
                }
            });

            ui.add_space(12.0);

            // Chosen targets.
            if self.target_paths.is_empty() {
                widgets::well(ui, 92.0, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(6.0);
                        icons::paint(ui, Icon::Folder, 22.0, pal.ink_faint);
                        ui.label(theme::body("尚未选择文件或文件夹").color(pal.ink_soft));
                        widgets::hint(ui, "也可以把文件或文件夹直接拖放到这个窗口");
                        ui.add_space(4.0);
                    });
                });
            } else {
                let total = self.target_paths.len();
                let show = total.min(8);
                widgets::well(ui, 168.0, |ui| {
                    ScrollArea::vertical()
                        .id_salt("scan-targets")
                        .max_height(148.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for index in 0..show {
                                let path = &self.target_paths[index];
                                ui.horizontal(|ui| {
                                    icons::paint(
                                        ui,
                                        if path.is_dir() {
                                            Icon::Folder
                                        } else {
                                            Icon::FileDoc
                                        },
                                        14.0,
                                        pal.ink_faint,
                                    );
                                    ui.label(
                                        theme::mono_text(truncate_path(
                                            &path.to_string_lossy(),
                                            64,
                                        ))
                                        .color(pal.ink),
                                    );
                                    widgets::right_aligned(ui, |ui| {
                                        if widgets::icon_button(ui, Icon::Close, "移除").clicked()
                                        {
                                            intent = Some(ScanIntent::RemoveTarget(index));
                                        }
                                    });
                                });
                            }

                            if total > show {
                                widgets::hint(ui, &format!("另有 {} 个目标未显示", total - show));
                            }
                        });
                });
            }

            ui.add_space(12.0);

            ui.horizontal(|ui| {
                let blocked = scanning || self.target_paths.is_empty();
                if widgets::primary_enabled(ui, Some(Icon::Play), "开始扫描", !blocked).clicked()
                {
                    intent = Some(ScanIntent::Start(self.target_paths.clone()));
                }

                if self.config.scan_archives {
                    widgets::hint(ui, "压缩包会被展开检查，耗时更长");
                }
            });
        });

        ui.add_space(12.0);

        // --- At-a-glance configuration ----------------------------------
        widgets::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::pill(
                    ui,
                    Some(Icon::FileDoc),
                    if self.config.recursive_scan {
                        "递归扫描"
                    } else {
                        "仅当前目录"
                    },
                    if self.config.recursive_scan {
                        Tone::Accent
                    } else {
                        Tone::Neutral
                    },
                );
                widgets::pill(
                    ui,
                    Some(Icon::Database),
                    &format!("单文件上限 {} MB", self.config.max_file_size_mb),
                    Tone::Neutral,
                );
                if self.config.max_scan_threads > 1 {
                    widgets::pill(
                        ui,
                        Some(Icon::Chip),
                        &format!("{} 个并发进程", self.config.max_scan_threads),
                        Tone::Info,
                    );
                }

                widgets::right_aligned(ui, |ui| {
                    if widgets::switch(ui, &mut self.config.auto_quarantine).changed() {
                        self.mark_config_dirty();
                    }
                    ui.label(theme::small("扫描后自动隔离").color(pal.ink_soft));
                });
            });
        });

        ui.add_space(14.0);

        // --- Live progress ----------------------------------------------
        if scanning || self.scan_engine.state == ScanState::Finished {
            let totals = self.scan_engine.totals();
            let stats = self.scan_engine.stats.clone();

            widgets::card(ui, |ui| {
                if scanning {
                    ui.horizontal(|ui| {
                        icons::paint(ui, Icon::Magnifier, 15.0, pal.accent);
                        let text = if self.scan_engine.current_file.is_empty() {
                            "正在准备...".to_string()
                        } else {
                            truncate_path(&self.scan_engine.current_file, 74)
                        };
                        ui.label(theme::mono_text(text).color(pal.ink));
                    });

                    ui.add_space(8.0);

                    // A single worker gives no percentage, so sweep instead of
                    // drawing a bar that would sit at zero for the whole run.
                    match self.scan_engine.progress_fraction() {
                        Some(fraction) => widgets::progress(ui, fraction, 0.0, pal.accent, 6.0),
                        None => widgets::progress(ui, -1.0, phase(ctx), pal.accent, 6.0),
                    }

                    ui.add_space(10.0);
                } else {
                    ui.label(
                        theme::body(if self.scan_engine.was_cancelled {
                            "扫描已取消"
                        } else {
                            "扫描完成"
                        })
                        .color(pal.ink)
                        .strong(),
                    );
                    ui.add_space(8.0);
                }

                ui.columns(4, |cols| {
                    widgets::stat_tile(
                        &mut cols[0],
                        Icon::FileDoc,
                        &format_count(stats.scanned_files),
                        "已扫描文件",
                        Tone::Neutral,
                    );
                    widgets::stat_tile(
                        &mut cols[1],
                        Icon::ShieldAlert,
                        &format_count(stats.infected_files),
                        "检出威胁",
                        if stats.infected_files > 0 {
                            Tone::Danger
                        } else {
                            Tone::Success
                        },
                    );
                    widgets::stat_tile(
                        &mut cols[2],
                        Icon::Database,
                        &format_size((stats.scanned_data_mb * 1024.0 * 1024.0) as u64),
                        "扫描数据量",
                        Tone::Neutral,
                    );
                    widgets::stat_tile(
                        &mut cols[3],
                        Icon::Clock,
                        &format_duration(stats.elapsed_secs),
                        "用时",
                        Tone::Neutral,
                    );
                });

                if totals.workers_total > 1 {
                    ui.add_space(8.0);
                    widgets::hint(
                        ui,
                        &format!(
                            "{} 个扫描进程，已完成 {} 个",
                            totals.workers_total, totals.workers_done
                        ),
                    );
                }
            });

            ui.add_space(14.0);
        }

        // --- Threats ----------------------------------------------------
        if !self.scan_engine.threats.is_empty() {
            let threats = &self.scan_engine.threats;

            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::section_title("发现的威胁").color(pal.ink));
                    widgets::right_aligned(ui, |ui| {
                        if widgets::danger(ui, Some(Icon::Lock), "全部隔离").clicked() {
                            intent = Some(ScanIntent::QuarantineAll);
                        }
                    });
                });

                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(8.0);

                // Row intents are collected here because the list borrows
                // immutably while the action needs to mutate the engine.
                let mut row_intent: Option<usize> = None;

                ScrollArea::vertical()
                    .id_salt("scan-threats")
                    .max_height(280.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (index, threat) in threats.iter().enumerate() {
                            ui.horizontal(|ui| {
                                icons::paint(ui, Icon::ShieldAlert, 15.0, pal.danger);
                                ui.vertical(|ui| {
                                    ui.label(
                                        theme::mono_text(truncate_path(&threat.file_path, 62))
                                            .color(pal.ink),
                                    );
                                    ui.label(theme::small(&threat.threat_name).color(pal.danger));
                                });
                                widgets::right_aligned(ui, |ui| {
                                    if widgets::outline(ui, Some(Icon::Lock), "隔离").clicked() {
                                        row_intent = Some(index);
                                    }
                                });
                            });
                            ui.add_space(2.0);
                        }
                    });

                if let Some(index) = row_intent {
                    intent = Some(ScanIntent::QuarantineOne(index));
                }
            });

            ui.add_space(14.0);
        }

        // --- Log --------------------------------------------------------
        if self.show_scan_log {
            let card_budget = widgets::fill_height(ui, page_height, 4.0, 160.0);
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::section_title("扫描日志").color(pal.ink));
                    widgets::right_aligned(ui, |ui| {
                        if widgets::quiet(ui, None, "复制").clicked() {
                            let text = self.scan_engine.log_lines.join("\n");
                            ui.ctx().copy_text(text);
                            self.toast(ToastKind::Info, "日志已复制到剪贴板");
                        }
                    });
                });
                ui.add_space(4.0);
                ui.label(
                    theme::small(format!("共 {} 行", self.scan_engine.log_lines.len()))
                        .color(pal.ink_faint),
                );
                ui.add_space(8.0);
                // The results take the slack so the page ends at the window edge.
                let height = widgets::well_in_card(ui, card_budget, 32.0, 120.0);
                widgets::log_well(
                    ui,
                    "scan-log",
                    &self.scan_engine.log_lines,
                    height,
                    widgets::default_line_color,
                );
            });
        } else {
            // The log can be switched off, but the page still has to reach the
            // bottom of the window instead of leaving a band of bare paper.
            widgets::empty_state_filling(
                ui,
                page_height,
                Icon::FileDoc,
                "扫描日志已隐藏",
                "点击页面上方的“显示日志”可以随时打开",
                Tone::Neutral,
            );
        }

        if let Some(intent) = intent {
            self.apply_scan_intent(intent);
        }
    }

    fn realtime_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);
        let running = self.realtime.is_running();

        widgets::page_header(
            ui,
            Icon::Pulse,
            "实时保护",
            "基于 Windows ETW 的文件与进程监控",
            |ui| {
                if running {
                    if widgets::danger(ui, Some(Icon::Stop), "停止保护").clicked() {
                        self.realtime.stop(&self.config);
                        self.toast(ToastKind::Info, "已请求停止实时保护");
                    }
                } else if widgets::primary(ui, Some(Icon::Play), "开启保护").clicked() {
                    match self.realtime.start(&self.config) {
                        Ok(()) => self.toast(ToastKind::Success, "实时保护已启动"),
                        Err(e) => self.toast(ToastKind::Danger, e),
                    }
                }
            },
        );

        let tone = if running {
            Tone::Success
        } else {
            Tone::Neutral
        };

        widgets::card_tuned(
            ui,
            Some(pal.surface(tone)),
            Some(pal.tone_ink(tone).gamma_multiply(0.3)),
            Some(18.0),
            |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                    icons::draw(
                        ui.painter(),
                        rect,
                        if running {
                            Icon::ShieldCheck
                        } else {
                            Icon::Shield
                        },
                        pal.tone_ink(tone),
                        40.0,
                    );
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.label(
                            theme::body(if running {
                                "监控运行中"
                            } else {
                                "监控已停止"
                            })
                            .color(pal.ink)
                            .strong(),
                        );
                        let detail = if running {
                            match self.realtime.daemon_pid {
                                Some(pid) => format!("后台进程 {}", pid),
                                None => "后台进程已连接".to_string(),
                            }
                        } else {
                            "开启后可拦截落地的可疑文件".to_string()
                        };
                        ui.label(theme::small(detail).color(pal.ink_soft));
                    });
                    widgets::right_aligned(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                theme::body(format_count(self.realtime.monitored_events))
                                    .color(pal.ink)
                                    .strong(),
                            );
                            ui.label(theme::small("监控事件").color(pal.ink_faint));
                        });
                    });
                });
            },
        );

        if let Some(error) = self.realtime.last_error.clone() {
            ui.add_space(12.0);
            widgets::tone_card(ui, Tone::Danger, |ui| {
                ui.horizontal(|ui| {
                    icons::paint(ui, Icon::Alert, 15.0, pal.danger);
                    ui.label(theme::small(error).color(pal.ink));
                });
            });
        }

        ui.add_space(16.0);

        ui.columns(2, |cols| {
            widgets::card(&mut cols[0], |ui| {
                ui.label(theme::section_title("监控选项").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(6.0);

                if widgets::toggle_row(
                    ui,
                    &mut self.config.yamagoya_monitor_all,
                    "监控全部活动",
                    "关闭后只监控文件与进程创建事件",
                )
                .changed()
                {
                    self.mark_config_dirty();
                }

                if widgets::toggle_row(
                    ui,
                    &mut self.config.yamagoya_kill_process,
                    "终止可疑进程",
                    "检出后直接结束相关进程，可能影响正在运行的程序",
                )
                .changed()
                {
                    self.mark_config_dirty();
                }

                if widgets::toggle_row(
                    ui,
                    &mut self.config.persist_realtime_on_exit,
                    "退出后保持保护",
                    "关闭本程序后，后台监控继续运行",
                )
                .changed()
                {
                    self.mark_config_dirty();
                }
            });

            widgets::card(&mut cols[1], |ui| {
                ui.label(theme::section_title("检测结果").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(8.0);

                if self.realtime.threats.is_empty() {
                    widgets::hint(ui, "暂无检测记录");
                } else {
                    let threats = &self.realtime.threats;
                    let show = threats.len().min(6);
                    ScrollArea::vertical()
                        .id_salt("realtime-threats")
                        .max_height(150.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for threat in threats.iter().rev().take(show) {
                                ui.horizontal(|ui| {
                                    ui.label(theme::small(&threat.timestamp).color(pal.ink_faint));
                                    ui.label(
                                        theme::small(&threat.threat_name)
                                            .color(pal.danger)
                                            .strong(),
                                    );
                                });
                                ui.label(
                                    theme::mono_text(truncate_path(&threat.file_path, 54))
                                        .color(pal.ink_soft),
                                );
                                ui.add_space(4.0);
                            }
                        });

                    if threats.len() > show {
                        widgets::hint(ui, &format!("另有 {} 条记录", threats.len() - show));
                    }
                }
            });
        });

        ui.add_space(14.0);

        // Budget for the whole log card, measured here at page level; the well
        // inside takes what the card's own heading leaves.
        let card_budget = widgets::fill_height(ui, page_height, 4.0, 160.0);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section_title("运行日志").color(pal.ink));
                widgets::right_aligned(ui, |ui| {
                    if widgets::quiet(ui, None, "复制").clicked() {
                        let text = self.realtime.log_lines.join("\n");
                        ui.ctx().copy_text(text);
                        self.toast(ToastKind::Info, "日志已复制到剪贴板");
                    }
                });
            });
            ui.add_space(8.0);
            let height = widgets::well_in_card(ui, card_budget, 32.0, 120.0);
            widgets::log_well(
                ui,
                "realtime-log",
                &self.realtime.log_lines,
                height,
                widgets::default_line_color,
            );
        });
    }

    fn update_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);
        let updating = self.updater.is_updating();

        widgets::page_header(
            ui,
            Icon::Download,
            "病毒库",
            "通过官方镜像更新病毒特征库",
            |ui| {
                if updating {
                    if widgets::danger(ui, Some(Icon::Stop), "取消").clicked() {
                        self.updater.cancel_update();
                        self.toast(ToastKind::Warning, "已请求取消更新");
                    }
                } else if widgets::primary(ui, Some(Icon::Download), "立即更新").clicked() {
                    match self.updater.start_update(&self.config) {
                        Ok(()) => self.toast(ToastKind::Info, "已开始更新病毒库"),
                        Err(e) => self.toast(ToastKind::Warning, e),
                    }
                }
            },
        );

        if updating {
            widgets::card(ui, |ui| {
                ui.label(theme::body("正在更新病毒库").color(pal.ink).strong());
                ui.add_space(8.0);
                match self.updater.progress {
                    Some(fraction) => widgets::progress(ui, fraction, 0.0, pal.accent, 6.0),
                    None => widgets::progress(ui, -1.0, phase(ctx), pal.accent, 6.0),
                }
                ui.add_space(6.0);
                if let Some(fraction) = self.updater.progress {
                    widgets::hint(ui, &format!("已完成 {:.0}%", fraction * 100.0));
                }
            });
            ui.add_space(14.0);
        }

        if let Some(error) = self.updater.last_error.clone() {
            widgets::tone_card(ui, Tone::Danger, |ui| {
                ui.horizontal(|ui| {
                    icons::paint(ui, Icon::Alert, 15.0, pal.danger);
                    ui.label(theme::small(error).color(pal.ink));
                });
            });
            ui.add_space(14.0);
        }

        ui.columns(2, |cols| {
            widgets::card(&mut cols[0], |ui| {
                ui.label(theme::section_title("当前病毒库").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(10.0);

                if self.updater.db_files.is_empty() {
                    widgets::empty_state(
                        ui,
                        Icon::Database,
                        "尚未安装病毒库",
                        "首次使用需要联网执行一次更新",
                        Tone::Warning,
                    );
                } else {
                    widgets::kv(
                        ui,
                        "版本",
                        self.updater.db_version.as_deref().unwrap_or("未知"),
                        None,
                    );
                    widgets::kv(
                        ui,
                        "签名数量",
                        &self
                            .updater
                            .db_sigs
                            .map(format_count)
                            .unwrap_or_else(|| "未知".to_string()),
                        None,
                    );
                    widgets::kv(ui, "占用空间", &format_size(self.updater.db_bytes), None);
                    widgets::kv(
                        ui,
                        "更新时间",
                        self.updater.db_modified.as_deref().unwrap_or("未知"),
                        None,
                    );
                    widgets::kv(
                        ui,
                        "文件",
                        &self.updater.db_files.join(", "),
                        Some(pal.ink_soft),
                    );
                }
            });

            widgets::card(&mut cols[1], |ui| {
                ui.label(theme::section_title("更新设置").color(pal.ink));
                ui.add_space(4.0);
                theme::rule(ui);
                ui.add_space(6.0);

                if widgets::toggle_row(
                    ui,
                    &mut self.config.auto_update,
                    "启动时自动更新",
                    "在后台静默检查并下载新版本病毒库",
                )
                .changed()
                {
                    self.mark_config_dirty();
                }

                ui.add_space(8.0);
                widgets::kv(ui, "镜像", "database.clamav.net", Some(pal.ink_soft));
                widgets::kv(
                    ui,
                    "证书目录",
                    &truncate_path(&self.config.certs_dir().to_string_lossy(), 40),
                    None,
                );
                widgets::kv(
                    ui,
                    "更新工具",
                    &if self.config.freshclam_path().exists() {
                        "freshclam 已就绪".to_string()
                    } else {
                        "freshclam 缺失".to_string()
                    },
                    Some(if self.config.freshclam_path().exists() {
                        pal.success
                    } else {
                        pal.danger
                    }),
                );
            });
        });

        ui.add_space(14.0);

        let card_budget = widgets::fill_height(ui, page_height, 4.0, 160.0);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section_title("更新日志").color(pal.ink));
                widgets::right_aligned(ui, |ui| {
                    if widgets::quiet(ui, None, "复制").clicked() {
                        let text = self.updater.log_lines.join("\n");
                        ui.ctx().copy_text(text);
                        self.toast(ToastKind::Info, "日志已复制到剪贴板");
                    }
                });
            });
            ui.add_space(8.0);
            let height = widgets::well_in_card(ui, card_budget, 32.0, 120.0);
            widgets::log_well(
                ui,
                "update-log",
                &self.updater.log_lines,
                height,
                widgets::default_line_color,
            );
        });
    }

    fn quarantine_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);
        let mut intent: Option<QuarantineIntent> = None;

        let total = self.quarantine.len();
        let subtitle = if total == 0 {
            "隔离的文件会保存在这里".to_string()
        } else {
            format!("共 {} 个项目", total)
        };

        widgets::page_header(ui, Icon::Lock, "隔离区", &subtitle, |ui| {
            if widgets::quiet_enabled(ui, Some(Icon::Refresh), "刷新", true).clicked() {
                self.invalidate_quarantine();
            }
            if widgets::danger_outline_enabled(ui, Some(Icon::Trash), "清空隔离区", total > 0)
                .clicked()
            {
                self.confirm = Some(Confirm::DeleteAllQuarantine);
            }
        });

        if total == 0 {
            // `empty_state` is already a card; wrapping it in another one drew a
            // frame inside a frame with a band of empty padding between them.
            widgets::empty_state_filling(
                ui,
                page_height,
                Icon::ShieldCheck,
                "隔离区是空的",
                "检出的威胁在隔离后会出现在这里，可随时恢复",
                Tone::Success,
            );
            return;
        }

        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                icons::paint(ui, Icon::Magnifier, 14.0, pal.ink_faint);
                ui.add(
                    egui::TextEdit::singleline(&mut self.quarantine_filter)
                        .hint_text("按文件名、原始路径或威胁名称筛选")
                        .desired_width(f32::INFINITY),
                );
            });
        });

        ui.add_space(12.0);

        let filter = self.quarantine_filter.to_lowercase();
        let matches: Vec<usize> = self
            .quarantine
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                if filter.is_empty() {
                    return true;
                }
                let name = entry
                    .quarantine_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                let meta = entry
                    .meta
                    .as_ref()
                    .map(|m| {
                        format!(
                            "{} {}",
                            m.original_path.to_lowercase(),
                            m.threat_name.to_lowercase()
                        )
                    })
                    .unwrap_or_default();
                name.contains(&filter) || meta.contains(&filter)
            })
            .map(|(index, _)| index)
            .collect();

        if matches.is_empty() {
            widgets::empty_state_filling(
                ui,
                page_height,
                Icon::Magnifier,
                "没有匹配的项目",
                "换一个关键词试试",
                Tone::Neutral,
            );
            return;
        }

        // The list takes the slack: 32 px of card padding plus a little air.
        let list_h = widgets::fill_height(ui, page_height, 38.0, 200.0);
        widgets::card(ui, |ui| {
            ScrollArea::vertical()
                .id_salt("quarantine-list")
                .max_height(list_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for index in matches {
                        let Some(entry) = self.quarantine.get(index) else {
                            continue;
                        };

                        let name = entry
                            .quarantine_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "未知文件".to_string());
                        let threat = entry
                            .meta
                            .as_ref()
                            .map(|m| m.threat_name.clone())
                            .unwrap_or_else(|| "未知威胁".to_string());
                        let original = entry
                            .meta
                            .as_ref()
                            .map(|m| m.original_path.clone())
                            .unwrap_or_else(|| "原始路径未知".to_string());
                        let date = entry
                            .meta
                            .as_ref()
                            .map(|m| m.quarantine_date.clone())
                            .unwrap_or_default();

                        ui.horizontal_top(|ui| {
                            icons::paint(ui, Icon::Lock, 18.0, pal.warning);
                            ui.add_space(2.0);
                            ui.vertical(|ui| {
                                ui.label(
                                    theme::body(truncate_path(&name, 52))
                                        .color(pal.ink)
                                        .strong(),
                                );
                                ui.label(theme::small(threat.clone()).color(pal.danger));
                                ui.label(
                                    theme::mono_text(truncate_path(&original, 58))
                                        .color(pal.ink_faint),
                                );
                            });
                            widgets::right_aligned(ui, |ui| {
                                if widgets::danger_outline(ui, Some(Icon::Trash), "删除").clicked()
                                {
                                    intent = Some(QuarantineIntent::Delete(index));
                                }
                                if widgets::outline(ui, Some(Icon::Restore), "恢复").clicked() {
                                    intent = Some(QuarantineIntent::Restore(index));
                                }
                                ui.vertical(|ui| {
                                    ui.label(
                                        theme::small(format_size(entry.file_size))
                                            .color(pal.ink_faint),
                                    );
                                    if !date.is_empty() {
                                        ui.label(theme::small(date).color(pal.ink_faint));
                                    }
                                });
                            });
                        });

                        ui.add_space(8.0);
                        theme::rule(ui);
                        ui.add_space(8.0);
                    }
                });
        });

        if let Some(intent) = intent {
            self.apply_quarantine_intent(intent);
        }
    }

    fn log_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, page_height: f32) {
        let pal = Palette::current(ui);

        widgets::page_header(
            ui,
            Icon::FileDoc,
            "日志",
            "扫描、实时保护与更新的完整记录",
            |ui| {
                let lines = self.current_log().to_vec();
                if widgets::outline_enabled(ui, None, "导出", !lines.is_empty()).clicked() {
                    let name = match self.log_source {
                        LogSource::Scan => "scan.log",
                        LogSource::Realtime => "realtime.log",
                        LogSource::Update => "update.log",
                    };
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("导出日志")
                        .set_file_name(name)
                        .save_file()
                    {
                        match std::fs::write(&path, lines.join("\r\n")) {
                            Ok(()) => self
                                .toast(ToastKind::Success, format!("已导出到 {}", path.display())),
                            Err(e) => self.toast(ToastKind::Danger, format!("导出失败: {}", e)),
                        }
                    }
                }
                if widgets::quiet(ui, None, "复制").clicked() {
                    ui.ctx().copy_text(lines.join("\n"));
                    self.toast(ToastKind::Info, "日志已复制到剪贴板");
                }
            },
        );

        ui.horizontal(|ui| {
            for (source, label) in [
                (LogSource::Scan, "扫描"),
                (LogSource::Realtime, "实时保护"),
                (LogSource::Update, "病毒库更新"),
            ] {
                if widgets::choice_chip(ui, self.log_source == source, None, label).clicked() {
                    self.log_source = source;
                }
            }
            widgets::right_aligned(ui, |ui| {
                widgets::hint(ui, &format!("{} 行", self.current_log().len()));
            });
        });

        ui.add_space(12.0);

        let lines = self.current_log().to_vec();

        if lines.is_empty() {
            widgets::empty_state_filling(
                ui,
                page_height,
                Icon::FileDoc,
                "暂无日志",
                "执行一次扫描或更新后，这里会显示详细输出",
                Tone::Neutral,
            );
            return;
        }

        // The log *is* this page, so its card takes everything the heading and
        // the source chips did not use.
        let card_budget = widgets::fill_height(ui, page_height, 4.0, 200.0);
        widgets::card_tuned(ui, None, None, Some(10.0), |ui| {
            let height = widgets::well_in_card(ui, card_budget, 20.0, 200.0);
            widgets::log_well(ui, "log-panel", &lines, height, widgets::default_line_color);
        });

        // Keeps the palette referenced even when the list is short-circuited.
        let _ = pal;
    }

    fn current_log(&self) -> &Vec<String> {
        match self.log_source {
            LogSource::Scan => &self.scan_engine.log_lines,
            LogSource::Realtime => &self.realtime.log_lines,
            LogSource::Update => &self.updater.log_lines,
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        let pal = Palette::current(ui);

        widgets::page_header(
            ui,
            Icon::Sliders,
            "设置",
            "扫描行为、排除规则与目录位置",
            |ui| {
                if widgets::primary(ui, Some(Icon::Check), "保存设置").clicked() {
                    self.save_config();
                    self.toast(ToastKind::Success, "设置已保存");
                }
            },
        );

        // The page itself scrolls; the panel must not nest another ScrollArea
        // inside it, which is what previously made the wheel behave oddly over
        // the settings form.
        ScrollArea::vertical()
            .id_salt("settings-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // --- Presets -------------------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "扫描强度");

                    ui.horizontal_wrapped(|ui| {
                        let fast = self.config.max_file_size_mb <= 25 && !self.config.scan_archives;
                        let thorough = self.config.max_file_size_mb >= 500 && self.config.scan_mail;

                        if widgets::choice_chip(ui, fast, Some(Icon::Chip), "快速").clicked() {
                            self.config.apply_fast_scan_preset();
                            self.mark_config_dirty();
                        }
                        if widgets::choice_chip(ui, !fast && !thorough, None, "均衡").clicked() {
                            self.config.apply_balanced_scan_preset();
                            self.mark_config_dirty();
                        }
                        if widgets::choice_chip(ui, thorough, None, "彻底").clicked() {
                            self.config.apply_thorough_scan_preset();
                            self.mark_config_dirty();
                        }
                    });

                    ui.add_space(12.0);

                    let mut max_mb = self.config.max_file_size_mb as f32;
                    ui.horizontal(|ui| {
                        ui.label(theme::small("单文件大小上限").color(pal.ink_soft));
                        if ui
                            .add(
                                egui::Slider::new(&mut max_mb, 1.0..=1024.0)
                                    .suffix(" MB")
                                    .logarithmic(true),
                            )
                            .changed()
                        {
                            self.config.max_file_size_mb = max_mb.round() as u64;
                            self.mark_config_dirty();
                        }
                    });

                    let mut threads = self.config.max_scan_threads as f32;
                    ui.horizontal(|ui| {
                        ui.label(theme::small("并发扫描进程").color(pal.ink_soft));
                        if ui
                            .add(egui::Slider::new(&mut threads, 1.0..=8.0).integer())
                            .changed()
                        {
                            self.config.max_scan_threads = threads.round() as u32;
                            self.mark_config_dirty();
                        }
                    });

                    if self.config.max_scan_threads > 1 {
                        widgets::hint(
                            ui,
                            &format!(
                                "每个进程都会独立加载一份病毒库，约多占用 {} MB 内存；仅在高速磁盘上有明显收益。",
                                (self.updater.db_bytes / (1024 * 1024)).saturating_mul(
                                    self.config.max_scan_threads.saturating_sub(1) as u64
                                )
                            ),
                        );
                    } else {
                        widgets::hint(ui, "单进程扫描；加载一次病毒库，内存占用最低。");
                    }
                });

                ui.add_space(14.0);

                // --- Scanning behaviour -------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "扫描范围");

                    if widgets::toggle_row(
                        ui,
                        &mut self.config.recursive_scan,
                        "递归扫描子目录",
                        "关闭后只扫描所选目录的第一层",
                    )
                    .changed()
                    {
                        self.mark_config_dirty();
                    }

                    ui.add_space(8.0);
                    ui.label(theme::small("内容类型").color(pal.ink_faint));
                    ui.add_space(4.0);

                    ui.horizontal_wrapped(|ui| {
                        let mut changed = false;
                        changed |= widgets::check_box(ui, &mut self.config.scan_archives).changed();
                        ui.label(theme::small("压缩包").color(pal.ink_soft));
                        ui.add_space(10.0);
                        changed |= widgets::check_box(ui, &mut self.config.scan_mail).changed();
                        ui.label(theme::small("邮件").color(pal.ink_soft));
                        ui.add_space(10.0);
                        changed |= widgets::check_box(ui, &mut self.config.scan_ole2).changed();
                        ui.label(theme::small("Office 文档").color(pal.ink_soft));
                        ui.add_space(10.0);
                        changed |= widgets::check_box(ui, &mut self.config.scan_pdf).changed();
                        ui.label(theme::small("PDF").color(pal.ink_soft));
                        ui.add_space(10.0);
                        changed |= widgets::check_box(ui, &mut self.config.scan_html).changed();
                        ui.label(theme::small("HTML").color(pal.ink_soft));
                        ui.add_space(10.0);
                        changed |= widgets::check_box(ui, &mut self.config.heuristic_alerts).changed();
                        ui.label(theme::small("启发式告警").color(pal.ink_soft));

                        if changed {
                            self.mark_config_dirty();
                        }
                    });

                    ui.add_space(8.0);
                    widgets::hint(
                        ui,
                        "「启发式告警」会把疑似文件也报出来，可能产生误报，但不会漏掉加壳样本。",
                    );
                });

                ui.add_space(14.0);

                // --- Exclusions ---------------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "排除规则");
                    widgets::hint(
                        ui,
                        "每条规则都是区分大小写的正则表达式（PCRE），同时用于跳过目录和忽略文件。",
                    );
                    ui.add_space(10.0);

                    let mut remove: Option<usize> = None;
                    for (index, pattern) in self.config.exclude_patterns.iter().enumerate() {
                        ui.horizontal(|ui| {
                            icons::paint(ui, Icon::ChevronRight, 13.0, pal.ink_faint);
                            ui.label(theme::mono_text(pattern.clone()).color(pal.ink));
                            widgets::right_aligned(ui, |ui| {
                                if widgets::icon_button(ui, Icon::Trash, "删除规则").clicked() {
                                    remove = Some(index);
                                }
                            });
                        });
                    }

                    if let Some(index) = remove {
                        self.config.exclude_patterns.remove(index);
                        self.mark_config_dirty();
                    }

                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.exclude_draft)
                                .hint_text(r"例如 [\\/]node_modules$")
                                .desired_width(320.0),
                        );
                        let submit = response.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter));

                        if (widgets::outline(ui, Some(Icon::Check), "添加").clicked() || submit)
                            && !self.exclude_draft.trim().is_empty()
                        {
                            let pattern = self.exclude_draft.trim().to_string();
                            if !self.config.exclude_patterns.contains(&pattern) {
                                self.config.exclude_patterns.push(pattern);
                                self.mark_config_dirty();
                            }
                            self.exclude_draft.clear();
                        }

                        if widgets::quiet(ui, None, "开发目录预设").clicked() {
                            for pattern in config::developer_exclusions() {
                                if !self.config.exclude_patterns.contains(&pattern) {
                                    self.config.exclude_patterns.push(pattern);
                                }
                            }
                            self.mark_config_dirty();
                            self.toast(ToastKind::Info, "已添加 node_modules、target 等排除项");
                        }
                    });
                });

                ui.add_space(14.0);

                // --- Appearance & startup ------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "外观与启动");

                    if widgets::toggle_row(
                        ui,
                        &mut self.config.dark_mode,
                        "深色墨板",
                        "关闭时使用暖白纸面配色",
                    )
                    .changed()
                    {
                        self.grain = None;
                        self.mark_config_dirty();
                    }

                    let mut close_to_tray = self.config.close_to_tray;
                    if widgets::toggle_row(
                        ui,
                        &mut close_to_tray,
                        "关闭窗口时最小化到托盘",
                        if self.tray.is_some() {
                            "程序仍在后台运行，可从托盘图标恢复"
                        } else {
                            "当前环境不支持系统托盘，该选项不会生效"
                        },
                    )
                    .changed()
                    {
                        self.config.close_to_tray = close_to_tray;
                        self.mark_config_dirty();
                    }

                    if widgets::toggle_row(
                        ui,
                        &mut self.config.auto_quarantine,
                        "扫描后自动隔离",
                        "扫描结束后立即把检出的文件移入隔离区",
                    )
                    .changed()
                    {
                        self.mark_config_dirty();
                    }

                    ui.add_space(8.0);

                    // The app does not request elevation at startup, so surface
                    // the consequence honestly instead of failing silently later.
                    if crate::is_elevated() {
                        ui.horizontal(|ui| {
                            icons::paint(ui, Icon::ShieldCheck, 15.0, pal.accent);
                            ui.label(
                                theme::small("当前以管理员身份运行，受保护位置也可以扫描和隔离。")
                                    .color(pal.ink_soft),
                            );
                        });
                    } else {
                        ui.horizontal(|ui| {
                            if widgets::outline(ui, Some(Icon::ShieldCheck), "以管理员身份重启")
                                .clicked()
                            {
                                match crate::relaunch_as_admin() {
                                    Ok(()) => {
                                        // Hand the single-instance lock over to
                                        // the elevated copy.
                                        self.quitting = true;
                                        ui.ctx().send_viewport_cmd(
                                            egui::ViewportCommand::Close,
                                        );
                                    }
                                    Err(message) => {
                                        self.toast(ToastKind::Warning, message);
                                    }
                                }
                            }
                            ui.label(
                                theme::small(
                                    "部分系统位置需要管理员权限才能扫描或隔离。",
                                )
                                .color(pal.ink_faint),
                            );
                        });
                    }
                });

                ui.add_space(14.0);

                // --- Directories ---------------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "目录位置");

                    let mut pick: Option<usize> = None;
                    let dirs: [(usize, &str, PathBuf, bool); 3] = [
                        (0, "扫描引擎", self.config.clamav_dir.clone(), true),
                        (1, "病毒库", self.config.database_dir.clone(), true),
                        (2, "隔离区", self.config.quarantine_dir.clone(), true),
                    ];

                    for (index, label, path, _is_dir) in &dirs {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(theme::small(*label).color(pal.ink_faint));
                                ui.label(
                                    theme::mono_text(truncate_path(
                                        &path.to_string_lossy(),
                                        54,
                                    ))
                                    .color(pal.ink),
                                );
                            });
                            widgets::right_aligned(ui, |ui| {
                                if widgets::quiet_enabled(ui, None, "浏览", true).clicked() {
                                    pick = Some(*index);
                                }
                                if widgets::quiet_enabled(
                                    ui,
                                    None,
                                    "打开",
                                    path.exists(),
                                )
                                .clicked()
                                {
                                    let _ = open::that(path);
                                }
                            });
                        });
                        ui.add_space(6.0);
                    }

                    if let Some(index) = pick {
                        if let Some(folder) = rfd::FileDialog::new()
                            .set_title("选择目录")
                            .pick_folder()
                        {
                            match index {
                                0 => self.config.clamav_dir = folder,
                                1 => self.config.database_dir = folder,
                                2 => self.config.quarantine_dir = folder,
                                _ => {}
                            }
                            self.config = self.config.clone().normalized();
                            self.mark_config_dirty();
                        }
                    }

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if widgets::quiet(ui, Some(Icon::Refresh), "恢复默认目录").clicked() {
                            let defaults = AppConfig::default();
                            self.config.clamav_dir = defaults.clamav_dir;
                            self.config.database_dir = defaults.database_dir;
                            self.config.quarantine_dir = defaults.quarantine_dir;
                            self.config.log_dir = defaults.log_dir;
                            self.mark_config_dirty();
                        }
                        if widgets::quiet(ui, None, "打开配置目录").clicked() {
                            let _ = open::that(config::base_dir());
                        }
                    });
                });

                ui.add_space(14.0);

                // --- About ---------------------------------------------------
                widgets::card(ui, |ui| {
                    widgets::section(ui, "关于");

                    widgets::kv(ui, "程序版本", APP_VERSION, None);
                    widgets::kv(ui, "配置文件", &truncate_path(
                        &AppConfig::primary_config_path().to_string_lossy(),
                        52,
                    ), None);
                    widgets::kv(
                        ui,
                        "系统托盘",
                        if self.tray.is_some() { "可用" } else { "不可用" },
                        Some(if self.tray.is_some() { pal.success } else { pal.warning }),
                    );

                    ui.add_space(6.0);
                    ui.label(
                        theme::small("ClamAV 是 Cisco Talos 的商标；本程序仅为图形前端。")
                            .color(pal.ink_faint),
                    );

                    ui.add_space(12.0);
                    if widgets::danger_outline(ui, Some(Icon::Refresh), "恢复默认设置").clicked() {
                        self.confirm = Some(Confirm::ResetSettings);
                    }

                    if widgets::quiet(ui, Some(Icon::Trash), "清除扫描历史").clicked() {
                        self.confirm = Some(Confirm::ClearScanHistory);
                    }
                });
            });
    }

    fn render_confirm(&mut self, ctx: &egui::Context) {
        let Some(kind) = self.confirm else {
            return;
        };

        let pal = Palette::from_ctx(ctx);
        let (title, body, confirm_label) = match kind {
            Confirm::DeleteAllQuarantine => (
                "清空隔离区？",
                "隔离区中的全部文件将被永久删除，此操作无法撤销。".to_string(),
                "永久删除",
            ),
            Confirm::DeleteQuarantine(index) => {
                let name = self
                    .quarantine
                    .get(index)
                    .and_then(|e| e.quarantine_path.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "该文件".to_string());
                (
                    "删除隔离文件？",
                    format!("「{}」将被永久删除，此操作无法撤销。", name),
                    "永久删除",
                )
            }
            Confirm::ClearScanHistory => (
                "清除扫描历史？",
                "仅删除本程序记录的扫描结果，不会影响磁盘上的任何文件。".to_string(),
                "清除记录",
            ),
            Confirm::ResetSettings => (
                "恢复默认设置？",
                "扫描选项、排除规则与目录位置都会回到初始状态。".to_string(),
                "恢复默认",
            ),
        };

        let mut decision: Option<bool> = None;

        egui::Modal::new(egui::Id::new("confirm-modal")).show(ctx, |ui| {
            ui.set_width(400.0);
            ui.horizontal(|ui| {
                icons::paint(ui, Icon::Alert, 20.0, pal.warning);
                ui.label(theme::title(title).color(pal.ink));
            });
            ui.add_space(10.0);
            ui.label(theme::body(body).color(pal.ink_soft));
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if widgets::danger(ui, None, confirm_label).clicked() {
                    decision = Some(true);
                }
                if widgets::outline(ui, None, "取消").clicked() {
                    decision = Some(false);
                }
            });
        });

        match decision {
            Some(true) => {
                self.confirm = None;
                match kind {
                    Confirm::DeleteAllQuarantine => {
                        self.apply_quarantine_intent(QuarantineIntent::DeleteAll)
                    }
                    Confirm::DeleteQuarantine(index) => self.delete_quarantine_entry(index),
                    Confirm::ClearScanHistory => {
                        let path = self.config.scan_history_path();
                        let _ = std::fs::remove_file(&path);
                        self.scan_engine = ScanEngine::default();
                        self.scan_engine.restored_from_history = true;
                        self.scan_target_label = "尚未执行扫描".to_string();
                        self.toast(ToastKind::Success, "扫描历史已清除");
                    }
                    Confirm::ResetSettings => {
                        let dark = self.config.dark_mode;
                        self.config = AppConfig::default();
                        self.config.dark_mode = dark;
                        self.grain = None;
                        self.mark_config_dirty();
                        self.toast(ToastKind::Info, "已恢复默认设置");
                    }
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }

    fn render_toast(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);

        let Some(toast) = self.toast.as_mut() else {
            return;
        };

        if toast.expires_at == 0.0 {
            toast.expires_at = now + 4.5;
        } else if now > toast.expires_at {
            self.toast = None;
            return;
        }

        let pal = Palette::from_ctx(ctx);
        let tone = toast.kind.tone();
        let icon = toast.kind.icon();
        let text = toast.text.clone();

        egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -26.0))
            .order(egui::Order::Foreground)
            .interactable(false)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(pal.surface(tone))
                    .stroke(theme::hairline(pal.tone_ink(tone).gamma_multiply(0.35)))
                    .corner_radius(theme::radius(theme::R_MD))
                    .inner_margin(egui::Margin::symmetric(14, 9))
                    .shadow(egui::epaint::Shadow {
                        offset: [0, 2],
                        blur: 10,
                        spread: 0,
                        color: Color32::from_black_alpha(if pal.dark { 90 } else { 28 }),
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            icons::paint(ui, icon, 15.0, pal.tone_ink(tone));
                            ui.label(theme::body(text).color(pal.ink));
                        });
                    });
            });
    }

    fn render_initialising(&mut self, ctx: &egui::Context) -> bool {
        if self.bootstrap.finished {
            return false;
        }

        let pal = Palette::from_ctx(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(pal.paper))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.32);
                    icons::paint(ui, Icon::ShieldCheck, 46.0, pal.accent);
                    ui.add_space(10.0);
                    ui.label(theme::title(APP_NAME).color(pal.ink));
                    ui.add_space(6.0);
                    ui.label(theme::body(self.bootstrap.label.clone()).color(pal.ink_soft));
                    ui.add_space(14.0);

                    let width = 380.0_f32.min(ui.available_width() * 0.8);
                    ui.allocate_ui(Vec2::new(width, 8.0), |ui| {
                        let fraction = self.bootstrap.fraction().unwrap_or(-1.0);
                        widgets::progress(ui, fraction, phase(ctx), pal.accent, 6.0);
                    });

                    ui.add_space(10.0);
                    widgets::hint(ui, "首次启动需要释放内置组件，之后的启动会很快。");
                });
            });

        true
    }
}

impl eframe::App for ClamAvApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // --- Pump background work --------------------------------------
        self.handle_bootstrap();
        self.scan_engine.poll_messages();
        self.realtime.poll_messages();
        self.updater.poll_messages(&self.config);

        self.handle_tray(ctx);
        // Launching the executable again is the user asking to see this window,
        // so a second copy signals us instead of starting its own.
        if crate::take_wake_request() {
            self.restore_from_tray(ctx);
        }
        self.handle_close_request(ctx);
        self.handle_dropped_files(ctx);
        self.handle_auto_quarantine();
        self.ensure_quarantine();
        self.update_tray_tooltip();
        self.maybe_save_config();
        self.save_window_size(ctx);

        // --- Apply the theme only when it actually changed ---------------
        if self.applied_dark != Some(self.config.dark_mode) {
            theme::apply(ctx, self.config.dark_mode);
            self.applied_dark = Some(self.config.dark_mode);
            // The grain tint differs between paper and ink board.
            self.grain = None;
        }

        // --- While in the tray, skip layout and painting entirely ---------
        // The window is only minimised, so this branch still runs: a tray menu
        // click is noticed from here, and everything below is what would cost
        // real CPU if it kept running behind a closed window.
        if self.hidden {
            let toast_expired = self
                .toast
                .as_ref()
                .is_some_and(|toast| ctx.input(|i| i.time) >= toast.expires_at);
            if toast_expired {
                self.toast = None;
            }
            // Safety net: poll the tray channel a few times a second even if a
            // wake-up from the menu thread were ever dropped. A frame that
            // reaches this point draws nothing, so it is nearly free.
            ctx.request_repaint_after(Duration::from_millis(120));
            return;
        }

        // --- First-run splash ------------------------------------------
        if self.render_initialising(ctx) {
            self.render_toast(ctx);
            ctx.request_repaint_after(Duration::from_millis(90));
            return;
        }

        // --- Grain texture (created once, reused) ----------------------
        let grain = self
            .grain
            .get_or_insert_with(|| theme::grain_texture(ctx))
            .clone();

        let pal = Palette::of(self.config.dark_mode);

        // --- Navigation rail -------------------------------------------
        egui::SidePanel::left("nav-rail")
            .exact_width(theme::RAIL_WIDTH)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(pal.sunken)
                    .inner_margin(egui::Margin::symmetric(12, 14)),
            )
            .show(ctx, |ui| {
                self.sidebar(ui);
            });

        // --- Page ------------------------------------------------------
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal.paper)
                    .inner_margin(egui::Margin::symmetric(
                        theme::PAGE_PAD as i8,
                        (theme::PAGE_PAD - 4.0) as i8,
                    )),
            )
            .show(ctx, |ui| {
                // Paper grain behind everything on the page.
                let full = ui.max_rect().expand(theme::PAGE_PAD);
                theme::paint_grain(ui.painter(), full, &grain, &pal);

                // The height a page may use, measured out here where it is
                // simply the viewport. Pages lay themselves out to end exactly
                // at this line, so nothing needs scrolling and nothing is left
                // as bare paper at the bottom.
                let page_height = ui.available_height();

                ScrollArea::vertical()
                    .id_salt(("page", self.tab as u8))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        widgets::page(ui, |ui| {
                            let tab = self.tab;
                            match tab {
                                Tab::Dashboard => self.dashboard_panel(ui, ctx, page_height),
                                Tab::Scan => self.scan_panel(ui, ctx, page_height),
                                Tab::Realtime => self.realtime_panel(ui, ctx, page_height),
                                Tab::Update => self.update_panel(ui, ctx, page_height),
                                Tab::Quarantine => self.quarantine_panel(ui, ctx, page_height),
                                Tab::Logs => self.log_panel(ui, ctx, page_height),
                                Tab::Settings => self.settings_panel(ui),
                            }
                        });
                    });
            });

        // --- Overlays ---------------------------------------------------
        self.render_confirm(ctx);
        self.render_toast(ctx);

        // --- Repaint policy ---------------------------------------------
        ctx.request_repaint_after(self.repaint_delay());
    }
}

impl ClamAvApp {
    /// Remember the window size so it can be persisted on exit.
    fn save_window_size(&mut self, ctx: &egui::Context) {
        // While in the tray the window is minimised, so its "size" is the
        // icon-sized rectangle Windows gives a minimised window and its
        // maximised flag reads as false. Remembering either would reopen the app
        // tiny — or un-maximised — on the next launch.
        if self.hidden {
            return;
        }

        let (size, maximized) = ctx.input(|i| {
            let viewport = i.viewport();
            (viewport.inner_rect.map(|r| r.size()), viewport.maximized)
        });

        if let Some(size) = size {
            if size.x > 100.0 && size.y > 100.0 {
                self.window_size = Some((size.x, size.y));
            }
        }
        if let Some(maximized) = maximized {
            self.window_maximized = maximized;
        }
    }
}

impl Drop for ClamAvApp {
    /// Persist geometry and make sure the background monitor cannot outlive the
    /// user's intent to close the window.
    fn drop(&mut self) {
        // Geometry.
        if let Some((width, height)) = self.window_size {
            self.config.window.width = width;
            self.config.window.height = height;
        }
        self.config.window.maximized = self.window_maximized;

        // The monitor is only left running when the user explicitly asked for
        // that; otherwise shut it down synchronously, because a spawned thread
        // would be torn down with the process before it finished.
        if self.realtime.is_running() && !self.config.persist_realtime_on_exit {
            self.realtime.stop_blocking(&self.config);
        }

        self.persist_history();
        let _ = self.config.save();
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Animation phase for indeterminate progress, derived from the frame clock.
fn phase(ctx: &egui::Context) -> f32 {
    // One full sweep per 1.6 seconds.
    ((ctx.input(|i| i.time) % 1.6) / 1.6) as f32
}

/// Shorten a long path for display, keeping the head and the file name.
///
/// Character-based rather than byte-based: the previous implementation sliced
/// `&path[len - n..]`, which panics the moment a Chinese path puts a multi-byte
/// character on the cut boundary.
fn truncate_path(path: &str, max_chars: usize) -> String {
    let count = path.chars().count();
    if count <= max_chars {
        return path.to_string();
    }
    if max_chars <= 8 {
        return "…".to_string();
    }

    // A quarter of the budget goes to the leading volume / folder hint; the
    // rest is spent on the tail, where the file name lives.
    let head_len = (max_chars - 3) / 4;
    let tail_len = max_chars - 3 - head_len;

    let head: String = path.chars().take(head_len).collect();
    let tail: String = path.chars().skip(count - tail_len).collect();
    format!("{}…{}", head, tail)
}

/// Human-readable byte count.
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else if value >= 100.0 {
        format!("{:.0} {}", value, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Elapsed seconds as `1 小时 2 分 3 秒`.
fn format_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 1.0 {
        return "不到 1 秒".to_string();
    }

    let total = secs.round() as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

    if hours > 0 {
        format!("{} 小时 {} 分", hours, minutes)
    } else if minutes > 0 {
        format!("{} 分 {} 秒", minutes, seconds)
    } else {
        format!("{} 秒", seconds)
    }
}

/// Thousands separators, for large file counts.
fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }

    out
}

/// Default quick-scan locations: the places malware actually lands.
fn quick_scan_targets() -> Vec<PathBuf> {
    let mut targets = Vec::new();

    if let Some(home) = dirs::home_dir() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let path = home.join(sub);
            if path.is_dir() {
                targets.push(path);
            }
        }
    }

    if let Some(app_data) = dirs::config_dir() {
        let startup = app_data.join("Microsoft/Windows/Start Menu/Programs/Startup");
        if startup.is_dir() {
            targets.push(startup);
        }
    }

    for variable in ["TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(variable) {
            let path = PathBuf::from(value);
            if path.is_dir() {
                targets.push(path);
            }
        }
    }

    if let Some(windows) = std::env::var_os("SystemRoot") {
        let temp = PathBuf::from(windows).join("Temp");
        if temp.is_dir() {
            targets.push(temp);
        }
    }

    targets.sort();
    targets.dedup();
    targets
}

/// Fixed local drives, for the "scan everything" action.
///
/// Uses `GetLogicalDrives`/`GetDriveType` rather than probing `A:`…`Z:` with
/// `Path::exists`, which would spin up removable media and can block for
/// seconds on an empty card reader.
#[cfg(windows)]
fn logical_drives() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

    /// `DRIVE_FIXED` from `Win32::System::SystemServices`, spelled out so the
    /// extra windows-sys feature is not needed just for one constant.
    const DRIVE_FIXED: u32 = 3;

    let mask = unsafe { GetLogicalDrives() };
    let mut drives = Vec::new();

    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }

        let letter = (b'A' + index as u8) as char;
        let root = format!("{}:\\", letter);
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

        if unsafe { GetDriveTypeW(wide.as_ptr()) } == DRIVE_FIXED {
            drives.push(PathBuf::from(root));
        }
    }

    drives
}

#[cfg(not(windows))]
fn logical_drives() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Tiny convenience for building a fallback subtitle.
trait PipeIfEmpty {
    fn pipe_if_empty(self, fallback: &str) -> String;
}

impl PipeIfEmpty for String {
    fn pipe_if_empty(self, fallback: &str) -> String {
        if self.trim().is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncating_a_cjk_path_never_panics() {
        // Regression: the old version sliced bytes (`&path[len - n..]`), which
        // panics as soon as a cut lands inside a multi-byte character — i.e. on
        // essentially every Chinese path.
        let path = r"C:\用户\非常长的目录名称\另一个很长的目录\还有一个目录\最终的文件.docx";
        let out = truncate_path(path, 24);

        assert!(out.chars().count() <= 24, "got {:?}", out);
        assert!(out.contains('…'), "got {:?}", out);
        assert!(out.starts_with("C:\\"), "got {:?}", out);
        assert!(!out.contains('\u{FFFD}'), "got {:?}", out);
        // The file name is the part worth keeping, so the tail must survive.
        assert!(out.ends_with(".docx"), "got {:?}", out);
    }

    #[test]
    fn truncating_leaves_short_paths_alone() {
        assert_eq!(truncate_path(r"C:\a.txt", 40), r"C:\a.txt");
        // Exactly at the budget is still "short enough".
        assert_eq!(truncate_path("abc", 3), "abc");
    }

    #[test]
    fn a_tiny_budget_degrades_to_an_ellipsis() {
        assert_eq!(truncate_path(r"C:\some\very\long\path.txt", 8), "…");
        assert_eq!(truncate_path(r"C:\some\very\long\path.txt", 1), "…");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0 GB");
        // 100 KB and up drop the decimal, so columns stay narrow.
        assert_eq!(format_size(100 * 1024), "100 KB");
        assert_eq!(format_size(999 * 1024), "999 KB");
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(format_duration(0.0), "不到 1 秒");
        assert_eq!(format_duration(f64::NAN), "不到 1 秒");
        assert_eq!(format_duration(1.4), "1 秒");
        assert_eq!(format_duration(45.0), "45 秒");
        assert_eq!(format_duration(65.0), "1 分 5 秒");
        assert_eq!(format_duration(3661.0), "1 小时 1 分");
        assert_eq!(format_duration(7200.0), "2 小时 0 分");
    }

    #[test]
    fn counts_get_thousands_separators() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1000), "1,000");
        assert_eq!(format_count(12_345), "12,345");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn quick_scan_targets_are_absolute_and_exist() {
        // The list is derived from the real user profile, so only assert the
        // invariants: absolute paths, and nothing that does not exist.
        for path in quick_scan_targets() {
            assert!(path.is_absolute(), "{path:?} is not absolute");
            assert!(path.exists(), "{path:?} does not exist");
        }
    }

    #[cfg(windows)]
    #[test]
    fn logical_drives_are_fixed_disks() {
        let drives = logical_drives();
        assert!(!drives.is_empty(), "expected at least one fixed drive");
        for drive in drives {
            let text = drive.to_string_lossy().to_string();
            assert!(text.ends_with(":\\"), "unexpected drive {text:?}");
        }
    }
}

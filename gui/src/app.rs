use eframe::egui;
use egui::{Color32, CornerRadius, FontId, Stroke};
use std::collections::HashSet;

use crate::config::AppConfig;
use crate::scanner::{ScanEngine, ScanState};
use crate::realtime::{RealtimeProtection, RealtimeState};
use crate::theme;
use crate::updater::{DatabaseUpdater, UpdateState};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    Scan,
    Realtime,
    Update,
    Quarantine,
    Settings,
    Log,
}

pub struct ClamAvApp {
    config: AppConfig,
    scan_engine: ScanEngine,
    updater: DatabaseUpdater,
    realtime: RealtimeProtection,
    current_tab: Tab,
    scan_target: String,
    theme_applied: bool,
    // Settings temp state
    settings_max_size: String,
    settings_threads: String,
    settings_exclude: String,
    // Quarantine state
    quarantine_selected: HashSet<String>,
    auto_quarantine_pending: bool,
}

impl ClamAvApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        config.ensure_dirs();

        let settings_max_size = config.max_file_size_mb.to_string();
        let settings_threads = config.max_scan_threads.to_string();
        let settings_exclude = config.exclude_patterns.join("\n");

        let mut updater = DatabaseUpdater::default();
        updater.check_database_status(&config);

        let scan_engine = ScanEngine::default();

        Self {
            config,
            scan_engine,
            updater,
            realtime: RealtimeProtection::default(),
            current_tab: Tab::Dashboard,
            scan_target: String::new(),
            theme_applied: false,
            settings_max_size,
            settings_threads,
            settings_exclude,
            quarantine_selected: HashSet::new(),
            auto_quarantine_pending: false,
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.vertical(|ui| {
            ui.add_space(16.0);

            // App title
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("🛡 ClamAV")
                        .font(FontId::proportional(24.0))
                        .color(theme::ACCENT),
                );
                ui.label(
                    egui::RichText::new("杀毒软件扫描器")
                        .font(FontId::proportional(12.0))
                        .color(theme::text_secondary(dark_mode)),
                );
            });

            ui.add_space(24.0);
            ui.separator();
            ui.add_space(8.0);

            let tabs = [
                (Tab::Dashboard, "📊", "仪表板"),
                (Tab::Scan, "🔍", "扫描文件"),
                (Tab::Realtime, "🛡", "实时保护"),
                (Tab::Update, "🔄", "更新病毒库"),
                (Tab::Quarantine, "🔒", "隔离区"),
                (Tab::Settings, "⚙", "设置"),
                (Tab::Log, "📋", "日志"),
            ];

            for (tab, icon, label) in &tabs {
                let selected = self.current_tab == *tab;
                let btn = ui.add_sized(
                    [theme::SIDEBAR_WIDTH - 24.0, 38.0],
                    egui::Button::new(
                        egui::RichText::new(format!("  {}  {}", icon, label))
                            .font(FontId::proportional(15.0))
                            .color(if selected {
                                Color32::WHITE
                            } else {
                                theme::text_secondary(dark_mode)
                            }),
                    )
                    .fill(if selected {
                        theme::ACCENT
                    } else {
                        Color32::TRANSPARENT
                    })
                    .corner_radius(CornerRadius::same(8))
                    .stroke(Stroke::NONE),
                );
                if btn.clicked() {
                    self.current_tab = *tab;
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                        .font(FontId::proportional(11.0))
                        .color(theme::text_secondary(dark_mode)),
                );
            });
        });
    }

    fn dashboard_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.add_space(12.0);
        ui.label(theme::heading("仪表板"));
        ui.add_space(12.0);

        // Status cards row - enhanced with icons and better styling
        ui.columns(4, |cols| {
            // ClamAV 引擎状态
            cols[0].vertical_centered(|ui| {
                let clamscan_exists = self.config.clamscan_path().exists();
                
                enhanced_card(ui, |ui| {
                    status_icon(ui, if clamscan_exists { "⚙" } else { "✖" });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(if clamscan_exists { "就绪" } else { "未找到" })
                            .font(FontId::proportional(16.0))
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new("引擎状态")
                            .font(FontId::proportional(11.0)),
                    );
                }, if clamscan_exists { theme::SUCCESS } else { theme::DANGER });
            });

            // Realtime status
            cols[1].vertical_centered(|ui| {
                let rt_on = self.realtime.state == RealtimeState::Running;
                enhanced_card(ui, |ui| {
                    status_icon(ui, if rt_on { "🛡" } else { "⚠" });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(if rt_on { "已启用" } else { "未启用" })
                            .font(FontId::proportional(16.0))
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new("实时保护")
                            .font(FontId::proportional(11.0)),
                    );
                }, if rt_on { theme::SUCCESS } else { theme::WARNING });
            });

            // Database status
            cols[2].vertical_centered(|ui| {
                let has_db = self.updater.db_version.is_some();
                enhanced_card(ui, |ui| {
                    status_icon(ui, if has_db { "📚" } else { "⚠" });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(if has_db { "已加载" } else { "未配置" })
                            .font(FontId::proportional(16.0))
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new("病毒库")
                            .font(FontId::proportional(11.0)),
                    );
                }, if has_db { theme::SUCCESS } else { theme::WARNING });
            });

            // Threats count
            cols[3].vertical_centered(|ui| {
                let threat_count = self.scan_engine.threats.len() + self.realtime.threats.len();
                enhanced_card(ui, |ui| {
                    status_icon(ui, if threat_count == 0 { "✓" } else { "⚠" });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(threat_count.to_string())
                            .font(FontId::proportional(16.0))
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new("发现威胁")
                            .font(FontId::proportional(11.0)),
                    );
                }, if threat_count == 0 { theme::SUCCESS } else { theme::DANGER });
            });
        });

        ui.add_space(20.0);

        // Statistics overview
        ui.label(theme::subheading("统计概览"));
        ui.add_space(8.0);
        
        ui.columns(3, |cols| {
            cols[0].vertical_centered(|ui| {
                stat_card(ui, "📊", &self.scan_engine.stats.scanned_files.to_string(), "已扫描文件");
            });
            cols[1].vertical_centered(|ui| {
                stat_card(ui, "🔍", &self.realtime.scanned_count.to_string(), "实时监控扫描");
            });
            cols[2].vertical_centered(|ui| {
                let last_update = self.updater.last_update.clone()
                    .unwrap_or_else(|| "未更新".to_string());
                stat_card(ui, "🕒", &last_update, "上次更新");
            });
        });

        ui.add_space(20.0);

        // Quick actions - enhanced
        ui.label(theme::subheading("快速操作"));
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let scan_busy = self.scan_engine.state == ScanState::Scanning;
            if ui.add_enabled(!scan_busy, theme::accent_button("⚡ 快速扫描")).clicked() {
                // Quick scan system locations
                self.start_quick_scan();
                self.current_tab = Tab::Scan;
            }
            if ui.add_enabled(!scan_busy, theme::accent_button("💿 全盘扫描")).clicked() {
                // Full disk scan
                self.start_full_scan();
                self.current_tab = Tab::Scan;
            }
            if ui.add(theme::accent_button("🔄 更新病毒库")).clicked() {
                if self.updater.state != UpdateState::Updating {
                    self.updater.start_update(&self.config);
                }
                self.current_tab = Tab::Update;
            }
            if self.realtime.state != RealtimeState::Running {
                if ui.add(theme::accent_button("🛡 启动保护")).clicked() {
                    self.realtime.start(&self.config);
                    self.current_tab = Tab::Realtime;
                }
            }
        });

        ui.add_space(20.0);

        // Recent threats with better visualization
        ui.label(theme::subheading("最近威胁"));
        ui.add_space(8.0);

        if self.scan_engine.threats.is_empty() && self.realtime.threats.is_empty() {
            egui::Frame::new()
                .fill(theme::success_surface(dark_mode))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("✅")
                                .font(FontId::proportional(24.0)),
                        );
                        ui.label(
                            egui::RichText::new("系统安全 - 未发现任何威胁")
                                .font(FontId::proportional(15.0))
                                .color(theme::SUCCESS),
                        );
                    });
                });
        } else {
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    // Collect all threats into owned vector
                    let mut all_threats = Vec::new();
                    for t in &self.scan_engine.threats {
                        all_threats.push(crate::scanner::ThreatInfo {
                            file_path: t.file_path.clone(),
                            threat_name: t.threat_name.clone(),
                        });
                    }
                    for t in &self.realtime.threats {
                        all_threats.push(crate::scanner::ThreatInfo {
                            file_path: t.file_path.clone(),
                            threat_name: t.threat_name.clone(),
                        });
                    }
                    
                    for threat in all_threats.iter().take(20) {
                        egui::Frame::new()
                            .fill(theme::danger_surface(dark_mode))
                            .corner_radius(CornerRadius::same(6))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("⚠️")
                                            .font(FontId::proportional(18.0)),
                                    );
                                    ui.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(&threat.threat_name)
                                                .font(FontId::proportional(13.0))
                                                .color(theme::WARNING)
                                                .strong(),
                                        );
                                        ui.label(
                                            egui::RichText::new(truncate_path(&threat.file_path, 60))
                                                .font(FontId::proportional(11.0)),
                                        );
                                    });
                                });
                            });
                        ui.add_space(4.0);
                    }
                });
        }
    }

    fn start_quick_scan(&mut self) {
        // Quick scan should cover multiple critical locations.
        let mut candidates = Vec::new();

        if let Some(home) = dirs::home_dir() {
            candidates.push(home.join("Downloads"));
            candidates.push(home.join("Desktop"));
            candidates.push(home.join("Documents"));
            candidates.push(home.join("AppData").join("Local").join("Temp"));
        }

        if let Ok(temp) = std::env::var("TEMP") {
            candidates.push(std::path::PathBuf::from(temp));
        }

        if let Ok(windir) = std::env::var("WINDIR") {
            candidates.push(std::path::PathBuf::from(windir).join("Temp"));
        }

        let mut targets = Vec::new();
        for path in candidates {
            if path.exists() && !targets.iter().any(|p| p == &path) {
                targets.push(path);
            }
        }

        if targets.is_empty() {
            self.scan_engine.log_lines.push("ERROR: 快速扫描未找到可用目录".to_string());
            return;
        }

        let preview = targets
            .iter()
            .take(3)
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("; ");
        self.scan_target = if targets.len() > 3 {
            format!("快速扫描: {} ... (共 {} 个路径)", preview, targets.len())
        } else {
            format!("快速扫描: {}", preview)
        };

        self.auto_quarantine_pending = false;
        self.scan_engine.start_scan_targets(targets, &self.config);
    }

    fn start_full_scan(&mut self) {
        // Scan all available local drives (C:..Z:).
        let mut drives = Vec::new();
        for letter in b'C'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let path = std::path::PathBuf::from(&root);
            if path.exists() {
                drives.push(path);
            }
        }

        if drives.is_empty() {
            self.scan_engine.log_lines.push("ERROR: 未找到可扫描磁盘".to_string());
            return;
        }

        self.scan_target = format!(
            "全盘扫描: {}",
            drives
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );

        self.auto_quarantine_pending = false;
        self.scan_engine.start_scan_targets(drives, &self.config);
    }

    fn scan_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        let panel_width = ui.available_width();

        ui.add_space(12.0);
        ui.label(theme::heading("文件扫描"));
        ui.add_space(12.0);

        // Target selection
        ui.label(
            egui::RichText::new("扫描目标")
                .font(FontId::proportional(13.0))
                .color(theme::text_secondary(dark_mode)),
        );
        ui.add_space(4.0);
        ui.add_sized(
            [panel_width, 30.0],
            egui::TextEdit::singleline(&mut self.scan_target)
                .hint_text("选择文件夹或文件路径...")
                .font(FontId::proportional(13.0)),
        );

        ui.add_space(8.0);

        // Buttons row
        ui.horizontal_wrapped(|ui| {
            let scan_busy = self.scan_engine.state == ScanState::Scanning;
            if ui.add_enabled(!scan_busy, theme::accent_button("📁 浏览文件夹")).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.scan_target = folder.to_string_lossy().to_string();
                }
            }
            if ui.add_enabled(!scan_busy, theme::accent_button("📄 浏览文件")).clicked() {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.scan_target = file.to_string_lossy().to_string();
                }
            }
            if ui.add_enabled(!scan_busy, theme::accent_button("⚡ 快速扫描")).clicked() {
                self.start_quick_scan();
            }
            if ui.add_enabled(!scan_busy, theme::accent_button("💿 全盘扫描")).clicked() {
                self.start_full_scan();
            }

            match self.scan_engine.state {
                ScanState::Idle | ScanState::Finished => {
                    let has_target = !self.scan_target.is_empty();
                    if ui.add_enabled(has_target, theme::accent_button("▶ 开始扫描")).clicked() {
                        let target_path = std::path::Path::new(&self.scan_target);
                        if !target_path.exists() {
                            self.scan_engine.log_lines.push(format!(
                                "ERROR: 扫描目标不存在: {}", self.scan_target
                            ));
                            self.scan_engine.state = ScanState::Finished;
                        } else if !self.config.clamscan_path().exists() {
                            self.scan_engine.log_lines.push(format!(
                                "ERROR: 扫描引擎未找到: {}", self.config.clamscan_path().display()
                            ));
                            self.scan_engine.state = ScanState::Finished;
                        } else {
                            self.auto_quarantine_pending = false;
                            self.scan_engine.start_scan(
                                std::path::PathBuf::from(&self.scan_target),
                                &self.config,
                            );
                        }
                    }
                }
                ScanState::Scanning => {
                    if ui.add(theme::danger_button("⏹ 停止扫描")).clicked() {
                        self.scan_engine.cancel_scan();
                    }
                }
            }
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // Stats - use columns to evenly divide available width
        let scanned = self.scan_engine.stats.scanned_files.to_string();
        let infected = self.scan_engine.stats.infected_files.to_string();
        let infected_color = if self.scan_engine.stats.infected_files > 0 { theme::DANGER } else { theme::SUCCESS };
        let scanned_data = format!("{:.1} MB", self.scan_engine.stats.scanned_data_mb);
        let elapsed = format!("{:.1}s", self.scan_engine.stats.elapsed_secs);

        ui.columns(4, |cols| {
            cols[0].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&scanned).font(FontId::proportional(26.0)).color(theme::text_primary(dark_mode)));
                            ui.label(egui::RichText::new("已扫描").font(FontId::proportional(13.0)).color(theme::text_secondary(dark_mode)));
                        });
                    });
            });
            cols[1].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&infected).font(FontId::proportional(26.0)).color(infected_color));
                            ui.label(egui::RichText::new("已感染").font(FontId::proportional(13.0)).color(theme::text_secondary(dark_mode)));
                        });
                    });
            });
            cols[2].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&scanned_data).font(FontId::proportional(26.0)).color(theme::text_primary(dark_mode)));
                            ui.label(egui::RichText::new("扫描数据").font(FontId::proportional(13.0)).color(theme::text_secondary(dark_mode)));
                        });
                    });
            });
            cols[3].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&elapsed).font(FontId::proportional(26.0)).color(theme::text_primary(dark_mode)));
                            ui.label(egui::RichText::new("用时").font(FontId::proportional(13.0)).color(theme::text_secondary(dark_mode)));
                        });
                    });
            });
        });

        ui.add_space(12.0);

        // Current file being scanned - enhanced display
        if self.scan_engine.state == ScanState::Scanning {
            ui.add_space(4.0);
            egui::Frame::new()
                .fill(theme::info_surface(dark_mode))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new("正在扫描")
                                    .font(FontId::proportional(11.0))
                                    .color(theme::text_secondary(dark_mode)),
                            );
                            ui.label(
                                egui::RichText::new(&self.scan_engine.current_file)
                                    .font(FontId::proportional(10.0))
                                    .color(theme::text_secondary(dark_mode)),
                            );
                        });
                    });
                });
            ui.add_space(8.0);
        }

        // Error messages display
        if self.scan_engine.state != ScanState::Scanning {
            let errors: Vec<_> = self.scan_engine.log_lines.iter()
                .filter(|l| l.starts_with("ERROR:"))
                .cloned()
                .collect();
            if !errors.is_empty() {
                for err in errors.iter().rev().take(3) {
                    egui::Frame::new()
                        .fill(theme::danger_surface(dark_mode))
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new("❌")
                                        .font(FontId::proportional(16.0)),
                                );
                                ui.label(
                                    egui::RichText::new(err)
                                        .font(FontId::proportional(13.0))
                                        .color(theme::DANGER),
                                );
                            });
                        });
                    ui.add_space(4.0);
                }
            }
        }

        // Scan result banner
        if self.scan_engine.state == ScanState::Finished
            && self.scan_engine.stats.scanned_files > 0
        {
            let (msg, color) = if self.scan_engine.stats.infected_files == 0 {
                ("✅ 扫描完成 - 未发现威胁", theme::SUCCESS)
            } else {
                ("⚠ 扫描完成 - 发现威胁！", theme::DANGER)
            };
            ui.label(
                egui::RichText::new(msg)
                    .font(FontId::proportional(18.0))
                    .color(color),
            );
            ui.add_space(8.0);
        }

        // Threats list
        if !self.scan_engine.threats.is_empty() {
            ui.label(
                egui::RichText::new(format!("⚠ 发现 {} 个威胁", self.scan_engine.threats.len()))
                    .font(FontId::proportional(16.0))
                    .color(theme::DANGER),
            );
            ui.add_space(4.0);

            let threats = self.scan_engine.threats.clone();
            let quarantine_dir = self.config.quarantine_dir.clone();
            for threat in &threats {
                egui::Frame::new()
                    .fill(theme::danger_surface(dark_mode))
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("⚠")
                                    .font(FontId::proportional(16.0))
                                    .color(theme::DANGER),
                            );
                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new(&threat.threat_name)
                                        .font(FontId::proportional(13.0))
                                        .color(theme::WARNING),
                                );
                                ui.label(
                                    egui::RichText::new(&threat.file_path)
                                        .font(FontId::proportional(11.0))
                                        .color(theme::text_secondary(dark_mode)),
                                );
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(theme::danger_button("🔒 隔离")).clicked() {
                                    let _ = self.scan_engine.quarantine_threat(threat, &quarantine_dir);
                                }
                            });
                        });
                    });
                ui.add_space(4.0);
            }
        }
    }

    fn realtime_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.add_space(12.0);
        ui.label(theme::heading("实时保护"));
        ui.add_space(12.0);

        // Status banner
        let is_running = self.realtime.state == RealtimeState::Running;
        egui::Frame::new()
            .fill(if is_running {
                theme::success_surface(dark_mode)
            } else {
                theme::warning_surface(dark_mode)
            })
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(if is_running { "🛡" } else { "⚠" })
                            .font(FontId::proportional(28.0)),
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(if is_running {
                                "实时保护已启用"
                            } else {
                                "实时保护已关闭"
                            })
                            .font(FontId::proportional(18.0))
                            .color(if is_running { theme::SUCCESS } else { theme::WARNING }),
                        );
                        ui.label(
                            egui::RichText::new(if is_running {
                                "正在监控文件变化，自动扫描新文件"
                            } else {
                                "点击下方按钮开启实时保护"
                            })
                            .font(FontId::proportional(12.0))
                            .color(theme::text_secondary(dark_mode)),
                        );
                    });
                });
            });

        ui.add_space(12.0);

        // Control buttons
        ui.horizontal(|ui| {
            if is_running {
                if ui.add(theme::danger_button("⏹ 停止保护")).clicked() {
                    self.realtime.stop();
                }
            } else {
                if ui.add(theme::accent_button("▶ 启动保护")).clicked() {
                    self.realtime.start(&self.config);
                }
            }
        });

        ui.add_space(12.0);

        // Monitor dirs
        ui.label(theme::subheading("监控目录"));
        ui.add_space(4.0);

        let watch_dirs = if self.realtime.watch_dirs.is_empty() {
            let mut defaults = Vec::new();
            if let Some(home) = dirs::home_dir() {
                for sub in &["Downloads", "Desktop", "Documents"] {
                    let p = home.join(sub);
                    if p.exists() {
                        defaults.push(p);
                    }
                }
            }
            defaults
        } else {
            self.realtime.watch_dirs.clone()
        };

        for dir in &watch_dirs {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("📁")
                        .font(FontId::proportional(14.0)),
                );
                ui.label(
                    egui::RichText::new(dir.to_string_lossy())
                        .font(FontId::proportional(12.0))
                        .color(theme::text_primary(dark_mode)),
                );
            });
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.add(theme::accent_button("➕ 添加目录")).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.realtime.watch_dirs.push(folder);
                }
            }
            if !self.realtime.watch_dirs.is_empty() {
                if ui.add(theme::danger_button("🗑 清除自定义")).clicked() {
                    self.realtime.watch_dirs.clear();
                }
            }
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // Stats
        ui.columns(2, |cols| {
            cols[0].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new(&self.realtime.scanned_count.to_string())
                                    .font(FontId::proportional(26.0))
                                    .color(theme::text_primary(dark_mode)),
                            );
                            ui.label(
                                egui::RichText::new("已扫描文件")
                                    .font(FontId::proportional(13.0))
                                    .color(theme::text_secondary(dark_mode)),
                            );
                        });
                    });
            });
            cols[1].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::bg_card(dark_mode))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            let count = self.realtime.threats.len();
                            ui.label(
                                egui::RichText::new(&count.to_string())
                                    .font(FontId::proportional(26.0))
                                    .color(if count > 0 { theme::DANGER } else { theme::SUCCESS }),
                            );
                            ui.label(
                                egui::RichText::new("发现威胁")
                                    .font(FontId::proportional(13.0))
                                    .color(theme::text_secondary(dark_mode)),
                            );
                        });
                    });
            });
        });

        // Threats
        if !self.realtime.threats.is_empty() {
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new(format!("⚠ 实时检测到 {} 个威胁", self.realtime.threats.len()))
                    .font(FontId::proportional(15.0))
                    .color(theme::DANGER),
            );
            ui.add_space(4.0);

            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for threat in self.realtime.threats.iter().rev().take(50) {
                        egui::Frame::new()
                            .fill(theme::danger_surface(dark_mode))
                            .corner_radius(CornerRadius::same(6))
                            .inner_margin(egui::Margin::same(6))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("⚠").color(theme::DANGER),
                                    );
                                    ui.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(&threat.threat_name)
                                                .font(FontId::proportional(12.0))
                                                .color(theme::WARNING),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!("{} - {}", threat.timestamp, threat.file_path))
                                                .font(FontId::proportional(11.0))
                                                .color(theme::text_secondary(dark_mode)),
                                        );
                                    });
                                });
                            });
                        ui.add_space(2.0);
                    }
                });
        }

        // Activity log
        if !self.realtime.log_lines.is_empty() {
            ui.add_space(12.0);
            ui.label(theme::subheading("活动日志"));
            egui::ScrollArea::vertical()
                .id_salt("realtime_log")
                .max_height(150.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in self.realtime.log_lines.iter().rev().take(100) {
                        let color = if line.contains("THREAT") {
                            theme::DANGER
                        } else {
                            theme::text_secondary(dark_mode)
                        };
                        ui.label(
                            egui::RichText::new(line)
                                .font(FontId::monospace(10.0))
                                .color(color),
                        );
                    }
                });
        }
    }

    fn update_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.add_space(12.0);
        ui.label(theme::heading("病毒库更新"));
        ui.add_space(12.0);

        // Database info
        ui.horizontal(|ui| {
            card(ui, 250.0, |ui| {
                ui.label(theme::subheading("当前病毒库"));
                let ver = self
                    .updater
                    .db_version
                    .clone()
                    .unwrap_or_else(|| "未安装".into());
                ui.label(
                    egui::RichText::new(ver)
                        .font(FontId::proportional(13.0))
                        .color(theme::text_primary(dark_mode)),
                );
            });
            card(ui, 250.0, |ui| {
                ui.label(theme::subheading("上次更新"));
                let ts = self
                    .updater
                    .last_update
                    .clone()
                    .unwrap_or_else(|| "从未".into());
                ui.label(
                    egui::RichText::new(ts)
                        .font(FontId::proportional(13.0))
                        .color(theme::text_primary(dark_mode)),
                );
            });
        });

        ui.add_space(12.0);

        match self.updater.state {
            UpdateState::Idle | UpdateState::Done => {
                if ui.add(theme::accent_button("🔄 开始更新")).clicked() {
                    self.updater.start_update(&self.config);
                }
            }
            UpdateState::Updating => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        egui::RichText::new("正在更新病毒库...")
                            .font(FontId::proportional(14.0))
                            .color(theme::ACCENT),
                    );
                });
            }
        }

        // Update log - always show, even if empty during update
        ui.add_space(12.0);
        ui.label(theme::subheading("更新日志"));
        egui::ScrollArea::vertical()
            .id_salt("update_log")
            .max_height(300.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.updater.log_lines.is_empty() {
                    let msg = if self.updater.state == UpdateState::Updating {
                        "Connecting..."
                    } else {
                        "No logs - Click 'Start Update' button above"
                    };
                    ui.label(
                        egui::RichText::new(msg)
                            .font(FontId::monospace(12.0))
                            .color(theme::text_secondary(dark_mode)),
                    );
                } else {
                    for line in &self.updater.log_lines {
                        ui.label(
                            egui::RichText::new(line)
                                .font(FontId::monospace(12.0))
                                .color(theme::text_secondary(dark_mode)),
                        );
                    }
                }
            });
    }

    fn quarantine_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.add_space(12.0);
        ui.label(theme::heading("隔离区"));
        ui.add_space(8.0);

        ui.label(
            egui::RichText::new(format!(
                "隔离目录: {}",
                self.config.quarantine_dir.display()
            ))
            .font(FontId::proportional(12.0))
            .color(theme::text_secondary(dark_mode)),
        );

        ui.add_space(8.0);

        // 列出隔离文件
        let entries = crate::scanner::list_quarantine_entries(&self.config.quarantine_dir);

        // 清除无效选择（已不在列表中的）
        let valid_keys: HashSet<String> = entries
            .iter()
            .map(|e| e.quarantine_path.to_string_lossy().to_string())
            .collect();
        self.quarantine_selected.retain(|k| valid_keys.contains(k));

        // 工具栏
        ui.horizontal(|ui| {
            if ui.add(theme::accent_button("📁 打开隔离目录")).clicked() {
                let _ = open::that(&self.config.quarantine_dir);
            }

            if !entries.is_empty() {
                ui.add_space(8.0);
                // 全选 / 取消全选
                if self.quarantine_selected.len() == entries.len() {
                    if ui.add(theme::accent_button("☐ 取消全选")).clicked() {
                        self.quarantine_selected.clear();
                    }
                } else {
                    if ui.add(theme::accent_button("☑ 全选")).clicked() {
                        self.quarantine_selected = valid_keys;
                    }
                }

                let sel_count = self.quarantine_selected.len();
                if sel_count > 0 {
                    ui.add_space(8.0);
                    if ui
                        .add(theme::danger_button(&format!("🗑 批量删除 ({})", sel_count)))
                        .clicked()
                    {
                        let to_delete: Vec<_> = entries
                            .iter()
                            .filter(|e| {
                                self.quarantine_selected
                                    .contains(&e.quarantine_path.to_string_lossy().to_string())
                            })
                            .cloned()
                            .collect();
                        for entry in &to_delete {
                            let _ = crate::scanner::delete_quarantined(entry);
                        }
                        self.quarantine_selected.clear();
                    }
                    if ui
                        .add(theme::accent_button(&format!("↩ 批量恢复 ({})", sel_count)))
                        .clicked()
                    {
                        let to_restore: Vec<_> = entries
                            .iter()
                            .filter(|e| {
                                self.quarantine_selected
                                    .contains(&e.quarantine_path.to_string_lossy().to_string())
                            })
                            .cloned()
                            .collect();
                        for entry in &to_restore {
                            let _ = crate::scanner::restore_quarantined(entry);
                        }
                        self.quarantine_selected.clear();
                    }
                }
            }
        });

        ui.add_space(12.0);

        if entries.is_empty() {
            egui::Frame::new()
                .fill(theme::success_surface(dark_mode))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("✅")
                                .font(FontId::proportional(24.0)),
                        );
                        ui.label(
                            egui::RichText::new("隔离区为空 - 没有隔离的文件")
                                .font(FontId::proportional(15.0))
                                .color(theme::SUCCESS),
                        );
                    });
                });
        } else {
            ui.label(
                egui::RichText::new(format!(
                    "共 {} 个隔离文件 (已选 {})",
                    entries.len(),
                    self.quarantine_selected.len()
                ))
                .font(FontId::proportional(13.0))
                .color(theme::WARNING),
            );
            ui.add_space(4.0);

            egui::ScrollArea::vertical()
                .max_height(450.0)
                .show(ui, |ui| {
                    for entry in &entries {
                        let key = entry.quarantine_path.to_string_lossy().to_string();
                        let name = entry
                            .quarantine_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let size_str = format_size(entry.file_size);

                        egui::Frame::new()
                            .fill(theme::bg_card(dark_mode))
                            .corner_radius(CornerRadius::same(6))
                            .inner_margin(egui::Margin::same(8))
                            .stroke(Stroke::new(
                                1.0,
                                if self.quarantine_selected.contains(&key) {
                                    theme::ACCENT
                                } else {
                                    theme::border_color(dark_mode)
                                },
                            ))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    // 选择框
                                    let mut checked = self.quarantine_selected.contains(&key);
                                    if ui.checkbox(&mut checked, "").changed() {
                                        if checked {
                                            self.quarantine_selected.insert(key.clone());
                                        } else {
                                            self.quarantine_selected.remove(&key);
                                        }
                                    }

                                    ui.label(
                                        egui::RichText::new("🔒")
                                            .font(FontId::proportional(16.0))
                                            .color(theme::WARNING),
                                    );

                                    ui.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(&name)
                                                .font(FontId::proportional(13.0))
                                                .color(theme::text_primary(dark_mode)),
                                        );
                                        // 显示元数据信息
                                        if let Some(ref meta) = entry.meta {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "威胁: {}",
                                                    meta.threat_name
                                                ))
                                                .font(FontId::proportional(11.0))
                                                .color(theme::DANGER),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "原路径: {}",
                                                    truncate_path(&meta.original_path, 70)
                                                ))
                                                .font(FontId::proportional(11.0))
                                                .color(theme::text_secondary(dark_mode)),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "隔离时间: {} | 大小: {}",
                                                    meta.quarantine_date, size_str
                                                ))
                                                .font(FontId::proportional(11.0))
                                                .color(theme::text_secondary(dark_mode)),
                                            );
                                        } else {
                                            ui.label(
                                                egui::RichText::new(format!("大小: {}", size_str))
                                                    .font(FontId::proportional(11.0))
                                                    .color(theme::text_secondary(dark_mode)),
                                            );
                                        }
                                    });

                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.add(theme::danger_button("🗑 删除")).clicked() {
                                                let _ = crate::scanner::delete_quarantined(entry);
                                                self.quarantine_selected.remove(&key);
                                            }
                                            let has_meta = entry.meta.is_some();
                                            if ui
                                                .add_enabled(
                                                    has_meta,
                                                    theme::accent_button("↩ 恢复"),
                                                )
                                                .clicked()
                                            {
                                                let _ = crate::scanner::restore_quarantined(entry);
                                                self.quarantine_selected.remove(&key);
                                            }
                                        },
                                    );
                                });
                            });
                        ui.add_space(4.0);
                    }
                });
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(theme::heading("设置"));
        ui.add_space(12.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Theme toggle
            ui.label(theme::subheading("界面主题"));
            ui.add_space(4.0);
            let mut theme_changed = false;
            ui.horizontal(|ui| {
                ui.label("🌙");
                if ui.checkbox(&mut self.config.dark_mode, "深色模式").changed() {
                    theme_changed = true;
                }
            });
            if theme_changed {
                theme::apply_theme(ui.ctx(), self.config.dark_mode);
            }
            ui.add_space(12.0);

            // Scan options
            ui.label(theme::subheading("扫描选项"));
            ui.add_space(4.0);

            // 扫描预设
            ui.label(
                egui::RichText::new("扫描预设")
                    .font(FontId::proportional(12.0))
                    .color(theme::text_secondary(ui.visuals().dark_mode)),
            );
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui.add(theme::accent_button("⚡ 快速模式")).on_hover_text("跳过压缩包和邮件，速度最快").clicked() {
                    self.config.apply_fast_scan_preset();
                    self.settings_max_size = self.config.max_file_size_mb.to_string();
                }
                if ui.add(theme::accent_button("⚖ 平衡模式")).on_hover_text("推荐设置，性能与安全平衡").clicked() {
                    self.config.apply_balanced_scan_preset();
                    self.settings_max_size = self.config.max_file_size_mb.to_string();
                }
                if ui.add(theme::accent_button("🔬 深度模式")).on_hover_text("全面扫描，最安全但较慢").clicked() {
                    self.config.apply_thorough_scan_preset();
                    self.settings_max_size = self.config.max_file_size_mb.to_string();
                }
            });
            ui.add_space(8.0);

            ui.checkbox(&mut self.config.recursive_scan, "递归扫描子目录");
            ui.checkbox(&mut self.config.scan_archives, "扫描压缩包文件");
            ui.checkbox(&mut self.config.scan_mail, "扫描邮件文件");
            ui.checkbox(&mut self.config.scan_pdf, "扫描 PDF 文件");
            ui.checkbox(&mut self.config.scan_html, "扫描 HTML 文件");
            ui.checkbox(&mut self.config.heuristic_alerts, "启发式检测");

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("最大文件大小 (MB):");
                ui.add_sized(
                    [80.0, 24.0],
                    egui::TextEdit::singleline(&mut self.settings_max_size)
                        .font(FontId::proportional(13.0)),
                );
            });

            ui.horizontal(|ui| {
                ui.label("扫描线程数:");
                ui.add_sized(
                    [80.0, 24.0],
                    egui::TextEdit::singleline(&mut self.settings_threads)
                        .font(FontId::proportional(13.0)),
                );
            });

            ui.add_space(8.0);
            ui.label(theme::subheading("排除模式 (每行一个)"));
            ui.add_sized(
                [500.0, 80.0],
                egui::TextEdit::multiline(&mut self.settings_exclude)
                    .font(FontId::monospace(12.0)),
            );

            ui.add_space(8.0);
            ui.checkbox(&mut self.config.auto_update, "启动时自动更新病毒库");
            ui.checkbox(
                &mut self.config.persist_realtime_on_exit,
                "退出 GUI 后保留实时保护进程",
            );

            ui.add_space(16.0);

            if ui.add(theme::accent_button("💾 保存设置")).clicked() {
                if let Ok(v) = self.settings_max_size.parse::<u64>() {
                    self.config.max_file_size_mb = v;
                }
                if let Ok(v) = self.settings_threads.parse::<u32>() {
                    self.config.max_scan_threads = v;
                }
                self.config.exclude_patterns = self
                    .settings_exclude
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.trim().to_string())
                    .collect();
                self.config.ensure_dirs();
                self.config.save();
            }
        });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        ui.add_space(12.0);
        ui.label(theme::heading("扫描日志"));
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.add(theme::accent_button("🗑 清除日志")).clicked() {
                self.scan_engine.log_lines.clear();
            }
            ui.label(
                egui::RichText::new(format!("{} 条记录", self.scan_engine.log_lines.len()))
                    .font(FontId::proportional(12.0))
                    .color(theme::text_secondary(dark_mode)),
            );
        });

        ui.add_space(8.0);

        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.scan_engine.log_lines {
                    let color = if line.contains("THREAT") || line.contains("FOUND") {
                        theme::DANGER
                    } else if line.contains("ERROR") {
                        theme::WARNING
                    } else {
                        theme::text_secondary(dark_mode)
                    };
                    ui.label(
                        egui::RichText::new(line)
                            .font(FontId::monospace(11.0))
                            .color(color),
                    );
                }
            });
    }
}

impl Drop for ClamAvApp {
    fn drop(&mut self) {
        // Stop any active scan and kill the scan process
        self.scan_engine.cancel_scan();

        if !self.config.persist_realtime_on_exit
            && self.realtime.state == RealtimeState::Running
        {
            self.realtime.stop();
        }
        // ScanEngine::Drop will handle killing scan child process
    }
}

impl eframe::App for ClamAvApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx, self.config.dark_mode);
            self.theme_applied = true;
        }

        // Poll background tasks
        self.scan_engine.poll_messages();
        self.updater.poll_messages();
        self.realtime.poll_messages();

        // 扫描完成后自动隔离感染文件
        if self.scan_engine.state == ScanState::Finished
            && !self.auto_quarantine_pending
            && !self.scan_engine.threats.is_empty()
        {
            self.auto_quarantine_pending = true;
            let quarantine_dir = self.config.quarantine_dir.clone();
            let threats = self.scan_engine.threats.clone();
            let mut quarantined_count = 0u32;
            for threat in &threats {
                if let Ok(_) = self.scan_engine.quarantine_threat(threat, &quarantine_dir) {
                    quarantined_count += 1;
                }
            }
            if quarantined_count > 0 {
                self.scan_engine.log_lines.push(format!(
                    "INFO: 已自动隔离 {} 个感染文件到隔离区",
                    quarantined_count
                ));
            }
        }

        // Request repaint while scanning/updating/realtime
        if self.scan_engine.state == ScanState::Scanning
            || self.updater.state == UpdateState::Updating
            || self.realtime.state == RealtimeState::Running
        {
            ctx.request_repaint();
        }

        // Sidebar
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(theme::SIDEBAR_WIDTH)
            .show(ctx, |ui| {
                ui.painter().rect_filled(
                    ui.max_rect(),
                    CornerRadius::ZERO,
                    theme::bg_panel(ctx.style().visuals.dark_mode),
                );
                self.sidebar(ui);
            });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                match self.current_tab {
                    Tab::Dashboard => self.dashboard_panel(ui),
                    Tab::Scan => self.scan_panel(ui),
                    Tab::Realtime => self.realtime_panel(ui),
                    Tab::Update => self.update_panel(ui),
                    Tab::Quarantine => self.quarantine_panel(ui),
                    Tab::Settings => self.settings_panel(ui),
                    Tab::Log => self.log_panel(ui),
                }
            });
        });
    }
}

fn card(ui: &mut egui::Ui, width: f32, add_contents: impl FnOnce(&mut egui::Ui)) {
    let dark_mode = ui.visuals().dark_mode;
    egui::Frame::new()
        .fill(theme::bg_card(dark_mode))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
        .show(ui, |ui| {
            ui.set_min_width(width);
            add_contents(ui);
        });
}

fn enhanced_card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui), accent_color: Color32) {
    let dark_mode = ui.visuals().dark_mode;
    egui::Frame::new()
        .fill(theme::bg_card(dark_mode))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(16))
        .stroke(Stroke::new(2.0, accent_color.gamma_multiply(0.3)))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                add_contents(ui);
            });
        });
}

fn status_icon(ui: &mut egui::Ui, icon: &str) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), 42.0),
        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
        |ui| {
            ui.label(
                egui::RichText::new(icon)
                    .font(FontId::proportional(32.0)),
            );
        },
    );
}

fn stat_card(ui: &mut egui::Ui, icon: &str, value: &str, label: &str) {
    let dark_mode = ui.visuals().dark_mode;
    egui::Frame::new()
        .fill(theme::bg_card(dark_mode))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(12))
        .stroke(Stroke::new(1.0, theme::border_color(dark_mode)))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 28.0),
                    egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                    |ui| {
                        ui.label(
                            egui::RichText::new(icon)
                                .font(FontId::proportional(20.0)),
                        );
                    },
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(value)
                        .font(FontId::proportional(18.0))
                        .color(theme::text_primary(dark_mode))
                        .strong(),
                );
                ui.label(
                    egui::RichText::new(label)
                        .font(FontId::proportional(10.0))
                        .color(theme::text_secondary(dark_mode)),
                );
            });
        });
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - max_len + 3..])
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

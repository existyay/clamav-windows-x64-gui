use eframe::egui;
use egui::{Color32, CornerRadius, FontId, Stroke};

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
    settings_clamav_dir: String,
}

impl ClamAvApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        config.ensure_dirs();

        let settings_max_size = config.max_file_size_mb.to_string();
        let settings_threads = config.max_scan_threads.to_string();
        let settings_exclude = config.exclude_patterns.join("\n");
        let settings_clamav_dir = config.clamav_dir.to_string_lossy().to_string();

        let mut updater = DatabaseUpdater::default();
        updater.check_database_status(&config);

        Self {
            config,
            scan_engine: ScanEngine::default(),
            updater,
            realtime: RealtimeProtection::default(),
            current_tab: Tab::Dashboard,
            scan_target: String::new(),
            theme_applied: false,
            settings_max_size,
            settings_threads,
            settings_exclude,
            settings_clamav_dir,
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
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
                    egui::RichText::new("Antivirus Scanner")
                        .font(FontId::proportional(12.0))
                        .color(theme::TEXT_SECONDARY),
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
                                theme::TEXT_SECONDARY
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
                    egui::RichText::new("v1.0.0")
                        .font(FontId::proportional(11.0))
                        .color(theme::TEXT_SECONDARY),
                );
            });
        });
    }

    fn dashboard_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(theme::heading("仪表板"));
        ui.add_space(8.0);

        // Status cards row
        ui.horizontal(|ui| {
            // ClamAV status card
            card(ui, 150.0, |ui| {
                ui.label(
                    egui::RichText::new("引擎状态")
                        .font(FontId::proportional(13.0))
                        .color(theme::TEXT_SECONDARY),
                );
                let clamscan_exists = self.config.clamscan_path().exists();
                ui.label(
                    egui::RichText::new(if clamscan_exists {
                        "✅ 就绪"
                    } else {
                        "❌ 未找到"
                    })
                    .font(FontId::proportional(18.0))
                    .color(if clamscan_exists {
                        theme::SUCCESS
                    } else {
                        theme::DANGER
                    }),
                );
            });

            card(ui, 150.0, |ui| {
                ui.label(
                    egui::RichText::new("实时保护")
                        .font(FontId::proportional(13.0))
                        .color(theme::TEXT_SECONDARY),
                );
                let rt_on = self.realtime.state == RealtimeState::Running;
                ui.label(
                    egui::RichText::new(if rt_on { "🛡 已启用" } else { "⚠ 未启用" })
                        .font(FontId::proportional(18.0))
                        .color(if rt_on { theme::SUCCESS } else { theme::WARNING }),
                );
            });

            card(ui, 150.0, |ui| {
                ui.label(
                    egui::RichText::new("病毒库")
                        .font(FontId::proportional(13.0))
                        .color(theme::TEXT_SECONDARY),
                );
                let has_db = self.updater.db_version.is_some();
                ui.label(
                    egui::RichText::new(if has_db { "✅ 已加载" } else { "⚠ 未配置" })
                        .font(FontId::proportional(18.0))
                        .color(if has_db {
                            theme::SUCCESS
                        } else {
                            theme::WARNING
                        }),
                );
            });

            card(ui, 150.0, |ui| {
                ui.label(
                    egui::RichText::new("上次更新")
                        .font(FontId::proportional(13.0))
                        .color(theme::TEXT_SECONDARY),
                );
                let text = self
                    .updater
                    .last_update
                    .clone()
                    .unwrap_or_else(|| "从未".into());
                ui.label(
                    egui::RichText::new(text)
                        .font(FontId::proportional(16.0))
                        .color(theme::TEXT_PRIMARY),
                );
            });
        });

        ui.add_space(16.0);

        // Quick actions
        ui.label(theme::subheading("快速操作"));
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.add(theme::accent_button("🔍 快速扫描")).clicked() {
                self.current_tab = Tab::Scan;
            }
            if ui.add(theme::accent_button("🔄 更新病毒库")).clicked() {
                if self.updater.state != UpdateState::Updating {
                    self.updater.start_update(&self.config);
                }
                self.current_tab = Tab::Update;
            }
            if self.realtime.state != RealtimeState::Running {
                if ui.add(theme::accent_button("🛡 启用实时保护")).clicked() {
                    self.realtime.start(&self.config);
                    self.current_tab = Tab::Realtime;
                }
            }
        });

        ui.add_space(16.0);

        // Recent threats
        ui.label(theme::subheading("最近威胁"));
        ui.add_space(4.0);

        if self.scan_engine.threats.is_empty() {
            ui.label(
                egui::RichText::new("  未发现威胁 ✓")
                    .font(FontId::proportional(14.0))
                    .color(theme::SUCCESS),
            );
        } else {
            let threats = self.scan_engine.threats.clone();
            for (i, threat) in threats.iter().enumerate().take(10) {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!("  {}. ⚠", i + 1))
                            .color(theme::DANGER),
                    );
                    ui.label(
                        egui::RichText::new(&threat.threat_name)
                            .font(FontId::proportional(13.0))
                            .color(theme::TEXT_PRIMARY),
                    );
                    ui.label(
                        egui::RichText::new(truncate_path(&threat.file_path, 50))
                            .font(FontId::proportional(12.0))
                            .color(theme::TEXT_SECONDARY),
                    );
                });
            }
        }
    }

    fn scan_panel(&mut self, ui: &mut egui::Ui) {
        let panel_width = ui.available_width();

        ui.add_space(12.0);
        ui.label(theme::heading("文件扫描"));
        ui.add_space(12.0);

        // Target selection
        ui.label(
            egui::RichText::new("扫描目标")
                .font(FontId::proportional(13.0))
                .color(theme::TEXT_SECONDARY),
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
            if ui.add(theme::accent_button("📁 浏览文件夹")).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.scan_target = folder.to_string_lossy().to_string();
                }
            }
            if ui.add(theme::accent_button("📄 浏览文件")).clicked() {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.scan_target = file.to_string_lossy().to_string();
                }
            }

            match self.scan_engine.state {
                ScanState::Idle | ScanState::Finished => {
                    let can_scan = !self.scan_target.is_empty()
                        && std::path::Path::new(&self.scan_target).exists();
                    if ui.add_enabled(can_scan, theme::accent_button("▶ 开始扫描")).clicked() {
                        self.scan_engine.start_scan(
                            std::path::PathBuf::from(&self.scan_target),
                            &self.config,
                        );
                    }
                }
                ScanState::Scanning => {
                    if ui.add(theme::danger_button("⏹ 停止扫描")).clicked() {
                        self.scan_engine.cancel_scan();
                    }
                }
                ScanState::Paused => {}
            }
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // Stats - use columns to evenly divide available width
        let scanned = self.scan_engine.stats.scanned_files.to_string();
        let infected = self.scan_engine.stats.infected_files.to_string();
        let infected_color = if self.scan_engine.stats.infected_files > 0 { theme::DANGER } else { theme::SUCCESS };
        let elapsed = format!("{:.1}s", self.scan_engine.stats.elapsed_secs);

        ui.columns(3, |cols| {
            cols[0].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::BG_CARD)
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&scanned).font(FontId::proportional(26.0)).color(theme::TEXT_PRIMARY));
                            ui.label(egui::RichText::new("已扫描").font(FontId::proportional(13.0)).color(theme::TEXT_SECONDARY));
                        });
                    });
            });
            cols[1].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::BG_CARD)
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&infected).font(FontId::proportional(26.0)).color(infected_color));
                            ui.label(egui::RichText::new("已感染").font(FontId::proportional(13.0)).color(theme::TEXT_SECONDARY));
                        });
                    });
            });
            cols[2].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::BG_CARD)
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&elapsed).font(FontId::proportional(26.0)).color(theme::TEXT_PRIMARY));
                            ui.label(egui::RichText::new("用时").font(FontId::proportional(13.0)).color(theme::TEXT_SECONDARY));
                        });
                    });
            });
        });

        ui.add_space(12.0);

        // Current file being scanned
        if self.scan_engine.state == ScanState::Scanning {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true), |ui| {
                    ui.label(
                        egui::RichText::new(&self.scan_engine.current_file)
                            .font(FontId::proportional(12.0))
                            .color(theme::TEXT_SECONDARY),
                    );
                });
            });
            ui.add_space(8.0);
        }

        // Scan result banner
        if self.scan_engine.state == ScanState::Finished {
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
                    .fill(Color32::from_rgb(50, 30, 30))
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
                                        .color(theme::TEXT_SECONDARY),
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
        ui.add_space(12.0);
        ui.label(theme::heading("实时保护"));
        ui.add_space(12.0);

        // Status banner
        let is_running = self.realtime.state == RealtimeState::Running;
        egui::Frame::new()
            .fill(if is_running {
                Color32::from_rgb(20, 50, 40)
            } else {
                Color32::from_rgb(50, 35, 20)
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
                            .color(theme::TEXT_SECONDARY),
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
                        .color(theme::TEXT_PRIMARY),
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
                    .fill(theme::BG_CARD)
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new(&self.realtime.scanned_count.to_string())
                                    .font(FontId::proportional(26.0))
                                    .color(theme::TEXT_PRIMARY),
                            );
                            ui.label(
                                egui::RichText::new("已扫描文件")
                                    .font(FontId::proportional(13.0))
                                    .color(theme::TEXT_SECONDARY),
                            );
                        });
                    });
            });
            cols[1].vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(theme::BG_CARD)
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
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
                                    .color(theme::TEXT_SECONDARY),
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
                            .fill(Color32::from_rgb(50, 30, 30))
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
                                                .color(theme::TEXT_SECONDARY),
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
                            theme::TEXT_SECONDARY
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
                        .color(theme::TEXT_PRIMARY),
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
                        .color(theme::TEXT_PRIMARY),
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

        // Update log
        if !self.updater.log_lines.is_empty() {
            ui.add_space(12.0);
            ui.label(theme::subheading("更新日志"));
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.updater.log_lines {
                        ui.label(
                            egui::RichText::new(line)
                                .font(FontId::monospace(12.0))
                                .color(theme::TEXT_SECONDARY),
                        );
                    }
                });
        }
    }

    fn quarantine_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(theme::heading("隔离区"));
        ui.add_space(8.0);

        ui.label(
            egui::RichText::new(format!(
                "隔离目录: {}",
                self.config.quarantine_dir.display()
            ))
            .font(FontId::proportional(12.0))
            .color(theme::TEXT_SECONDARY),
        );

        ui.add_space(8.0);

        if ui.add(theme::accent_button("📁 打开隔离目录")).clicked() {
            let _ = open::that(&self.config.quarantine_dir);
        }

        ui.add_space(12.0);

        // List quarantined files
        let entries: Vec<_> = std::fs::read_dir(&self.config.quarantine_dir)
            .ok()
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext == "quarantine")
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();

        if entries.is_empty() {
            ui.label(
                egui::RichText::new("  隔离区为空 ✓")
                    .font(FontId::proportional(14.0))
                    .color(theme::SUCCESS),
            );
        } else {
            ui.label(
                egui::RichText::new(format!("共 {} 个隔离文件", entries.len()))
                    .font(FontId::proportional(13.0))
                    .color(theme::WARNING),
            );

            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    for entry in &entries {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let size = entry
                            .metadata()
                            .map(|m| format_size(m.len()))
                            .unwrap_or_default();
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("🔒").color(theme::WARNING),
                            );
                            ui.label(
                                egui::RichText::new(&name)
                                    .font(FontId::proportional(13.0))
                                    .color(theme::TEXT_PRIMARY),
                            );
                            ui.label(
                                egui::RichText::new(size)
                                    .font(FontId::proportional(12.0))
                                    .color(theme::TEXT_SECONDARY),
                            );
                            if ui.add(theme::danger_button("🗑 删除")).clicked() {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        });
                        ui.separator();
                    }
                });
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(theme::heading("设置"));
        ui.add_space(12.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // ClamAV directory
            ui.label(theme::subheading("ClamAV 路径"));
            ui.horizontal(|ui| {
                ui.add_sized(
                    [400.0, 26.0],
                    egui::TextEdit::singleline(&mut self.settings_clamav_dir)
                        .font(FontId::proportional(13.0)),
                );
                if ui.add(theme::accent_button("📁 浏览")).clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.settings_clamav_dir = folder.to_string_lossy().to_string();
                    }
                }
            });
            ui.add_space(8.0);

            // Scan options
            ui.label(theme::subheading("扫描选项"));
            ui.add_space(4.0);

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
                self.config.clamav_dir =
                    std::path::PathBuf::from(&self.settings_clamav_dir);
                self.config.database_dir = self.config.clamav_dir.join("database");
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
                    .color(theme::TEXT_SECONDARY),
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
                        theme::TEXT_SECONDARY
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
        if !self.config.persist_realtime_on_exit
            && self.realtime.state == RealtimeState::Running
        {
            self.realtime.stop();
        }
    }
}

impl eframe::App for ClamAvApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx);
            self.theme_applied = true;
        }

        // Poll background tasks
        self.scan_engine.poll_messages();
        self.updater.poll_messages();
        self.realtime.poll_messages();

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
                    theme::BG_PANEL,
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
    egui::Frame::new()
        .fill(theme::BG_CARD)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .stroke(Stroke::new(1.0, Color32::from_rgb(55, 55, 55)))
        .show(ui, |ui| {
            ui.set_min_width(width);
            add_contents(ui);
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

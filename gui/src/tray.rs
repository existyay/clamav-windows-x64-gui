use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, MenuId, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use std::sync::mpsc;

pub enum TrayAction {
    ShowWindow,
    StopRealtime,
    ExitApp,
}

pub struct SystemTray {
    _tray: TrayIcon,
    _show_item: MenuItem,
    _stop_item: MenuItem,
    _exit_item: MenuItem,
    show_id: MenuId,
    stop_id: MenuId,
    exit_id: MenuId,
    rx: mpsc::Receiver<MenuEvent>,
}

impl SystemTray {
    pub fn new(ctx: egui::Context) -> Option<Self> {
        let menu = Menu::new();

        let show_item = MenuItem::new("显示主界面", true, None);
        let stop_item = MenuItem::new("退出实时保护", true, None);
        let exit_item = MenuItem::new("退出程序", true, None);

        let show_id = show_item.id().clone();
        let stop_id = stop_item.id().clone();
        let exit_id = exit_item.id().clone();

        let sep1 = PredefinedMenuItem::separator();
        let sep2 = PredefinedMenuItem::separator();
        menu.append(&show_item).ok()?;
        menu.append(&sep1).ok()?;
        menu.append(&stop_item).ok()?;
        menu.append(&sep2).ok()?;
        menu.append(&exit_item).ok()?;

        let icon = create_shield_icon();

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("ClamAV 实时保护运行中")
            .with_icon(icon)
            .build()
            .ok()?;

        // Use a custom event handler that wakes the egui event loop.
        // Without this, update() is never called while the window is
        // hidden (Visible(false)) on Windows, so tray clicks are lost.
        let (tx, rx) = mpsc::channel();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let _ = tx.send(event);
            ctx.request_repaint();
        }));

        Some(Self {
            _tray: tray,
            _show_item: show_item,
            _stop_item: stop_item,
            _exit_item: exit_item,
            show_id,
            stop_id,
            exit_id,
            rx,
        })
    }

    pub fn poll_event(&self) -> Option<TrayAction> {
        while let Ok(event) = self.rx.try_recv() {
            if event.id == self.exit_id {
                return Some(TrayAction::ExitApp);
            }
            if event.id == self.stop_id {
                return Some(TrayAction::StopRealtime);
            }
            if event.id == self.show_id {
                return Some(TrayAction::ShowWindow);
            }
        }
        None
    }
}

/// 生成 32x32 绿色圆形图标（表示保护运行中）
fn create_shield_icon() -> Icon {
    let size: u32 = 32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let center = size as f32 / 2.0;
    let radius = center - 2.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center + 0.5;
            let dy = y as f32 - center + 0.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = ((y * size + x) * 4) as usize;

            if dist <= radius {
                // 绿色填充
                rgba[idx] = 76;       // R
                rgba[idx + 1] = 175;  // G
                rgba[idx + 2] = 80;   // B
                rgba[idx + 3] = 255;  // A
            } else if dist <= radius + 1.0 {
                // 抗锯齿边缘
                let alpha = ((radius + 1.0 - dist) * 255.0) as u8;
                rgba[idx] = 76;
                rgba[idx + 1] = 175;
                rgba[idx + 2] = 80;
                rgba[idx + 3] = alpha;
            }
        }
    }

    // 在圆内绘制白色盾牌轮廓
    draw_shield_outline(&mut rgba, size);

    Icon::from_rgba(rgba, size, size).expect("Failed to create tray icon")
}

/// 在 RGBA 缓冲区上绘制简化的盾牌形状
fn draw_shield_outline(rgba: &mut [u8], size: u32) {
    let cx = size as f32 / 2.0;

    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;

            // 盾牌形状：上宽下窄，底部收尖
            let in_shield = if fy >= 6.0 && fy < 10.0 {
                (fx - cx).abs() < 9.0
            } else if fy >= 10.0 && fy < 22.0 {
                let width = 9.0 - (fy - 10.0) * 0.4;
                (fx - cx).abs() < width
            } else if fy >= 22.0 && fy < 27.0 {
                let width = 4.2 - (fy - 22.0) * 0.84;
                width > 0.0 && (fx - cx).abs() < width
            } else {
                false
            };

            if in_shield {
                let idx = ((y * size + x) * 4) as usize;
                rgba[idx] = 255;     // R
                rgba[idx + 1] = 255; // G
                rgba[idx + 2] = 255; // B
                rgba[idx + 3] = 255; // A
            }
        }
    }
}

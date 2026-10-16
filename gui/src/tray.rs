//! System tray icon and its context menu.
//!
//! The icon is rasterised here rather than loaded from a file so the binary
//! stays self-contained. Failure to create the tray (a locked-up shell, a
//! headless session) is reported as `None` and the caller must keep the normal
//! window close behaviour — hiding the window in that case would leave the app
//! with no way back except Task Manager.

use eframe::egui;
use std::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub enum TrayAction {
    ShowWindow,
    StopRealtime,
    ExitApp,
}

pub struct SystemTray {
    tray: TrayIcon,
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
        let stop_item = MenuItem::new("停止实时保护", true, None);
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

        let icon = create_icon()?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("ClamAV 安全中心")
            .with_icon(icon)
            .build()
            .ok()?;

        // A custom handler is required: without it `update()` is never called
        // while the window is hidden (`Visible(false)`), so tray clicks would be
        // dropped on Windows.
        let (tx, rx) = mpsc::channel();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let _ = tx.send(event);
            ctx.request_repaint();
        }));

        Some(Self {
            tray,
            _show_item: show_item,
            _stop_item: stop_item,
            _exit_item: exit_item,
            show_id,
            stop_id,
            exit_id,
            rx,
        })
    }

    /// Update the hover text, e.g. to reflect whether protection is active.
    pub fn set_tooltip(&mut self, text: &str) {
        let _ = self.tray.set_tooltip(Some(text));
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

/// Rasterise the app mark for the tray.
fn create_icon() -> Option<Icon> {
    const SIZE: u32 = 32;
    let rgba = crate::icons::app_icon_rgba(SIZE);
    Icon::from_rgba(rgba, SIZE, SIZE).ok()
}

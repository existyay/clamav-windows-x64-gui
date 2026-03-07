#![windows_subsystem = "windows"]

mod scanner;
mod updater;
mod realtime;
mod app;
mod theme;
mod config;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ClamAV Scanner")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ClamAV Scanner",
        options,
        Box::new(|cc| Ok(Box::new(app::ClamAvApp::new(cc)))),
    )
}

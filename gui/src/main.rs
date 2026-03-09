#![windows_subsystem = "windows"]

mod scanner;
mod updater;
mod realtime;
mod app;
mod theme;
mod config;
mod embedded;
mod tray;

use eframe::egui;

/// Prevent duplicate instances using a Windows named mutex.
/// Returns the handle on success (keep alive for lifetime of the process).
/// Returns `None` if another instance is already running.
#[cfg(windows)]
fn acquire_single_instance() -> Option<*mut std::ffi::c_void> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = "Global\\ClamAV_GUI_SingleInstance\0"
        .encode_utf16()
        .collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // Another instance owns the mutex
        return None;
    }
    Some(handle)
}

fn main() -> eframe::Result<()> {
    // --- Single-instance guard ---
    #[cfg(windows)]
    let _mutex = match acquire_single_instance() {
        Some(h) => h,
        None => {
            // Another instance is running – show a message box and exit
            #[cfg(windows)]
            {
                use windows_sys::Win32::Foundation::HWND;
                let text: Vec<u16> = "ClamAV Scanner 已在运行中。\n请检查系统托盘区域。\0"
                    .encode_utf16()
                    .collect();
                let caption: Vec<u16> = "ClamAV Scanner\0".encode_utf16().collect();
                unsafe {
                    windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                        0 as HWND,
                        text.as_ptr(),
                        caption.as_ptr(),
                        windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                            | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION,
                    );
                }
            }
            return Ok(());
        }
    };

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

#![windows_subsystem = "windows"]

mod scanner;
mod updater;
mod realtime;
mod app;
mod bootstrap;
mod theme;
mod widgets;
mod icons;
mod config;
mod embedded;
mod tray;

use eframe::egui;

/// Outcome of the single-instance check.
enum InstanceGuard {
    /// We own the guard; the handle must stay alive for the process lifetime.
    Acquired(*mut std::ffi::c_void),
    /// Another instance already holds it.
    AlreadyRunning,
    /// The guard could not be created (unusual permissions, an odd session
    /// type). Startup continues rather than refusing to run — see below.
    Unavailable,
}

/// Handle of the single-instance mutex.
///
/// Kept in a global rather than only in `main`'s local scope because
/// "restart as administrator" has to **release** the lock before the elevated
/// copy starts. Otherwise that copy finds the mutex still held, reports
/// "already running" and exits — and since this instance is quitting at the same
/// time, the user is left with no window at all.
#[cfg(windows)]
static INSTANCE_HANDLE: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Drop the single-instance lock so another copy can claim it.
#[cfg(windows)]
fn release_single_instance() {
    use std::sync::atomic::Ordering;

    let handle = INSTANCE_HANDLE.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if !handle.is_null() {
        // Closing the last handle destroys the mutex, so the next
        // `CreateMutexW` succeeds instead of reporting an existing instance.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    }
}

/// Take the lock back when a handover did not actually happen — for example the
/// user dismissed the UAC prompt — so this instance still behaves like the only
/// one.
#[cfg(windows)]
fn reacquire_single_instance() {
    use std::sync::atomic::Ordering;

    if !INSTANCE_HANDLE.load(Ordering::SeqCst).is_null() {
        return;
    }
    if let InstanceGuard::Acquired(handle) = acquire_single_instance() {
        INSTANCE_HANDLE.store(handle, Ordering::SeqCst);
    }
}

/// Prevent duplicate instances using a Windows named mutex.
///
/// Two things matter here:
///
/// * The mutex is **session-local** (no `Global\` prefix). A `Global\` object can
///   fail with `ERROR_ACCESS_DENIED` for a non-elevated process, and the old
///   code treated *any* failure as "already running" — so the app could refuse
///   to start at all and just print a wrong message box. A failure to create the
///   guard now simply means "run without a guard".
/// * `GetLastError` is only consulted when creation actually returned a handle.
#[cfg(windows)]
fn acquire_single_instance() -> InstanceGuard {
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = "ClamAV_GUI_SingleInstance_v1\0".encode_utf16().collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };

    if handle.is_null() {
        return InstanceGuard::Unavailable;
    }

    if unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_ALREADY_EXISTS {
        // We still own a handle; release it before reporting.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        return InstanceGuard::AlreadyRunning;
    }

    InstanceGuard::Acquired(handle)
}

#[cfg(not(windows))]
fn acquire_single_instance() -> InstanceGuard {
    InstanceGuard::Unavailable
}

/// Install a panic hook that leaves a trace and tells the user.
///
/// The binary is built with `windows_subsystem = "windows"`, so a panic would
/// otherwise make the window vanish with no explanation anywhere.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        let message = info.to_string();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());

        let report = format!(
            "ClamAV 安全中心 发生内部错误\n时间: {}\n位置: {}\n详情: {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            location,
            message
        );

        // Best-effort log next to the executable.
        let path = config::base_dir().join("crash.log");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, report.as_bytes()));

        let short = format!(
            "程序遇到内部错误，详情已写入:\n{}\n\n{}",
            config::display_path(&path),
            message
        );

        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::HWND;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                MessageBoxW, MB_ICONERROR, MB_OK,
            };

            let text: Vec<u16> = short.encode_utf16().chain(std::iter::once(0)).collect();
            let caption: Vec<u16> = "ClamAV 安全中心\0".encode_utf16().collect();
            unsafe {
                MessageBoxW(
                    0 as HWND,
                    text.as_ptr(),
                    caption.as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }

        default_hook(info);
    }));
}

#[cfg(windows)]
fn show_already_running_message() {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONINFORMATION, MB_OK,
    };

    let text: Vec<u16> = "ClamAV 安全中心 已在运行中。\n请查看系统托盘图标。\0"
        .encode_utf16()
        .collect();
    let caption: Vec<u16> = "ClamAV 安全中心\0".encode_utf16().collect();

    unsafe {
        MessageBoxW(
            0 as HWND,
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

/// Whether this process already holds administrator rights.
///
/// The build attaches no manifest requesting elevation (see `build.rs`), so the
/// app starts with the rights of whoever launched it. Some locations simply
/// cannot be read or quarantined without elevation, so the settings screen
/// offers to relaunch for those cases.
///
/// The answer cannot change while the process lives, and the UI asks on every
/// frame, so it is cached — that also means the token handle is opened once
/// rather than sixty times a second.
#[cfg(windows)]
pub(crate) fn is_elevated() -> bool {
    static ELEVATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ELEVATED.get_or_init(query_elevation)
}

#[cfg(windows)]
fn query_elevation() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();

    // SAFETY: `token` is a valid out-parameter, and the information buffer is
    // exactly the size the API documents for `TokenElevation`.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION {
            TokenIsElevated: 0,
        };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);

        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub(crate) fn is_elevated() -> bool {
    false
}

/// Close this instance and start a new one through the shell's `runas` verb.
///
/// Returns once the shell has accepted the request; the caller is expected to
/// request a normal exit straight afterwards so the elevated copy can take over
/// the single-instance lock.
#[cfg(windows)]
pub(crate) fn relaunch_as_admin() -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;

    /// `ShellExecuteW` returns a value at or below this to signal failure.
    const SHELL_SUCCESS_THRESHOLD: isize = 32;
    const SW_SHOWNORMAL: i32 = 1;

    let exe = std::env::current_exe().map_err(|e| format!("无法定位程序路径: {}", e))?;

    let to_wide = |text: &std::ffi::OsStr| -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        text.encode_wide().chain(std::iter::once(0)).collect()
    };

    let verb = to_wide(std::ffi::OsStr::new("runas"));
    let file = to_wide(exe.as_os_str());

    // Release the lock *before* the new process starts. If it were still held,
    // the elevated copy would see an existing instance, show "already running"
    // and exit — while this instance quits at the same time, leaving no window.
    release_single_instance();

    // SAFETY: all pointers are NUL-terminated wide strings that outlive the
    // call, and the two optional arguments are passed as null.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;

    if result <= SHELL_SUCCESS_THRESHOLD {
        // Nothing was launched, so take the lock back and carry on as before.
        reacquire_single_instance();

        // 5 (SE_ERR_ACCESSDENIED) is what a cancelled UAC prompt reports.
        Err(format!(
            "未能获得管理员权限（代码 {}）。可能取消了用户账户控制提示。",
            result
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub(crate) fn relaunch_as_admin() -> Result<(), String> {
    Err("仅 Windows 支持以管理员身份重启。".to_string())
}

fn main() -> eframe::Result<()> {
    install_panic_hook();

    // --- Single-instance guard ---
    //
    // The handle is parked in `INSTANCE_HANDLE` instead of a local: it has to
    // stay alive for the whole process, and the "restart as administrator" path
    // needs to reach it so it can release the lock during the handover.
    #[cfg(windows)]
    match acquire_single_instance() {
        InstanceGuard::Acquired(handle) => {
            INSTANCE_HANDLE.store(handle, std::sync::atomic::Ordering::SeqCst);
        }
        InstanceGuard::AlreadyRunning => {
            show_already_running_message();
            return Ok(());
        }
        InstanceGuard::Unavailable => {}
    }

    // Settings are read before the window exists so the remembered geometry can
    // be applied on the first frame.
    let config = config::AppConfig::load();

    let icon_size = 256;
    let icon = egui::IconData {
        rgba: icons::app_icon_rgba(icon_size),
        width: icon_size,
        height: icon_size,
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("ClamAV 安全中心")
        .with_app_id("clamav-safety-center")
        .with_icon(std::sync::Arc::new(icon))
        .with_inner_size([config.window.width, config.window.height])
        .with_min_inner_size([config::MIN_WINDOW_W, config::MIN_WINDOW_H]);

    if config.window.maximized {
        viewport = viewport.with_maximized(true);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "ClamAV 安全中心",
        options,
        Box::new(move |cc| Ok(Box::new(app::ClamAvApp::new(cc, config)))),
    )
}

#[cfg(all(windows, test))]
mod instance_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Store an acquired handle, reporting whether the lock was actually won.
    fn take(guard: InstanceGuard) -> bool {
        match guard {
            InstanceGuard::Acquired(handle) => {
                INSTANCE_HANDLE.store(handle, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    #[test]
    fn the_guard_is_exclusive_and_survives_a_handover() {
        // A real instance may be running on a developer's machine, in which case
        // there is nothing this test can assert about the lock.
        if !take(acquire_single_instance()) {
            eprintln!("skipping: another instance already holds the lock");
            return;
        }

        // While we hold it, a duplicate must be turned away.
        assert!(
            matches!(acquire_single_instance(), InstanceGuard::AlreadyRunning),
            "a second instance should not be allowed to start"
        );

        // The handover: releasing must let the elevated copy claim the lock.
        // Without this, "restart as administrator" left the user with no window,
        // because the new process saw the old lock and quit while this one was
        // quitting too.
        release_single_instance();
        assert!(
            take(acquire_single_instance()),
            "the elevated copy could not claim the lock after release"
        );

        // Reacquiring while the lock is already held must be a no-op, so a
        // cancelled UAC prompt cannot leave a second handle behind.
        reacquire_single_instance();
        assert!(
            matches!(acquire_single_instance(), InstanceGuard::AlreadyRunning),
            "reacquire should not have dropped the lock"
        );

        release_single_instance();
    }
}

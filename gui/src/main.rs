#![windows_subsystem = "windows"]

mod app;
mod bootstrap;
mod config;
mod embedded;
mod icons;
mod realtime;
mod scanner;
mod theme;
mod tray;
mod updater;
mod widgets;

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

/// Name of the event a second launch uses to ask the running copy to show itself.
#[cfg(windows)]
const WAKE_EVENT_NAME: &str = "ClamAV_GUI_ShowWindow_v1";

/// Handle of that event, held by the instance that won the single-instance lock.
#[cfg(windows)]
static WAKE_EVENT: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Create the (auto-reset, initially unsignalled) wake event.
#[cfg(windows)]
fn create_wake_event() -> *mut std::ffi::c_void {
    use windows_sys::Win32::System::Threading::CreateEventW;

    /// `CreateEventW`: not manual-reset, initially unsignalled.
    const AUTO_RESET: i32 = 0;
    const NOT_SIGNALLED: i32 = 0;

    let name: Vec<u16> = WAKE_EVENT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe { CreateEventW(std::ptr::null(), AUTO_RESET, NOT_SIGNALLED, name.as_ptr()) }
}

/// Ask the instance that holds the lock to bring its window back.
///
/// Without this a second launch left the user with a modal "already running"
/// dialog and a second live process, while the window they actually wanted stayed
/// minimised in the tray. The launch is the user's request to see the app, so it
/// is treated as one.
#[cfg(windows)]
fn signal_running_instance() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};

    let name: Vec<u16> = WAKE_EVENT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if !handle.is_null() {
        unsafe {
            SetEvent(handle);
            CloseHandle(handle);
        }
    }
}

/// Consume a pending "show yourself" request, if the event exists.
#[cfg(windows)]
pub(crate) fn take_wake_request() -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    /// `WAIT_OBJECT_0` from `Win32::System::Threading`.
    const WAIT_OBJECT_0: u32 = 0;

    let handle = WAKE_EVENT.load(std::sync::atomic::Ordering::SeqCst);
    if handle.is_null() {
        return false;
    }

    // Zero timeout: an auto-reset event clears itself once the wait succeeds, so
    // a request that arrives while the window is visible is simply dropped.
    unsafe { WaitForSingleObject(handle, 0) == WAIT_OBJECT_0 }
}

#[cfg(not(windows))]
pub(crate) fn take_wake_request() -> bool {
    false
}

/// Parent process of this process, as `(pid, image name)`.
///
/// Recorded in the launch log because "it opened by itself again" is only
/// answerable if the log says *who started it*: `explorer.exe` is the user
/// double-clicking, `powershell.exe`/`cmd.exe` is a script, `taskeng.exe` or
/// `svchost.exe` would be a scheduled task. A toolhelp snapshot is the only
/// dependency-free way to read that.
#[cfg(windows)]
fn parent_process() -> Option<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let name_of = |raw: &[u16; 260]| -> String {
        let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
        String::from_utf16_lossy(&raw[..end])
    };

    // SAFETY: standard toolhelp enumeration. The snapshot handle is checked
    // against `INVALID_HANDLE_VALUE` and closed in every path below, and the
    // entry buffer is a plain `PROCESSENTRY32W` whose `dwSize` the API requires
    // to be set before the first call.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return None;
        }

        let mut rows: Vec<(u32, u32, String)> = Vec::new();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                rows.push((
                    entry.th32ProcessID,
                    entry.th32ParentProcessID,
                    name_of(&entry.szExeFile),
                ));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);

        let me = std::process::id();
        let parent_pid = rows
            .iter()
            .find(|(pid, _, _)| *pid == me)
            .map(|(_, parent, _)| *parent)
            .filter(|parent| *parent != 0 && *parent != me)?;
        let parent_name = rows
            .iter()
            .find(|(pid, _, _)| *pid == parent_pid)
            .map(|(_, _, name)| name.clone())
            .unwrap_or_default();
        Some((parent_pid, parent_name))
    }
}

#[cfg(not(windows))]
fn parent_process() -> Option<(u32, String)> {
    None
}

/// Append one line to `logs\launch.log` describing what this launch decided.
///
/// The app has no other record of how often, when and by whom it was started, so
/// a report of "it keeps opening by itself" could not be checked against
/// anything. Each line carries the timestamp, this process id, the parent
/// process, the decision and the executable that was started. Best effort
/// throughout: diagnostics must never be able to break startup.
pub(crate) fn log_launch(decision: &str, detail: &str) {
    let path = config::base_dir().join("logs").join("launch.log");

    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    // Keep the file bounded; it is a diagnostic, not an audit trail.
    const MAX_BYTES: u64 = 256 * 1024;
    if std::fs::metadata(&path)
        .map(|meta| meta.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = std::fs::remove_file(&path);
    }

    let mut fields = format!("decision={decision} pid={}", std::process::id());
    if let Some((parent_pid, parent_name)) = parent_process() {
        fields.push_str(&format!(" ppid={parent_pid} parent={parent_name}"));
    }
    if !detail.is_empty() {
        fields.push(' ');
        fields.push_str(detail);
    }

    let exe = std::env::current_exe()
        .map(|path| config::display_path(&path))
        .unwrap_or_else(|_| "?".to_string());
    let line = format!(
        "{} {} exe={}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        fields,
        exe
    );

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()));
}

/// Outcome of the lock-file fallback used when the named mutex cannot exist.
#[cfg(windows)]
enum LockFileOutcome {
    /// We hold it. The file must stay open for the process lifetime, which is
    /// what makes the sharing violation below happen for everyone else.
    Acquired(std::fs::File),
    /// Another process already holds it.
    Held,
    /// The lock could not be created for some other reason (a read-only account
    /// directory, for instance), so there is no guard at all.
    Unavailable(String),
}

/// Hold `%APPDATA%\ClamAV GUI\instance.lock` open exclusively.
///
/// `CreateMutexW` is the primary guard, but it can fail to return a handle at
/// all in unusual security contexts. Startup used to continue in that case,
/// which meant *every* launch became its own instance — precisely the "it opened
/// twice again" symptom. `share_mode(0)` is the Windows way of saying "nobody
/// else may open this file", so the second copy gets `ERROR_SHARING_VIOLATION`.
#[cfg(windows)]
fn acquire_fallback_lock() -> LockFileOutcome {
    use std::os::windows::fs::OpenOptionsExt;

    /// `ERROR_SHARING_VIOLATION`, i.e. somebody holds the file.
    const SHARING_VIOLATION: i32 = 32;

    let Some(path) = config::AppConfig::fallback_config_path()
        .map(|config| config.with_file_name("instance.lock"))
    else {
        return LockFileOutcome::Unavailable("没有可用的用户目录".to_string());
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&path);

    match opened {
        Ok(file) => LockFileOutcome::Acquired(file),
        Err(err) if err.raw_os_error() == Some(SHARING_VIOLATION) => LockFileOutcome::Held,
        Err(err) => LockFileOutcome::Unavailable(err.to_string()),
    }
}

/// Keeps the fallback lock file open for the whole process lifetime.
#[cfg(windows)]
static FALLBACK_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

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
            use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

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

/// Let the running instance raise its window.
///
/// A process may only steal the foreground if it is *given* the right, and the
/// freshly launched copy is the one Windows currently grants it to. Handing it
/// over means the other instance's `Focus` restores the window properly instead
/// of merely flashing its taskbar button.
#[cfg(windows)]
fn allow_running_instance_to_raise_itself() {
    use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

    /// `ASFW_ANY` from `Win32::UI::WindowsAndMessaging`, spelled out so the extra
    /// windows-sys feature is not needed for one constant.
    const ASFW_ANY: u32 = u32::MAX;

    unsafe { AllowSetForegroundWindow(ASFW_ANY) };
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

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
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
            // The event a later launch signals to ask for the window back.
            WAKE_EVENT.store(create_wake_event(), std::sync::atomic::Ordering::SeqCst);
            log_launch("owned", "");
        }
        InstanceGuard::AlreadyRunning => {
            // This launch is the user asking to see the app, so hand it over
            // rather than rejecting it: the copy that owns the lock brings its
            // window back and this one exits straight away. The log line records
            // who asked, which is the whole point of the exercise — a reader can
            // tell a double-click (`parent=explorer.exe`) from a script.
            allow_running_instance_to_raise_itself();
            signal_running_instance();
            log_launch("woken-existing", "");
            return Ok(());
        }
        InstanceGuard::Unavailable => {
            // No mutex: fall back to the lock file instead of starting unguarded.
            // Silently starting unguarded is what lets one launch turn into many.
            match acquire_fallback_lock() {
                LockFileOutcome::Acquired(file) => {
                    let _ = FALLBACK_LOCK.set(file);
                    WAKE_EVENT.store(create_wake_event(), std::sync::atomic::Ordering::SeqCst);
                    log_launch("owned-fallback", "named mutex unavailable");
                }
                LockFileOutcome::Held => {
                    allow_running_instance_to_raise_itself();
                    signal_running_instance();
                    log_launch("woken-existing", "named mutex unavailable, lock file held");
                    return Ok(());
                }
                LockFileOutcome::Unavailable(reason) => {
                    log_launch("owned-unguarded", &format!("no guard available: {reason}"));
                }
            }
        }
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

    /// The lock-file fallback exists for the case where the named mutex cannot
    /// be created at all. A fallback that admits two copies would defeat the
    /// point, so it has to be exclusive in the same way.
    #[test]
    fn the_fallback_lock_is_exclusive() {
        let LockFileOutcome::Acquired(_held) = acquire_fallback_lock() else {
            // Somebody else holds it right now, which is itself proof that the
            // lock works. (A real instance uses the mutex, not this file.)
            return;
        };

        assert!(
            matches!(acquire_fallback_lock(), LockFileOutcome::Held),
            "a second holder of the fallback lock should have been turned away"
        );
    }

    /// The event that turns a second launch into "show the window" must be
    /// reachable by name: the launching copy only ever opens it by name, never
    /// by handle, so a typo or a `#[cfg]` mismatch would silently do nothing.
    #[test]
    fn a_second_launch_is_able_to_wake_the_running_copy() {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};

        let handle = create_wake_event();
        assert!(!handle.is_null(), "the wake event could not be created");

        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // A real instance is running and owns this event; leave it alone.
            unsafe { CloseHandle(handle) };
            eprintln!("skipping: a running instance owns the wake event");
            return;
        }

        WAKE_EVENT.store(handle, Ordering::SeqCst);

        // Nothing has asked for the window yet.
        assert!(!take_wake_request(), "spurious wake-up");

        signal_running_instance();
        assert!(
            take_wake_request(),
            "the running copy was not woken by a second launch"
        );

        // Auto-reset: one launch is one request.
        assert!(!take_wake_request(), "the request was not consumed");

        let handle = WAKE_EVENT.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !handle.is_null() {
            unsafe { CloseHandle(handle) };
        }
    }
}

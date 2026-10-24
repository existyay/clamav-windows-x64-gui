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
#[cfg(windows)]
enum InstanceGuard {
    /// We own the guard; the handle must stay alive for the process lifetime.
    Acquired(*mut std::ffi::c_void, std::fs::File),
    /// Another instance already holds it.
    AlreadyRunning,
    /// No exclusive file lock could be obtained; startup must fail closed.
    Unavailable(String),
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

/// All new instances participate in the same file-lock protocol. The named
/// mutex is retained only for compatibility with older versions.
#[cfg(windows)]
static INSTANCE_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

#[cfg(windows)]
const INSTANCE_MUTEX_NAME: &str = "ClamAV_GUI_SingleInstance_v1";

/// Close the legacy mutex before the file, so a new file-lock owner never sees
/// our stale mutex during handover. Serialize release/reacquire with the file slot.
#[cfg(windows)]
fn release_instance_locks(
    file: &std::sync::Mutex<Option<std::fs::File>>,
    mutex: &std::sync::atomic::AtomicPtr<std::ffi::c_void>,
) {
    let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let handle = mutex.swap(std::ptr::null_mut(), std::sync::atomic::Ordering::SeqCst);
    if !handle.is_null() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    }
    file.take();
}

#[cfg(windows)]
fn release_single_instance() {
    release_instance_locks(&INSTANCE_FILE, &INSTANCE_HANDLE);
}

/// Restore both guards after a failed handover. Failure must never leave the
/// existing GUI running without the common file lock.
#[cfg(windows)]
fn reacquire_instance_locks(
    file: &std::sync::Mutex<Option<std::fs::File>>,
    mutex: &std::sync::atomic::AtomicPtr<std::ffi::c_void>,
    acquire: impl FnOnce() -> InstanceGuard,
) -> Result<(), String> {
    let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if file.is_some() {
        return Ok(());
    }
    match acquire() {
        InstanceGuard::Acquired(handle, acquired_file) => {
            mutex.store(handle, std::sync::atomic::Ordering::SeqCst);
            *file = Some(acquired_file);
            Ok(())
        }
        InstanceGuard::AlreadyRunning => Err("另一实例已取得单实例锁".to_string()),
        InstanceGuard::Unavailable(reason) => Err(reason),
    }
}

#[cfg(windows)]
fn reacquire_single_instance() -> Result<(), String> {
    reacquire_instance_locks(&INSTANCE_FILE, &INSTANCE_HANDLE, acquire_single_instance)
}

#[cfg(windows)]
fn acquire_single_instance() -> InstanceGuard {
    let Some(path) = config::AppConfig::fallback_config_path()
        .map(|config| config.with_file_name("instance.lock"))
    else {
        return InstanceGuard::Unavailable("没有可用的用户目录，无法创建单实例锁".to_string());
    };
    acquire_single_instance_at(&path, INSTANCE_MUTEX_NAME)
}

/// Take the common lock first, even if the legacy mutex is available. Otherwise
/// a mutex owner and a file-only owner could both run. A mutex creation failure
/// is safe only because we already hold the exclusive file lock.
#[cfg(windows)]
fn acquire_single_instance_at(path: &std::path::Path, mutex_name: &str) -> InstanceGuard {
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let file = match acquire_file_lock(path) {
        LockFileOutcome::Acquired(file) => file,
        LockFileOutcome::Held => return InstanceGuard::AlreadyRunning,
        LockFileOutcome::Unavailable(reason) => return InstanceGuard::Unavailable(reason),
    };
    let name: Vec<u16> = mutex_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if !handle.is_null()
        && unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_ALREADY_EXISTS
    {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        return InstanceGuard::AlreadyRunning;
    }
    InstanceGuard::Acquired(handle, file)
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
    create_wake_event_named(WAKE_EVENT_NAME)
}

#[cfg(windows)]
fn create_wake_event_named(event_name: &str) -> *mut std::ffi::c_void {
    use windows_sys::Win32::System::Threading::CreateEventW;

    /// `CreateEventW`: not manual-reset, initially unsignalled.
    const AUTO_RESET: i32 = 0;
    const NOT_SIGNALLED: i32 = 0;

    let name: Vec<u16> = event_name
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
    signal_wake_event_named(WAKE_EVENT_NAME);
}

#[cfg(windows)]
fn signal_wake_event_named(event_name: &str) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};

    let name: Vec<u16> = event_name
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

/// Outcome of the common exclusive file lock used by every new instance.
#[cfg(windows)]
enum LockFileOutcome {
    /// We hold it. The file must stay open for the process lifetime, which is
    /// what makes the sharing violation below happen for everyone else.
    Acquired(std::fs::File),
    /// Another process already holds it.
    Held,
    /// The lock could not be created; the caller must refuse to run.
    Unavailable(String),
}

/// `share_mode(0)` denies every other opener, including elevated copies.
/// Never remove the lock file: its open handle, not its existence, is the lock.
#[cfg(windows)]
fn acquire_file_lock(path: &std::path::Path) -> LockFileOutcome {
    use std::os::windows::fs::OpenOptionsExt;

    /// `ERROR_SHARING_VIOLATION`, i.e. somebody holds the file.
    const SHARING_VIOLATION: i32 = 32;

    if let Some(dir) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(dir) {
            return LockFileOutcome::Unavailable(format!("无法创建单实例锁目录: {err}"));
        }
    }

    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path);

    match opened {
        Ok(file) => LockFileOutcome::Acquired(file),
        Err(err) if err.raw_os_error() == Some(SHARING_VIOLATION) => LockFileOutcome::Held,
        Err(err) => LockFileOutcome::Unavailable(err.to_string()),
    }
}

/// Explain a fail-closed decision before exiting a windowless executable.
#[cfg(windows)]
fn report_instance_error(reason: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    log_launch("lock-failed", reason);
    let text: Vec<u16> = format!("无法安全持有单实例锁，程序将退出。\n\n{reason}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let caption: Vec<u16> = "ClamAV 安全中心\0".encode_utf16().collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
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
        // Another launch may have won during the UAC prompt. Never keep this
        // GUI alive without the common lock if restoring ownership fails.
        if let Err(reason) = reacquire_single_instance() {
            report_instance_error(&format!("管理员重启失败，且无法重新取得单实例锁: {reason}"));
            std::process::exit(1);
        }

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
        InstanceGuard::Acquired(handle, file) => {
            *INSTANCE_FILE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(file);
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
        InstanceGuard::Unavailable(reason) => {
            report_instance_error(&reason);
            std::process::exit(1);
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

    struct IsolatedInstance {
        path: std::path::PathBuf,
        name: String,
        file: std::sync::Mutex<Option<std::fs::File>>,
        mutex: std::sync::atomic::AtomicPtr<std::ffi::c_void>,
    }

    impl IsolatedInstance {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let name = format!(
                "ClamAV_GUI_Test_{}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            Self {
                path: std::env::temp_dir().join(&name).join("instance.lock"),
                name,
                file: std::sync::Mutex::new(None),
                mutex: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
            }
        }

        fn acquire(&self) -> InstanceGuard {
            acquire_single_instance_at(&self.path, &self.name)
        }

        fn restore(&self) -> Result<(), String> {
            reacquire_instance_locks(&self.file, &self.mutex, || self.acquire())
        }
    }

    impl Drop for IsolatedInstance {
        fn drop(&mut self) {
            release_instance_locks(&self.file, &self.mutex);
            // The exact unique test directory, never the production lock path.
            let directory = self.path.parent().unwrap();
            assert!(directory.is_absolute());
            assert_eq!(directory.file_name().unwrap().to_str().unwrap(), self.name);
            let _ = std::fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn the_guard_is_exclusive_and_survives_a_handover() {
        let instance = IsolatedInstance::new();
        instance.restore().expect("initial lock");
        assert!(matches!(instance.acquire(), InstanceGuard::AlreadyRunning));
        release_instance_locks(&instance.file, &instance.mutex);
        instance.restore().expect("handover lock");
        instance.restore().expect("idempotent restore");
        assert!(matches!(instance.acquire(), InstanceGuard::AlreadyRunning));
        release_instance_locks(&instance.file, &instance.mutex);
        instance.restore().expect("cancelled UAC restores the lock");
    }

    #[test]
    fn common_file_lock_excludes_both_mutex_and_file_only_owners() {
        let instance = IsolatedInstance::new();
        let LockFileOutcome::Acquired(file) = acquire_file_lock(&instance.path) else {
            panic!("isolated file lock unavailable");
        };
        assert!(matches!(instance.acquire(), InstanceGuard::AlreadyRunning));
        drop(file);
        instance.restore().unwrap();
        assert!(matches!(
            acquire_file_lock(&instance.path),
            LockFileOutcome::Held
        ));
    }

    #[test]
    fn mutex_failure_still_requires_the_common_file_lock() {
        let instance = IsolatedInstance::new();
        // An event with this unique name makes CreateMutexW fail with a type
        // collision, without changing any production mutex or event.
        let event = create_wake_event_named(&instance.name);
        assert!(!event.is_null());
        instance.restore().unwrap();
        assert!(instance.mutex.load(Ordering::SeqCst).is_null());
        assert!(matches!(instance.acquire(), InstanceGuard::AlreadyRunning));
        release_instance_locks(&instance.file, &instance.mutex);
        instance
            .restore()
            .expect("file-only handover must release the file");
        unsafe { windows_sys::Win32::Foundation::CloseHandle(event) };
    }

    #[test]
    fn unavailable_lock_and_lost_uac_handover_fail_closed() {
        let instance = IsolatedInstance::new();
        std::fs::create_dir_all(instance.path.parent().unwrap()).unwrap();
        std::fs::write(&instance.path, b"blocking parent").unwrap();
        assert!(matches!(
            acquire_single_instance_at(&instance.path.join("child"), &instance.name),
            InstanceGuard::Unavailable(_)
        ));
        instance.restore().unwrap();
        release_instance_locks(&instance.file, &instance.mutex);
        let LockFileOutcome::Acquired(other_owner) = acquire_file_lock(&instance.path) else {
            panic!("other owner must claim released file");
        };
        assert!(instance.restore().is_err());
        assert!(instance.file.lock().unwrap().is_none());
        assert!(instance.mutex.load(Ordering::SeqCst).is_null());
        drop(other_owner);
        assert!(
            reacquire_instance_locks(&instance.file, &instance.mutex, || {
                InstanceGuard::Unavailable("injected failure".to_string())
            })
            .is_err()
        );
        assert!(instance.file.lock().unwrap().is_none());
    }

    #[test]
    fn a_second_launch_is_able_to_wake_the_running_copy() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        let instance = IsolatedInstance::new();
        let handle = create_wake_event_named(&instance.name);
        assert!(
            !handle.is_null(),
            "the isolated wake event could not be created"
        );
        assert_ne!(
            unsafe { WaitForSingleObject(handle, 0) },
            0,
            "spurious wake-up"
        );
        signal_wake_event_named(&instance.name);
        assert_eq!(
            unsafe { WaitForSingleObject(handle, 0) },
            0,
            "wake request missing"
        );
        assert_ne!(
            unsafe { WaitForSingleObject(handle, 0) },
            0,
            "request was not consumed"
        );
        unsafe { CloseHandle(handle) };
    }
}

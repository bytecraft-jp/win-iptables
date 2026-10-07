use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// UAC 昇格して自分自身を起動し直す
pub fn relaunch_as_admin() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let verb = wide("runas".as_ref());
    let file = wide(exe.as_os_str());
    let r = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL)
    };
    // 32 以下はエラー（ユーザーが UAC をキャンセルした場合も含む）
    if r as isize > 32 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// exe に埋め込んだアイコン（リソース ID 1）をウィンドウに設定する。
/// eframe は RGBA 1 枚しか渡せず 16px では縮小でつぶれるので、DPI に合ったサイズを ICO から直接読む
pub fn set_window_icon(hwnd: isize) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, SM_CXICON, SM_CXSMICON, SendMessageW, WM_SETICON,
    };
    let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
    unsafe {
        let module = GetModuleHandleW(std::ptr::null());
        let dpi = GetDpiForWindow(hwnd);
        for (kind, metric) in [(ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)] {
            let size = GetSystemMetricsForDpi(metric, dpi);
            // MAKEINTRESOURCE(1)
            let icon = LoadImageW(module, 1 as _, IMAGE_ICON, size, size, LR_DEFAULTCOLOR);
            if !icon.is_null() {
                SendMessageW(hwnd, WM_SETICON, kind as usize, icon as isize);
            }
        }
    }
}

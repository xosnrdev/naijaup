use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, null_mut};
use std::{io, iter};

use windows_sys::Win32::Foundation::{
    self, CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SMTO_NORMAL, SendMessageTimeoutW, WM_SETTINGCHANGE,
};

use crate::{print_success, print_warn};

pub fn add_to_path(dir: &Path) -> io::Result<()> {
    let dir_str = dir.to_string_lossy();
    let current_path = get_current_path()?;

    if current_path.to_lowercase().contains(&normalize_path(dir)) {
        return Ok(());
    }

    let new_path = if current_path.is_empty() {
        dir_str.to_string()
    } else {
        format!("{dir_str};{current_path}")
    };

    set_path(&new_path)
}

pub fn remove_from_path(dir: &Path) -> io::Result<()> {
    let target = normalize_path(dir);
    let current_path = get_current_path()?;

    let new_path: Vec<&str> =
        current_path.split(';').filter(|p| normalize_path(Path::new(p.trim())) != target).collect();

    set_path(&new_path.join(";"))
}

fn get_current_path() -> io::Result<String> {
    unsafe {
        let mut hkey = null_mut();
        let lpsubkey = to_utf16("Environment");
        let lpsubkey = lpsubkey.as_ptr();
        let lpvaluename = to_utf16("PATH");
        let lpvaluename = lpvaluename.as_ptr();

        // Open the registry key
        let n = RegOpenKeyExW(HKEY_CURRENT_USER, lpsubkey, 0, KEY_READ, &mut hkey);

        if n != ERROR_SUCCESS {
            return Ok(String::new());
        }

        // First, query the size needed
        let (mut lpcbdata, mut lptype) = (0, 0);
        let n =
            RegQueryValueExW(hkey, lpvaluename, null_mut(), &mut lptype, null_mut(), &mut lpcbdata);

        if n != ERROR_SUCCESS && n != ERROR_MORE_DATA {
            RegCloseKey(hkey);
            return Ok(String::new());
        }

        // Allocate buffer and read the value
        let len = (lpcbdata / 2) as usize;
        let mut buffer = vec![0u16; len];
        let lpdata = buffer.as_mut_ptr() as *mut u8;
        let n = RegQueryValueExW(hkey, lpvaluename, null_mut(), &mut lptype, lpdata, &mut lpcbdata);

        RegCloseKey(hkey);

        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        let path = String::from_utf16_lossy(&buffer[..len]);

        if n == ERROR_SUCCESS { Ok(path) } else { Ok(String::new()) }
    }
}

fn set_path(path: &str) -> io::Result<()> {
    unsafe {
        let mut hkey = null_mut();
        let lpsubkey = to_utf16("Environment");
        let lpsubkey = lpsubkey.as_ptr();
        let lpvaluename = to_utf16("PATH");
        let lpvaluename = lpvaluename.as_ptr();

        // Open the registry key with rights to set values
        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
        let n = RegOpenKeyExW(HKEY_CURRENT_USER, lpsubkey, 0, KEY_SET_VALUE, &mut hkey);
        if n != ERROR_SUCCESS {
            return Err(win32_error_to_io_error(n));
        }

        let lparam = lpsubkey as isize;
        if path.is_empty() {
            // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluew
            let n = RegDeleteValueW(hkey, lpvaluename);
            RegCloseKey(hkey);
            if n == ERROR_SUCCESS || n == Foundation::ERROR_FILE_NOT_FOUND {
                broadcast_env_changed(lparam);
                Ok(())
            } else {
                Err(win32_error_to_io_error(n))
            }
        } else {
            let lpdata = to_utf16(path);
            let cbdata = (lpdata.len() * 2) as u32;
            let lpdata = lpdata.as_ptr() as *const u8;

            // Set the value as REG_SZ
            // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw
            let n = RegSetValueExW(hkey, lpvaluename, 0, REG_SZ, lpdata, cbdata);
            RegCloseKey(hkey);
            if n == ERROR_SUCCESS {
                broadcast_env_changed(lparam);
                Ok(())
            } else {
                Err(win32_error_to_io_error(n))
            }
        }
    }
}

fn broadcast_env_changed(lparam: isize) {
    unsafe {
        let mut lpdwresult = 0usize;
        // https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-settingchange
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            lparam,
            SMTO_NORMAL | SMTO_ABORTIFHUNG,
            5000,
            &mut lpdwresult,
        );
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

fn to_utf16(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(iter::once(0)).collect()
}

fn win32_error_to_io_error(error_code: u32) -> io::Error {
    io::Error::from_raw_os_error(error_code as i32)
}

pub fn stage_update(
    from: &Path,
    to: &Path,
    parent: u32,
    cleanup: Option<&Path>,
) -> Result<(), String> {
    unsafe {
        let hhandle = OpenProcess(PROCESS_SYNCHRONIZE, 0, parent);
        if !hhandle.is_null() {
            WaitForSingleObject(hhandle, u32::MAX);
            CloseHandle(hhandle);
        }
    }

    let lpexistingfilename = to_utf16(&from.to_string_lossy());
    let lpexistingfilename = lpexistingfilename.as_ptr();
    let lpnewfilename = to_utf16(&to.to_string_lossy());
    let lpnewfilename = lpnewfilename.as_ptr();

    unsafe {
        if MoveFileExW(
            lpexistingfilename,
            lpnewfilename,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        ) == 0
        {
            let err = GetLastError();
            if MoveFileExW(
                lpexistingfilename,
                lpnewfilename,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT,
            ) == 0
            {
                return Err(format!(
                    "I no fit replace naijaup binary (WinErr {err}). Try run as admin or reinstall manually."
                ));
            } else {
                print_warn!(
                    "I schedule update make e finish when you reboot. Windows error code: {err}"
                );
                if let Some(path) = cleanup {
                    schedule_delete_after_reboot(path);
                }
                return Ok(());
            }
        }
    }

    if let Some(path) = cleanup {
        schedule_delete_after_reboot(path);
    }
    print_success!("I don finish update. Restart your shell make e pick the latest.");
    Ok(())
}

fn schedule_delete_after_reboot(path: &Path) {
    let lpexistingfilename = to_utf16(&path.to_string_lossy());
    let lpexistingfilename = lpexistingfilename.as_ptr();
    unsafe {
        if MoveFileExW(lpexistingfilename, ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) == 0 {
            print_warn!(
                "I no fit schedule cleanup for {} (WinErr {}).",
                path.display(),
                GetLastError()
            );
        }
    }
}

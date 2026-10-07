//! TUN がインターネット接続の共有（ICS）に使われていたら、アダプタを消す前に外す。
//!
//! モバイル ホットスポットの共有元に TUN が選ばれたまま停止してアダプタを消すと、ICS の設定が
//! 壊れて残り、ホットスポットが共有を設定できなくなる（EnableSharing が 0x80040201 で失敗する）。
//! ICS は COM（`HNetCfg.HNetShare`）からしか操作できないので、Windows PowerShell 経由で呼ぶ。
//! PowerShell の起動を待つので数秒かかる

use std::io;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const PRELUDE: &str = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;\
    try{$m=New-Object -ComObject HNetCfg.HNetShare;";
const POSTLUDE: &str = "}catch{\"ERR`t$($_.Exception.Message)\";exit 1}";

/// `guid` の接続に共有が設定されていれば外す（設定されていなければ何もしない）。
/// 共有したままアダプタを削除すると ICS の設定が壊れて残り、以後の EnableSharing が
/// 0x80040201 で失敗するようになるので、アダプタを消す前に呼ぶ。外したら true
pub fn release(guid: &str) -> io::Result<bool> {
    if !is_guid(guid) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("不正な GUID: {guid}")));
    }
    let out = run(&format!(
        "foreach($c in $m.EnumEveryConnection){{if($m.NetConnectionProps.Invoke($c).Guid -eq '{guid}'){{\
        $s=$m.INetSharingConfigurationForINetConnection.Invoke($c);if($s.SharingEnabled){{$s.DisableSharing();'RELEASED'}}}}}}"
    ))?;
    Ok(out.contains("RELEASED"))
}

fn is_guid(s: &str) -> bool {
    s.len() == 38 && s.starts_with('{') && s.ends_with('}') && s[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn run(body: &str) -> io::Result<String> {
    let script = format!("{PRELUDE}{body}{POSTLUDE}");
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(base64(&utf16))
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').to_string();
    if let Some(msg) = stdout.lines().find_map(|l| l.strip_prefix("ERR\t")) {
        return Err(io::Error::other(msg.trim().to_string()));
    }
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!("PowerShell が失敗しました: {}", err.trim())));
    }
    Ok(stdout)
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn rejects_bad_guids() {
        assert!(is_guid("{5F1C2A7E-93B4-4D61-A0E8-7C3B19D2E604}"));
        assert!(!is_guid("{5F1C2A7E-93B4-4D61-A0E8-7C3B19D2E604}';calc;'"));
        assert!(release("x").is_err());
    }

    #[test]
    fn release_of_unknown_connection_does_nothing() {
        // 存在しない接続なら何もせずに false（PowerShell との往復ができることも確かめる）
        assert!(!release("{00000000-0000-0000-0000-000000000000}").unwrap());
    }
}

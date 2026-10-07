//! 従来のインターネット共有（ICS、ncpa.cpl の「共有」タブ）の後始末。
//!
//! モバイル ホットスポットは hotspot.rs で扱う。ここでは、利用者が手動で TUN を共有したまま
//! 停止したときに、アダプタを消す前に共有を外す（消すと ICS の設定が壊れて残る）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Public,
    Private,
}

#[derive(Debug, Clone)]
struct Connection {
    guid: String,
    name: String,
    role: Option<Role>,
}

mod native;

/// TUN が共有に使われていたら外す。外したら true
pub fn release(guid: &str) -> anyhow::Result<bool> {
    let connections = native::list()?;
    if connections.iter().any(|c| c.guid.eq_ignore_ascii_case(guid) && c.role.is_some()) {
        native::set(guid, None)?;
        return Ok(true);
    }
    Ok(false)
}

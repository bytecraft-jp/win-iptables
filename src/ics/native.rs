//! ICS の COM API。COM オブジェクトは呼出しスレッド内だけで使用する。

use anyhow::Context;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    ICSSHARINGTYPE_PRIVATE, ICSSHARINGTYPE_PUBLIC, INetConnection, INetSharingConfiguration, INetSharingManager, NetSharingManager,
};
use windows::Win32::System::Com::{CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{IUnknown, Interface};

use super::{Connection, Role};

struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn with_connections<T>(f: impl FnOnce(&[(Connection, INetSharingConfiguration)]) -> anyhow::Result<T>) -> anyhow::Result<T> {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok() }.context("ICS COM の初期化に失敗")?;
    let _apartment = Apartment;
    let manager: INetSharingManager = unsafe { CoCreateInstance(&NetSharingManager, None, CLSCTX_ALL) }.context("ICS の取得に失敗")?;
    let collection = unsafe { manager.EnumEveryConnection() }.context("ICS 接続一覧の取得に失敗（管理者権限が必要です）")?;
    let enumerator: IEnumVARIANT = unsafe { collection._NewEnum() }?.cast().context("ICS 接続の列挙インターフェースを取得できません")?;
    let mut connections = Vec::new();
    loop {
        let mut values = [VARIANT::default()];
        let mut fetched = 0;
        unsafe { enumerator.Next(&mut values, &mut fetched).ok() }.context("ICS 接続の列挙に失敗")?;
        if fetched == 0 {
            break;
        }
        let connection: INetConnection = IUnknown::try_from(&values[0])?.cast()?;
        let props = unsafe { manager.get_NetConnectionProps(&connection) }?;
        let config = unsafe { manager.get_INetSharingConfigurationForINetConnection(&connection) }?;
        let role = if unsafe { config.SharingEnabled() }?.as_bool() {
            match unsafe { config.SharingConnectionType() }? {
                ICSSHARINGTYPE_PUBLIC => Some(Role::Public),
                ICSSHARINGTYPE_PRIVATE => Some(Role::Private),
                _ => anyhow::bail!("不明な ICS 接続種別"),
            }
        } else {
            None
        };
        connections.push((
            Connection {
                guid: unsafe { props.Guid() }?.to_string().to_ascii_uppercase(),
                name: unsafe { props.Name() }?.to_string(),
                role,
            },
            config,
        ));
    }
    f(&connections)
}

pub(super) fn list() -> anyhow::Result<Vec<Connection>> {
    with_connections(|connections| Ok(connections.iter().map(|(connection, _)| connection.clone()).collect()))
}

pub(super) fn set(guid: &str, role: Option<Role>) -> anyhow::Result<()> {
    with_connections(|connections| {
        let (connection, config) = connections
            .iter()
            .find(|(connection, _)| connection.guid.eq_ignore_ascii_case(guid))
            .with_context(|| format!("ICS 接続 {guid} が見つかりません"))?;
        if connection.role == role {
            return Ok(());
        }
        unsafe {
            match role {
                Some(Role::Public) => config.EnableSharing(ICSSHARINGTYPE_PUBLIC),
                Some(Role::Private) => config.EnableSharing(ICSSHARINGTYPE_PRIVATE),
                None => config.DisableSharing(),
            }
        }
        .with_context(|| format!("ICS 接続 {} の切替に失敗", connection.name))
    })
}

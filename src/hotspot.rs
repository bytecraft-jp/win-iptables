//! Windows のモバイル ホットスポットを、TUN を共有元にしてオン・オフする。
//!
//! 設定画面のホットスポットは物理 NIC しか共有元に選べず、従来の ICS（HNetCfg）からは
//! モバイル ホットスポットの共有が見えない。WinRT の NetworkOperatorTetheringManager なら
//! TUN の接続プロファイルを共有元にして開始できる。共有の NAT を通るので、端末の通信は
//! 送信元が TUN のアドレスのフローとして TUN に入り、ルールが適用される。
//!
//! 共有元の TUN を消すと共有の設定が壊れて残るので、エンジンはアダプタを消す前に必ず止める。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use parking_lot::Mutex;
use windows::Networking::Connectivity::{ConnectionProfile, NetworkInformation};
use windows::Networking::NetworkOperators::{
    NetworkOperatorTetheringManager, NetworkOperatorTetheringOperationResult, NetworkOperatorTetheringSessionAccessPointConfiguration,
    TetheringCapability, TetheringOperationStatus, TetheringOperationalState,
};
use windows::core::{GUID, HSTRING};

/// アダプタを作った直後は、Windows がネットワークを識別して接続プロファイルを作るまで少しかかる
const PROFILE_WAIT: Duration = Duration::from_secs(15);
const PROFILE_POLL: Duration = Duration::from_millis(500);

#[derive(Default)]
struct State {
    /// TUN を共有元にしてこちらで開始した
    ours: bool,
    /// 開始前に別の共有元（Wi-Fi など）でホットスポットが動いていた。エンジン停止後にそれで再開する
    previous_on: bool,
}

/// 名前とパスワードの指定。空欄なら Windows の設定画面のものを使う
#[derive(Debug, Clone, Default)]
pub struct AccessPoint {
    pub ssid: String,
    pub passphrase: String,
}

impl AccessPoint {
    /// 入力の検査（空欄は Windows の設定を使うので可）
    pub fn validate(&self) -> Result<(), String> {
        if self.ssid.len() > 32 {
            return Err("ネットワーク名は 32 バイト以内にしてください（日本語は 1 文字 3 バイト）".into());
        }
        let p = &self.passphrase;
        if !p.is_empty() && !(8..=63).contains(&p.len()) {
            return Err("パスワードは 8〜63 文字にしてください".into());
        }
        if !p.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            return Err("パスワードには半角の英数字と記号だけを使ってください".into());
        }
        Ok(())
    }

    fn is_default(&self) -> bool {
        self.ssid.is_empty() && self.passphrase.is_empty()
    }
}

pub struct Hotspot {
    tun: GUID,
    access_point: AccessPoint,
    state: Mutex<State>,
    /// こちらで開始したホットスポットが動いている間 true（TUN のパケット分割が見る）
    active: Arc<AtomicBool>,
}

impl Hotspot {
    pub fn new(tun_guid: u128, access_point: AccessPoint) -> Self {
        Self { tun: GUID::from_u128(tun_guid), access_point, state: Mutex::new(State::default()), active: Arc::default() }
    }

    /// ホットスポットが動いている間 true になるフラグ。端末宛てのパケットは共有の NAT の前では
    /// TUN 自身宛てに見えるので、TUN 側はこれを見て 1500 に分け直す
    pub fn active_flag(&self) -> Arc<AtomicBool> {
        self.active.clone()
    }

    /// 画面表示用。切替中（ロック中）なら None
    pub fn status(&self) -> Option<bool> {
        self.state.try_lock().map(|s| s.ours)
    }

    /// TUN を共有元にしてホットスポットを開始する（ブロッキング。数秒かかる）。
    /// 別の共有元で動いていたら止めて切り替え、エンジン停止時にそちらへ戻す
    pub fn turn_on(&self) -> anyhow::Result<String> {
        let mut st = self.state.lock();
        if st.ours {
            return Ok("ホットスポットは既にオンです".into());
        }
        let profile = wait_profile(self.tun)?;
        let capability = NetworkOperatorTetheringManager::GetTetheringCapabilityFromConnectionProfile(&profile)?;
        if capability != TetheringCapability::Enabled {
            bail!("この PC では TUN を共有元にしたホットスポットを使えません（{}）", capability_text(capability));
        }
        let manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile).context("ホットスポットの取得に失敗")?;
        let session = self.session_config(&manager)?;
        let was_on = is_on(&manager)?;
        if was_on {
            run(manager.StopTetheringAsync()?.join(), "動作中のホットスポットの停止")?;
        }
        let started = match &session {
            Some(config) => manager.StartTetheringAsync2(config)?.join(),
            None => manager.StartTetheringAsync()?.join(),
        };
        if let Err(e) = run(started, "ホットスポットの開始") {
            if was_on {
                // 元の共有元で動いていたものは戻しておく
                let _ = restore_previous();
            }
            return Err(e);
        }
        st.ours = true;
        self.active.store(true, Ordering::Relaxed);
        st.previous_on |= was_on;
        let ssid = match &session {
            Some(config) => config.Ssid()?,
            None => manager.GetCurrentAccessPointConfiguration()?.Ssid()?,
        };
        Ok(if was_on {
            format!("ホットスポットの共有元を TUN に切り替えました（名前: {ssid}。停止時に元の共有元へ戻します）")
        } else {
            format!("ホットスポットを開始しました（名前: {ssid}、共有元: TUN）")
        })
    }

    /// 名前・パスワードの指定があれば、その回だけの設定を作る（Windows の保存済みの設定は書き換えない）。
    /// 指定のない項目と帯域・認証方式は保存済みの設定から引き継ぐ
    fn session_config(
        &self,
        manager: &NetworkOperatorTetheringManager,
    ) -> anyhow::Result<Option<NetworkOperatorTetheringSessionAccessPointConfiguration>> {
        let ap = &self.access_point;
        if ap.is_default() {
            return Ok(None);
        }
        ap.validate().map_err(anyhow::Error::msg)?;
        let saved = manager.GetCurrentAccessPointConfiguration().context("ホットスポットの設定の取得に失敗")?;
        let pick = |mine: &str, saved: windows::core::Result<HSTRING>| -> windows::core::Result<HSTRING> {
            if mine.is_empty() { saved } else { Ok(HSTRING::from(mine)) }
        };
        let config = NetworkOperatorTetheringSessionAccessPointConfiguration::new()?;
        config.SetSsid(&pick(&ap.ssid, saved.Ssid())?)?;
        config.SetPassphrase(&pick(&ap.passphrase, saved.Passphrase())?)?;
        config.SetBand(saved.Band()?)?;
        config.SetAuthenticationKind(saved.AuthenticationKind()?)?;
        Ok(Some(config))
    }

    /// 利用者の操作でオフにする。元の共有元には戻さない
    pub fn turn_off(&self) -> anyhow::Result<String> {
        let mut st = self.state.lock();
        if !st.ours {
            return Ok("ホットスポットは既にオフです".into());
        }
        stop(self.tun)?;
        *st = State::default();
        self.active.store(false, Ordering::Relaxed);
        Ok("ホットスポットを停止しました".into())
    }

    /// エンジン停止時、TUN を消す前に呼ぶ。オンでなければ None、
    /// 止めたら元の共有元（Wi-Fi など）で再開すべきかを返す
    pub fn shutdown(&self) -> anyhow::Result<Option<bool>> {
        let mut st = self.state.lock();
        if !st.ours {
            return Ok(None);
        }
        let previous = st.previous_on;
        *st = State::default();
        self.active.store(false, Ordering::Relaxed);
        stop(self.tun)?;
        Ok(Some(previous))
    }

    /// Windows 側で止まった（省電力で自動オフ、設定画面からオフなど）ことを反映する。
    /// 定期的に呼ぶ。切替中なら何もしない。止まっていたら true
    pub fn refresh(&self) -> bool {
        let Some(mut st) = self.state.try_lock() else { return false };
        if !st.ours {
            return false;
        }
        let off = tun_profile(self.tun)
            .ok()
            .flatten()
            .and_then(|p| NetworkOperatorTetheringManager::CreateFromConnectionProfile(&p).ok())
            .and_then(|m| is_on(&m).ok())
            .is_some_and(|on| !on);
        if off {
            *st = State::default();
            self.active.store(false, Ordering::Relaxed);
        }
        off
    }
}

/// インターネット接続（TUN を消した後なら Wi-Fi など）を共有元にしてホットスポットを再開する
pub fn restore_previous() -> anyhow::Result<()> {
    let profile = NetworkInformation::GetInternetConnectionProfile().context("インターネット接続が見つかりません")?;
    let manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile)?;
    if !is_on(&manager)? {
        run(manager.StartTetheringAsync()?.join(), "ホットスポットの再開")?;
    }
    Ok(())
}

fn tun_profile(tun: GUID) -> anyhow::Result<Option<ConnectionProfile>> {
    let profiles = NetworkInformation::GetConnectionProfiles().context("接続プロファイルの取得に失敗")?;
    Ok(profiles.into_iter().find(|p| p.NetworkAdapter().and_then(|a| a.NetworkAdapterId()).is_ok_and(|id| id == tun)))
}

fn wait_profile(tun: GUID) -> anyhow::Result<ConnectionProfile> {
    let deadline = Instant::now() + PROFILE_WAIT;
    loop {
        if let Some(p) = tun_profile(tun)? {
            return Ok(p);
        }
        if Instant::now() >= deadline {
            bail!("TUN の接続プロファイルが見つかりません（Windows が TUN のネットワークを識別していない）");
        }
        std::thread::sleep(PROFILE_POLL);
    }
}

/// ホットスポットの状態は PC 全体で 1 つなので、どの接続プロファイルから見ても同じ値になる
fn is_on(manager: &NetworkOperatorTetheringManager) -> anyhow::Result<bool> {
    Ok(manager.TetheringOperationalState()? == TetheringOperationalState::On)
}

fn stop(tun: GUID) -> anyhow::Result<()> {
    let profile = match tun_profile(tun)? {
        Some(p) => p,
        None => NetworkInformation::GetInternetConnectionProfile().context("ホットスポットを止めるための接続が見つかりません")?,
    };
    let manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile)?;
    if is_on(&manager)? {
        run(manager.StopTetheringAsync()?.join(), "ホットスポットの停止")?;
    }
    Ok(())
}

/// `result` は StartTetheringAsync などを `join()` で待った結果
fn run(result: windows::core::Result<NetworkOperatorTetheringOperationResult>, what: &str) -> anyhow::Result<()> {
    let result = result.with_context(|| format!("{what}に失敗"))?;
    let status = result.Status()?;
    if status != TetheringOperationStatus::Success {
        let detail = result.AdditionalErrorMessage().map(|m| m.to_string()).unwrap_or_default();
        bail!("{what}に失敗: {}{}", status_text(status), if detail.is_empty() { String::new() } else { format!("（{detail}）") });
    }
    Ok(())
}

fn status_text(s: TetheringOperationStatus) -> String {
    match s {
        TetheringOperationStatus::WiFiDeviceOff => "Wi-Fi がオフです".into(),
        TetheringOperationStatus::BluetoothDeviceOff => "Bluetooth がオフです".into(),
        TetheringOperationStatus::OperationInProgress => "別の切替が進行中です".into(),
        TetheringOperationStatus::NetworkLimitedConnectivity => "共有元がインターネットにつながっていません".into(),
        TetheringOperationStatus::RadioRestriction => "無線が制限されています（機内モードなど）".into(),
        TetheringOperationStatus::BandInterference => "Wi-Fi の帯域が干渉しています（2.4 GHz/5 GHz の設定を確認）".into(),
        other => format!("{other:?}"),
    }
}

fn capability_text(c: TetheringCapability) -> String {
    match c {
        TetheringCapability::DisabledByGroupPolicy => "グループ ポリシーで無効".into(),
        TetheringCapability::DisabledByHardwareLimitation => "Wi-Fi アダプタが対応していません".into(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(ssid: &str, passphrase: &str) -> AccessPoint {
        AccessPoint { ssid: ssid.into(), passphrase: passphrase.into() }
    }

    #[test]
    fn access_point_validation() {
        assert!(ap("", "").validate().is_ok(), "空欄は Windows の設定を使う");
        assert!(ap("テスト SSID", "abcd1234").validate().is_ok());
        assert!(ap(&"x".repeat(32), &"y".repeat(63)).validate().is_ok());
        assert!(ap(&"x".repeat(33), "").validate().is_err());
        assert!(ap(&"あ".repeat(11), "").validate().is_err(), "SSID はバイト数で数える");
        assert!(ap("", "1234567").validate().is_err());
        assert!(ap("", &"y".repeat(64)).validate().is_err());
        assert!(ap("", "パスワード1234").validate().is_err());
        assert!(ap("", "abc\tdefgh").validate().is_err());
    }
}

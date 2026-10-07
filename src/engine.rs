//! ルーターエンジン本体。
//!
//! Wintun アダプタ → ipstack（ユーザー空間 TCP/IP スタック）でフローを終端 →
//! ルール評価 → `IP_UNICAST_IF` で物理NICに固定したソケットから再送出する。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, bail};
use ipnet::IpNet;
use ipstack::{IpStack, IpStackConfig, TcpConfig};
use wintun_bindings::{Adapter, Session};

use crate::config::{EngineConfig, RouteMode};
use crate::hotspot::{self, Hotspot};
use crate::rules::{RuleSet, Target};
use crate::tundev::{SessionSlot, TunDevice};
use crate::winnet;

mod flow;
mod network;
mod relay;
mod routes;
mod state;

use flow::{Ctx, net_refresher};
use network::{EgressForwarding, NetView};
use relay::accept_loop;
use routes::BypassRoutes;
pub use routes::{InstalledRoute, add_route_by_name};
pub use state::{ConnState, Shared};

/// ipstack 既定の 16KB では 1 接続あたりの未ACK量が頭打ちになり遅いので広げる
/// （ipstack は Window Scale 非対応なので実効ウィンドウは最大 64KB）
const TCP_BUF: usize = 256 * 1024;
/// 再作成しても Windows 側にネットワークプロファイルが増殖しないよう GUID を固定する
const ADAPTER_GUID: u128 = 0x5f1c_2a7e_93b4_4d61_a0e8_7c3b_19d2_e604;
/// 起動時に「自動選択」の出口をログに出すための宛先（調査用）
const PROBES: [IpAddr; 2] = [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))];

/// 停止後、TUN アダプタが本当に消えたかを確かめる時間
const ADAPTER_REMOVAL_WAIT: Duration = Duration::from_secs(5);

/// `{5F1C2A7E-93B4-4D61-A0E8-7C3B19D2E604}` 形式
fn adapter_guid_string() -> String {
    let h = format!("{ADAPTER_GUID:032X}");
    format!("{{{}-{}-{}-{}-{}}}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// 前回の TUN アダプタが残っているか（GUID を固定しているので、残っていると作り直せない）
fn tun_adapter_exists() -> bool {
    let guid = adapter_guid_string();
    winnet::list_interfaces().is_ok_and(|ifs| ifs.iter().any(|i| i.guid.eq_ignore_ascii_case(&guid)))
}

fn exe_dir() -> Option<std::path::PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

fn load_wintun() -> anyhow::Result<wintun_bindings::Wintun> {
    let local = exe_dir().map(|d| d.join("wintun.dll")).filter(|p| p.exists());
    let res = match &local {
        Some(p) => unsafe { wintun_bindings::load_from_path(p) },
        None => unsafe { wintun_bindings::load() },
    };
    res.context("wintun.dll を読み込めません（exe と同じフォルダに置いてください）")
}

pub struct Engine {
    pub config: EngineConfig,
    rt: tokio::runtime::Runtime,
    session: Arc<Session>,
    /// IP スタックが送信に使うセッション。停止時に空にする
    tun_session: SessionSlot,
    adapter: Arc<Adapter>,
    rx_thread: std::thread::JoinHandle<()>,
    tun_routes: Vec<InstalledRoute>,
    bypass: BypassRoutes,
    shared: Arc<Shared>,
    egress_fwd: Arc<EgressForwarding>,
    hotspot: Arc<Hotspot>,
    pub tun_luid: u64,
}

impl Engine {
    pub fn start(config: EngineConfig, shared: Arc<Shared>) -> anyhow::Result<Engine> {
        // 失敗しうる設定の検証は、アダプタ作成や物理 NIC の転送設定変更より先に済ませる。
        let mut tcp = TcpConfig::default();
        tcp.timeout = Duration::from_secs(600);
        tcp.max_unacked_bytes = TCP_BUF as u32;
        tcp.read_buffer_size = TCP_BUF;
        let mut ipcfg = IpStackConfig::default();
        ipcfg.mtu(config.mtu)?.udp_timeout(Duration::from_secs(60)).with_tcp_config(tcp);
        let tun_addrs = config.tun_addrs();
        let tun_nets = tun_addrs.iter().map(|&(a, p)| Ok(IpNet::new(a, p)?.trunc())).collect::<anyhow::Result<Vec<_>>>()?;

        if tun_adapter_exists() {
            bail!("前回の TUN アダプタがまだ残っているため開始できません。win-iptables を終了して起動し直してください");
        }
        let wintun = load_wintun()?;
        let adapter = Adapter::create(&wintun, &config.tun_name, "WinIptables", Some(ADAPTER_GUID))
            .context("Wintun アダプタの作成に失敗（管理者権限が必要です）")?;
        let tun_luid = unsafe { adapter.get_luid().Value };

        for &(addr, prefix) in &tun_addrs {
            winnet::add_address(tun_luid, addr, prefix)
                .with_context(|| format!("TUN への {} 付与に失敗", winnet::family(addr.is_ipv6())))?;
        }
        if let Err(e) = adapter.set_mtu(config.mtu as usize) {
            shared.log(format!("MTU 設定に失敗（続行）: {e}"));
        }
        // ICS などで他の端末から転送されてきたフローの応答は TUN から入って LAN 側へ転送されるので、
        // TUN でも転送を有効にしておく（アダプタごと消えるので停止時の後始末は不要）
        for &(addr, _) in &tun_addrs {
            if let Err(e) = winnet::set_forwarding(tun_luid, addr.is_ipv6(), true) {
                shared.log(format!("TUN の IP 転送を有効にできません（転送されてきた通信の中継に影響、続行）: {e}"));
            }
        }
        let session = adapter.start_session(wintun_bindings::MAX_RING_CAPACITY)?;

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("router").build()?;
        let net = NetView::load(tun_luid);
        let egress_fwd = Arc::new(EgressForwarding::default());
        let access_point = hotspot::AccessPoint { ssid: config.hotspot_ssid.clone(), passphrase: config.hotspot_passphrase.clone() };
        let hotspot = Arc::new(Hotspot::new(ADAPTER_GUID, access_point));
        egress_fwd.enforce(&net, tun_luid, &shared);
        let ctx = Arc::new(Ctx::new(&config, shared.clone(), tun_luid, tun_nets, net, egress_fwd.clone(), hotspot.clone()));
        for probe in PROBES {
            let fam = winnet::family(probe.is_ipv6());
            match ctx.resolve_in(&ctx.net.load(), &Target::Accept, probe) {
                Ok(b) => shared.log(format!("{fam} の自動選択の出口: \"{}\" (#{}) 送信元 {}", b.name, b.index, b.src)),
                Err(e) => shared.log(format!("{fam} の自動選択の出口: なし（{e}）")),
            }
        }

        let local = tun_addrs.iter().map(|&(a, _)| a).collect();
        let (device, rx_thread, tun_session) = TunDevice::new(session.clone(), config.mtu as usize, local, hotspot.active_flag());
        let stack = rt.block_on(async { IpStack::new(ipcfg, device) });
        rt.spawn(accept_loop(ctx.clone(), stack));

        let mut engine = Engine {
            config,
            rt,
            session,
            tun_session,
            adapter,
            rx_thread,
            tun_routes: Vec::new(),
            bypass: BypassRoutes::default(),
            shared,
            egress_fwd,
            hotspot,
            tun_luid,
        };
        if let Err(e) = engine.install_tun_routes() {
            engine.stop();
            return Err(e);
        }
        let rules = engine.shared.rules.load_full();
        engine.sync_bypass(&rules);
        if engine.config.hotspot_auto {
            match engine.hotspot.turn_on() {
                Ok(message) => engine.shared.log(message),
                Err(e) => engine.shared.log(format!("ホットスポットを開始できません（続行）: {e:#}")),
            }
        }
        engine.rt.spawn(net_refresher(ctx));
        engine.shared.log(format!(
            "開始: TUN \"{}\" {}/{}（{}）",
            engine.config.tun_name,
            engine.config.tun_ipv4,
            engine.config.tun_prefix,
            match engine.config.route_mode {
                RouteMode::Split => "全トラフィックを捕捉",
                RouteMode::Manual => "経路は手動",
            }
        ));
        Ok(engine)
    }

    fn install_tun_routes(&mut self) -> anyhow::Result<()> {
        if self.config.route_mode == RouteMode::Manual {
            return Ok(());
        }
        for dst in routes::split_nets(self.config.capture_ipv6) {
            // 途中で失敗しても、追加済みの分は stop() で消せるよう 1 本ずつ記録する
            self.tun_routes.push(routes::add_tun_route(self.tun_luid, dst)?);
        }
        Ok(())
    }

    /// BYPASS ルールとカーネル経路を同期する（差分だけ追加・削除）
    pub fn sync_bypass(&mut self, rules: &RuleSet) {
        self.bypass.sync(rules, &self.shared);
    }

    /// 画面のボタンからオン・オフするため、別スレッドへ渡せるようにする
    pub fn hotspot(&self) -> Arc<Hotspot> {
        self.hotspot.clone()
    }

    /// 経路を先に消すので、後段（アダプタの削除など）が戻らずに打ち切られても通信は物理NICに戻る。
    /// どこで止まったか分かるよう段階ごとにログを残す
    pub fn stop(self) {
        self.shared.log_conn_summary();
        // 共有元の TUN を消すと共有の設定が壊れて残るので、何より先に止める
        let restore_hotspot = match self.hotspot.shutdown() {
            Ok(None) => false,
            Ok(Some(previous)) => {
                self.shared.log("停止: ホットスポットを停止しました");
                previous
            }
            Err(e) => {
                self.shared.log(format!("ホットスポットを停止できません（続行）: {e:#}"));
                false
            }
        };
        self.shared.log("停止: 経路を削除");
        self.bypass.remove_all();
        for r in &self.tun_routes {
            let _ = r.remove();
        }
        self.shared.log("停止: TUN 受信を停止");
        let _ = self.session.shutdown();
        self.shared.log("停止: 中継処理の終了待ち");
        self.rt.shutdown_timeout(Duration::from_secs(2));
        // キューが満杯で blocking_send 中でも、スタック（受信側）の破棄で抜けられる。
        let _ = self.rx_thread.join();
        // IP スタックの後片付けが打ち切られて残っていても、セッションを手放させる
        self.tun_session.store(None);
        // 経路を消した後なので、転送を戻しても送出は TUN に戻らない
        self.egress_fwd.restore(self.tun_luid, &self.shared);
        // 共有したまま消すと ICS の設定が壊れて残り、ホットスポットも共有を設定できなくなる
        self.shared.log("停止: TUN の共有（ICS）を確認");
        match crate::ics::release(&adapter_guid_string()) {
            Ok(true) => self.shared.log("TUN の共有（ICS）を解除しました"),
            Ok(false) => {}
            Err(e) => self.shared.log(format!("TUN の共有（ICS）を確認できません（続行）: {e}")),
        }
        self.shared.log("停止: TUN アダプタを削除");
        // 中継処理がすべて終わっていれば、セッションを持っているのはここだけのはず。
        // ほかに残っているとセッションもアダプタも閉じられず、次の開始で作り直せない
        let holders = Arc::strong_count(&self.session);
        if holders > 1 {
            self.shared.log(format!("停止: TUN のセッションがまだ使われています（参照 {holders}）。アダプタが残るおそれがあります"));
        }
        drop(self.session);
        // 作成したアダプタは CloseAdapter で削除され、TUN 向けの経路も一緒に消える
        drop(self.adapter);
        let deadline = std::time::Instant::now() + ADAPTER_REMOVAL_WAIT;
        while tun_adapter_exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        if tun_adapter_exists() {
            self.shared
                .log("停止: TUN アダプタが削除されずに残っています。もう一度開始するには win-iptables を終了して起動し直してください");
        }
        if restore_hotspot {
            self.shared.log("停止: ホットスポットを元の共有元で再開");
            if let Err(e) = hotspot::restore_previous() {
                self.shared.log(format!("ホットスポットを再開できません: {e:#}"));
            }
        }
        self.shared.active.store(0, Ordering::Relaxed);
        self.shared.log("停止しました");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn adapter_guid_matches_windows_format() {
        // HNet の接続一覧に出る TUN の GUID と同じ表記
        assert_eq!(super::adapter_guid_string(), "{5F1C2A7E-93B4-4D61-A0E8-7C3B19D2E604}");
    }
}

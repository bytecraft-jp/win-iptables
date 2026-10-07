//! カーネル経路の追加・削除（TUN 向けの経路、BYPASS、「経路」タブの一時経路）。

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use ipnet::IpNet;

use super::state::Shared;
use crate::rules::{BypassRoute, RuleSet};
use crate::winnet;

pub(super) const TUN_ROUTE_METRIC: u32 = 1;
/// アダプタ起動直後はインターフェースが未準備で経路の追加に失敗することがあるので、少し待って再試行する
const TUN_ROUTE_ATTEMPTS: u32 = 20;
const TUN_ROUTE_RETRY_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRoute {
    pub luid: u64,
    pub dst: IpNet,
    pub gw: Option<IpAddr>,
}

impl InstalledRoute {
    pub fn remove(&self) -> io::Result<()> {
        winnet::delete_route(self.luid, self.dst, self.gw)
    }
}

/// インターフェース名で経路を追加する。ゲートウェイ省略時はそのNICの既定GW（なければオンリンク）
pub fn add_route_by_name(oif: &str, dst: IpNet, gw: Option<IpAddr>, metric: u32) -> anyhow::Result<InstalledRoute> {
    let ifs = winnet::list_interfaces()?;
    let iface = winnet::find_iface(&ifs, oif).ok_or_else(|| anyhow!("インターフェース \"{oif}\" が見つかりません"))?;
    let v6 = dst.addr().is_ipv6();
    let gw = gw.or_else(|| iface.gateway(v6));
    if gw.is_some_and(|g| g.is_ipv6() != v6) {
        bail!("宛先とゲートウェイのアドレスファミリが一致しません");
    }
    winnet::add_route(iface.luid, dst, gw, metric).with_context(|| format!("経路 {dst} → {oif} の追加に失敗"))?;
    Ok(InstalledRoute { luid: iface.luid, dst, gw })
}

/// 全トラフィックを捕捉するための経路（既存の既定経路より長いプレフィックスで TUN に向ける）
pub(super) fn split_nets(capture_ipv6: bool) -> Vec<IpNet> {
    let mut nets = vec!["0.0.0.0/1", "128.0.0.0/1"];
    if capture_ipv6 {
        nets.extend(["::/1", "8000::/1"]);
    }
    nets.into_iter().map(|n| n.parse().unwrap()).collect()
}

/// TUN 向けの経路を追加する（ブロッキング。準備待ちで最大数秒かかる）
pub(super) fn add_tun_route(tun_luid: u64, dst: IpNet) -> anyhow::Result<InstalledRoute> {
    for attempt in 1.. {
        match winnet::add_route(tun_luid, dst, None, TUN_ROUTE_METRIC) {
            Ok(()) => break,
            Err(e) if attempt >= TUN_ROUTE_ATTEMPTS => bail!("経路 {dst} → TUN の追加に失敗: {e}"),
            Err(_) => std::thread::sleep(TUN_ROUTE_RETRY_WAIT),
        }
    }
    Ok(InstalledRoute { luid: tun_luid, dst, gw: None })
}

/// BYPASS ルールから入れたカーネル経路
#[derive(Default)]
pub(super) struct BypassRoutes(Vec<(BypassRoute, InstalledRoute)>);

impl BypassRoutes {
    /// BYPASS ルールとカーネル経路を同期する（差分だけ追加・削除）
    pub(super) fn sync(&mut self, rules: &RuleSet, shared: &Shared) {
        let (keep, remove): (Vec<_>, Vec<_>) = std::mem::take(&mut self.0).into_iter().partition(|(b, _)| rules.bypass.contains(b));
        for (b, r) in remove {
            match r.remove() {
                Ok(()) => shared.log(format!("BYPASS 経路を削除: {} → {}", b.dst, b.oif)),
                Err(e) => shared.log(format!("BYPASS 経路の削除に失敗: {} ({e})", b.dst)),
            }
        }
        self.0 = keep;
        for b in &rules.bypass {
            if self.0.iter().any(|(x, _)| x == b) {
                continue;
            }
            match add_route_by_name(&b.oif, b.dst, b.gw, b.metric.unwrap_or(TUN_ROUTE_METRIC)) {
                Ok(r) => {
                    shared.log(format!("BYPASS 経路を追加: {} → {}", b.dst, b.oif));
                    self.0.push((b.clone(), r));
                }
                Err(e) => shared.log(format!("{e:#}")),
            }
        }
    }

    /// 停止時に消す（失敗しても続ける）
    pub(super) fn remove_all(&self) {
        for (_, r) in &self.0 {
            let _ = r.remove();
        }
    }
}

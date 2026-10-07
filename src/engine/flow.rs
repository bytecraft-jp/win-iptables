//! フローごとの評価（ルール・プロセス判定）と送出先の決定。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tokio::net::TcpStream;

use super::network::{Bound, Egress, EgressForwarding, NetView, connect_tcp};
use super::state::{ConnRecord, ConnState, Counters, Shared, now_hms};
use crate::config::EngineConfig;
use crate::hotspot::Hotspot;
use crate::pacer::{FailCache, Slots, TokenBucket};
use crate::rules::{Flow, Owner, Proto, RuleSet, Target};
use crate::{procinfo, winnet};

const NETVIEW_TTL: Duration = Duration::from_secs(5);
const NETVIEW_RETRY_MIN: Duration = Duration::from_secs(1);

/// 中継タスクが共有する、フローの評価と送出に要る状態
pub(super) struct Ctx {
    pub(super) shared: Arc<Shared>,
    tun_luid: u64,
    tun_nets: Vec<IpNet>,
    pub(super) net: ArcSwap<NetView>,
    egress_fwd: Arc<EgressForwarding>,
    hotspot: Arc<Hotspot>,
    started: Instant,
    throttle_at: AtomicU64,
    throttle_skipped: AtomicU64,
    connect_rate: TokenBucket,
    connect_slots: Slots,
    connect_fails: FailCache,
}

impl Ctx {
    pub(super) fn new(
        config: &EngineConfig,
        shared: Arc<Shared>,
        tun_luid: u64,
        tun_nets: Vec<IpNet>,
        net: NetView,
        egress_fwd: Arc<EgressForwarding>,
        hotspot: Arc<Hotspot>,
    ) -> Self {
        Self {
            shared,
            tun_luid,
            tun_nets,
            net: ArcSwap::from_pointee(net),
            egress_fwd,
            hotspot,
            started: Instant::now(),
            throttle_at: AtomicU64::new(u64::MAX),
            throttle_skipped: AtomicU64::new(0),
            connect_rate: TokenBucket::new(config.connect_rate, config.connect_burst),
            connect_slots: Slots::new(config.connect_concurrency),
            connect_fails: FailCache::new(Duration::from_secs(config.connect_fail_hold as u64)),
        }
    }

    async fn reload_net(&self) {
        let luid = self.tun_luid;
        let (fwd, shared) = (self.egress_fwd.clone(), self.shared.clone());
        let hotspot = self.hotspot.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            if hotspot.refresh() {
                shared.log("ホットスポットが Windows 側でオフになりました（省電力の自動オフ、設定画面からの操作など）");
            }
            let v = NetView::load(luid);
            fwd.enforce(&v, luid, &shared);
            v
        });
        if let Ok(v) = loaded.await {
            self.net.store(Arc::new(v));
        }
    }

    async fn resolve(&self, target: &Target, dst: IpAddr) -> Result<Bound, String> {
        let first = self.resolve_in(&self.net.load(), target, dst);
        if first.is_ok() {
            return first;
        }
        // NIC の抜き差し直後などに備えて取り直す（取り直した直後なら繰り返さない）
        if self.net.load().at.elapsed() > NETVIEW_RETRY_MIN {
            self.reload_net().await;
        }
        self.resolve_in(&self.net.load(), target, dst)
    }

    /// 外への TCP 接続を、速度・同時数の上限と失敗した宛先の保留を守って張る（詳細は pacer.rs）。
    /// この PC 宛て（REDIRECT 先のプロキシなど）はルーターを通らないので抑えない
    pub(super) async fn paced_connect(&self, eg: &Egress) -> io::Result<TcpStream> {
        if self.net.load().is_local(eg.to.ip()) {
            return connect_tcp(eg).await;
        }
        if let Some(left) = self.connect_fails.holding(eg.to, Instant::now()) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("直前につながらなかった宛先なので {} 秒間は接続を出さずに失敗させます", left.as_secs() + 1),
            ));
        }
        let _slot = self.connect_slots.acquire().await;
        let waited = self.connect_rate.wait().await;
        if waited >= Duration::from_secs(1) {
            self.log_throttled(format!("新規接続を抑えています（{:.1} 秒待ち）", waited.as_secs_f32()));
        }
        let res = connect_tcp(eg).await;
        match &res {
            Ok(_) => self.connect_fails.succeeded(eg.to),
            Err(_) => self.connect_fails.failed(eg.to, Instant::now()),
        }
        res
    }

    /// 同じ種類の警告が大量に出るときのため、1 秒に 1 行までにして残りは件数だけ数える
    pub(super) fn log_throttled(&self, msg: String) {
        let now = self.started.elapsed().as_secs();
        let last = self.throttle_at.swap(now, Ordering::Relaxed);
        let skipped = self.throttle_skipped.fetch_add(1, Ordering::Relaxed);
        if now != last || skipped == 0 {
            self.throttle_skipped.store(0, Ordering::Relaxed);
            let more = if skipped > 1 { format!("（ほか {} 件）", skipped - 1) } else { String::new() };
            self.shared.log(format!("{msg}{more}"));
        }
    }

    pub(super) fn resolve_in(&self, net: &NetView, target: &Target, dst: IpAddr) -> Result<Bound, String> {
        let v6 = dst.is_ipv6();
        let fam = winnet::family(v6);
        let iface = match target {
            Target::Route(name) => {
                winnet::find_iface(&net.ifaces, name).ok_or_else(|| format!("インターフェース \"{name}\" が見つかりません"))?
            }
            Target::Accept => {
                let luid = net.auto[v6 as usize].ok_or_else(|| format!("TUN 以外に {fam} の既定経路がありません"))?;
                net.ifaces.iter().find(|i| i.luid == luid).ok_or("既定経路のNICが見つかりません")?
            }
            Target::Drop | Target::Reject | Target::Dnat { .. } => unreachable!(),
        };
        if iface.luid == self.tun_luid {
            return Err("送出先に TUN 自身は指定できません".into());
        }
        if !iface.up {
            return Err(format!("\"{}\" はリンクダウンしています", iface.name));
        }
        // 送信元は Windows がその NIC で普段使うもの（IPv6 なら一時アドレス）を選ばせる。
        // 一覧の先頭のアドレスを使うと、通らないアドレスを選ぶことがある
        let src = winnet::best_source(iface.luid, dst)
            .or_else(|| iface.first_addr(v6))
            .ok_or_else(|| format!("\"{}\" に {fam} アドレスがありません", iface.name))?;
        Ok(Bound { name: iface.name.clone(), index: iface.index, src })
    }

    /// TUN 宛て・マルチキャスト・ブロードキャストは外へ出さず黙って捨てる
    pub(super) fn is_local_noise(&self, dst: IpAddr) -> bool {
        let special = match dst {
            IpAddr::V4(a) => a.is_multicast() || a.is_broadcast() || a.is_link_local(),
            IpAddr::V6(a) => a.is_multicast() || a.is_unicast_link_local(),
        };
        special || self.tun_nets.iter().any(|n| n.contains(&dst))
    }

    /// `since` はフローが TUN に届いた時刻（接続テーブルのスナップショットを使い回せるかの判断に使う）
    pub(super) async fn evaluate(self: &Arc<Self>, proto: Proto, src: SocketAddr, dst: SocketAddr, since: Instant) -> Decision {
        let rules = self.shared.rules.load_full();
        let net = self.net.load_full();
        // ICMP と、他の端末から転送されてきたフロー（ICS など）はこの PC のプロセスではないので PID を引かない
        let local_app = proto != Proto::Icmp && net.is_local(src.ip());
        if local_app && !self.tun_nets.iter().any(|n| n.contains(&src.ip())) {
            // 物理NICのアドレスを送信元にした通信が TUN に入ってきた。送出NICの固定が効かずに
            // 自分の送出ソケットが TUN へ戻ってきている（ループ）か、アプリが物理NICのアドレスに bind している
            self.log_throttled(format!("物理NICのアドレスから TUN に入った {proto} フロー: {src} → {dst}（ループの疑い）"));
        }
        // プロセス判定は接続テーブルを引くので重い。まずプロセス抜きで評価し、
        // プロセス情報が要る行に達したときだけ PID を引いて評価し直す
        let first = decide(&rules, &net, proto, src, dst, if local_app { None } else { Some(None) });
        let (process, rule_line, target, looked_up) = match first {
            Some((line, target)) => (None, line, target, false),
            None => {
                let rules = rules.clone();
                let r = tokio::task::spawn_blocking(move || {
                    let owner = procinfo::lookup(proto, src, since);
                    let (line, target) = decide(&rules, &net, proto, src, dst, Some(owner.as_ref())).expect("プロセスが既知なら必ず決まる");
                    (owner.map(|(_, name)| name), line, target)
                })
                .await
                .unwrap_or((None, None, Target::Accept));
                (r.0, r.1, r.2, true)
            }
        };
        let mut rec = ConnRecord {
            id: 0,
            time: now_hms(),
            proto,
            src,
            dst,
            process,
            rule_line,
            action: String::new(),
            counters: Arc::default(),
            state: ConnState::Connecting,
        };
        let egress = match &target {
            Target::Drop | Target::Reject => {
                rec.action = target.to_string();
                rec.state = ConnState::Blocked;
                None
            }
            t => match self.egress(t, dst).await {
                Ok((label, e)) => {
                    rec.action = label;
                    Some(e)
                }
                Err(msg) => {
                    rec.action = t.to_string();
                    rec.state = ConnState::Failed(msg);
                    None
                }
            },
        };
        let blocked = rec.state == ConnState::Blocked;
        let counters = rec.counters.clone();
        let id = self.shared.push_conn(rec);
        if !looked_up && local_app {
            // 表示用のプロセス名は接続を待たせずに後から埋める
            let ctx = self.clone();
            tokio::spawn(async move {
                if let Some(name) = lookup_process(proto, src, since).await {
                    ctx.shared.update_conn(id, |r| r.process = Some(name));
                }
            });
        }
        Decision { id, egress, counters, blocked, rules }
    }

    /// ターゲットから接続先と出口を決める。戻り値の文字列は接続表の「動作」欄
    async fn egress(&self, target: &Target, dst: SocketAddr) -> Result<(String, Egress), String> {
        match target {
            Target::Dnat { oif, .. } => {
                let to = target.dnat_dest(dst.port()).expect("DNAT");
                match oif {
                    Some(name) => {
                        let b = self.resolve(&Target::Route(name.clone()), to.ip()).await?;
                        Ok((format!("DNAT → {to} ({})", b.name), Egress { bind: Some(b), to }))
                    }
                    None => Ok((format!("DNAT → {to}"), Egress { bind: None, to })),
                }
            }
            t => {
                let b = self.resolve(t, dst.ip()).await?;
                Ok((format!("→ {}", b.name), Egress { bind: Some(b), to: dst }))
            }
        }
    }

    pub(super) fn finish(&self, id: u64, state: ConnState) {
        self.shared.update_conn(id, |r| r.state = state);
    }
}

/// ルールを評価して（マッチした行, ターゲット）を返す。
/// DNAT 先がこの PC で、フローの送信元がその待ち受けプロセス自身なら、そのルールは飛ばす
/// （プロキシが外へ出す通信が自分に戻ってくる無限ループを防ぐ）。ICMP は DNAT できない。
///
/// `owner` は送信元プロセス。外側の None は未判定で、プロセス情報が要る行に達したら None を返す。
/// 判定済み（`Some(Some(..))`）の場合は待ち受けプロセスを引くためブロッキングになりうる
fn decide(
    rules: &RuleSet,
    net: &NetView,
    proto: Proto,
    src: SocketAddr,
    dst: SocketAddr,
    owner: Option<Option<&(u32, String)>>,
) -> Option<(Option<usize>, Target)> {
    let process = match owner {
        None => Owner::Unknown,
        Some(o) => Owner::Known(o.map(|(_, n)| n.as_str())),
    };
    let flow = Flow { proto, src: src.ip(), dst: dst.ip(), dport: dst.port(), process };
    let v = rules.evaluate_with(&flow, |t| {
        let Some(to) = t.dnat_dest(dst.port()) else { return Some(true) };
        if proto == Proto::Icmp {
            return Some(false);
        }
        if !net.is_local(to.ip()) {
            return Some(true);
        }
        Some(match owner? {
            Some((pid, _)) => procinfo::listener_pid(proto, to.port()) != Some(*pid),
            None => true,
        })
    })?;
    Some((v.rule.map(|i| rules.rules[i].line), v.target.clone()))
}

async fn lookup_process(proto: Proto, src: SocketAddr, since: Instant) -> Option<String> {
    tokio::task::spawn_blocking(move || procinfo::lookup(proto, src, since).map(|(_, name)| name)).await.ok().flatten()
}

pub(super) async fn net_refresher(ctx: Arc<Ctx>) {
    let mut tick = tokio::time::interval(NETVIEW_TTL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        ctx.reload_net().await;
    }
}

pub(super) struct Decision {
    pub(super) id: u64,
    pub(super) egress: Option<Egress>,
    pub(super) counters: Arc<Counters>,
    /// DROP / REJECT で遮断した
    pub(super) blocked: bool,
    /// 評価に使ったルール（変更されたかの判定用）
    pub(super) rules: Arc<RuleSet>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotspot_redirect_rules_apply_to_forwarded_and_nat_flows() {
        let rules =
            crate::rules::parse("-A OUTPUT -p udp --dport 443 -j DROP\n-A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080")
                .unwrap();
        let net = NetView { at: Instant::now(), ifaces: Vec::new(), auto: [None; 2] };
        // 元の端末アドレスでも、ICS により TUN のアドレスへ NAT された場合でも同じルールに当たる。
        for source in ["192.168.137.48:50000", "10.233.0.2:50000", "[fd7a:233::2]:50000"] {
            let src = source.parse().unwrap();
            for port in [80, 443] {
                let dst = SocketAddr::new("203.0.113.1".parse().unwrap(), port);
                let (line, target) = decide(&rules, &net, Proto::Tcp, src, dst, Some(None)).unwrap();
                assert_eq!(line, Some(2));
                assert_eq!(target.dnat_dest(port), Some("127.0.0.1:8080".parse().unwrap()));
            }
            let dst = "203.0.113.1:443".parse().unwrap();
            assert_eq!(decide(&rules, &net, Proto::Udp, src, dst, Some(None)), Some((Some(1), Target::Drop)));
        }
    }
}

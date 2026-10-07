//! ルーターエンジン本体。
//!
//! Wintun アダプタ → ipstack（ユーザー空間 TCP/IP スタック）でフローを終端 →
//! ルール評価 → `IP_UNICAST_IF` で物理NICに固定したソケットから再送出する。

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use ipnet::IpNet;
use ipstack::{IpNumber, IpStack, IpStackConfig, IpStackStream, TcpConfig};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use wintun_bindings::{Adapter, Session};

use crate::rules::{BypassRoute, Flow, Owner, Proto, RuleSet, Target};
use crate::tundev::TunDevice;
use crate::pacer::{FailCache, Slots, TokenBucket};
use crate::{icmp, procinfo, winnet};

const MAX_CONN_RECORDS: usize = 2000;
const MAX_LOG_LINES: usize = 1000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const NETVIEW_TTL: Duration = Duration::from_secs(5);
const NETVIEW_RETRY_MIN: Duration = Duration::from_secs(1);
const RELAY_BUF: usize = 64 * 1024;
/// 遮断中の UDP フローがルールの変更を確かめる間隔
const BLOCKED_UDP_RECHECK: Duration = Duration::from_secs(1);
/// ipstack 既定の 16KB では 1 接続あたりの未ACK量が頭打ちになり遅いので広げる
/// （ipstack は Window Scale 非対応なので実効ウィンドウは最大 64KB）
const TCP_BUF: usize = 256 * 1024;
const TUN_ROUTE_METRIC: u32 = 1;
/// 再作成しても Windows 側にネットワークプロファイルが増殖しないよう GUID を固定する
const ADAPTER_GUID: u128 = 0x5f1c_2a7e_93b4_4d61_a0e8_7c3b_19d2_e604;

/// `{5F1C2A7E-93B4-4D61-A0E8-7C3B19D2E604}` 形式
fn adapter_guid_string() -> String {
    let h = format!("{ADAPTER_GUID:032X}");
    format!("{{{}-{}-{}-{}-{}}}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    /// 0.0.0.0/1 + 128.0.0.0/1 を TUN に向ける（既存の既定経路は触らない）
    Split,
    /// 経路は追加しない。「経路」タブで TUN 向けの経路を手動で入れる
    Manual,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub tun_name: String,
    pub tun_ipv4: Ipv4Addr,
    pub tun_prefix: u8,
    pub capture_ipv6: bool,
    pub tun_ipv6: Ipv6Addr,
    pub mtu: u16,
    pub route_mode: RouteMode,
    /// TUN の IP 転送を有効にする（ホットスポットなどで転送されてきた端末の通信に応答を返すのに必要）
    pub tun_forwarding: bool,
    /// 外への新規 TCP 接続の上限（件/秒）。0 なら制限しない
    pub connect_rate: u32,
    /// 新規 TCP 接続をまとめて出してよい件数
    pub connect_burst: u32,
    /// 接続中（応答待ち）の TCP 接続の同時数の上限。0 なら制限しない
    pub connect_concurrency: u32,
    /// つながらなかった宛先へ再び接続を出すまでの秒数。0 なら保留しない
    pub connect_fail_hold: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            tun_name: "WinIptables".into(),
            tun_ipv4: Ipv4Addr::new(10, 233, 0, 2),
            tun_prefix: 24,
            // IPv6 を捕捉しないと、IPv6 が使える環境では通信がルールを素通りする
            capture_ipv6: true,
            tun_ipv6: "fd7a:233::2".parse().unwrap(),
            // TCP は TUN で終端して張り直すので、TUN の MTU は経路 MTU と無関係に大きくできる。
            // 大きいほど TUN を往復するパケット数が減る（64KB 窓に複数セグメント載る程度に抑える）
            mtu: 9000,
            route_mode: RouteMode::Split,
            tun_forwarding: true,
            // ルーターの「IP フラッド検出」などに引っかからない程度に抑える
            connect_rate: 10,
            connect_burst: 30,
            connect_concurrency: 16,
            connect_fail_hold: 10,
        }
    }
}

// ───────────────────────── GUI と共有する状態 ─────────────────────────

#[derive(Default)]
pub struct Counters {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Open,
    Closed,
    Blocked,
    Failed(String),
}

pub struct ConnRecord {
    pub id: u64,
    pub time: String,
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub process: Option<String>,
    pub rule_line: Option<usize>,
    pub action: String,
    pub counters: Arc<Counters>,
    pub state: ConnState,
}

#[derive(Default)]
pub struct Shared {
    pub rules: ArcSwap<RuleSet>,
    pub conns: Mutex<VecDeque<ConnRecord>>,
    pub logs: Mutex<VecDeque<String>>,
    pub active: AtomicUsize,
    pub total: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    next_id: AtomicU64,
}

impl Shared {
    pub fn log(&self, msg: impl Into<String>) {
        let mut logs = self.logs.lock();
        if logs.len() >= MAX_LOG_LINES {
            logs.pop_front();
        }
        let line = format!("{} {}", now_hms(), msg.into());
        crate::config::append_log(&line);
        logs.push_back(line);
    }

    /// 接続表の集計（状態ごとの件数と、直近の失敗）をログに残す。停止時の調査用
    fn log_conn_summary(&self) {
        let lines = {
            let conns = self.conns.lock();
            let mut by_state: std::collections::BTreeMap<String, usize> = Default::default();
            for c in conns.iter() {
                let key = match &c.state {
                    ConnState::Failed(_) => "失敗".to_string(),
                    s => format!("{s:?}"),
                };
                *by_state.entry(format!("{} {key}", c.proto)).or_default() += 1;
            }
            let mut v = vec![format!(
                "接続の集計（直近 {} 件）: {}",
                conns.len(),
                by_state.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join(", ")
            )];
            v.extend(conns.iter().rev().filter(|c| matches!(c.state, ConnState::Failed(_))).take(30).map(|c| {
                let ConnState::Failed(m) = &c.state else { unreachable!() };
                format!(
                    "  失敗 {} {} {} → {} [{}] {} 行={:?}: {m}",
                    c.time,
                    c.proto,
                    c.src,
                    c.dst,
                    c.process.as_deref().unwrap_or("?"),
                    c.action,
                    c.rule_line
                )
            }));
            v
        };
        for l in lines {
            self.log(l);
        }
    }

    fn push_conn(&self, mut rec: ConnRecord) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        rec.id = id;
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut conns = self.conns.lock();
        if conns.len() >= MAX_CONN_RECORDS {
            conns.pop_front();
        }
        conns.push_back(rec);
        id
    }

    fn update_conn(&self, id: u64, f: impl FnOnce(&mut ConnRecord)) {
        let mut conns = self.conns.lock();
        if let Some(r) = conns.iter_mut().rev().find(|r| r.id == id) {
            f(r);
        }
    }
}

pub fn now_hms() -> String {
    let t = unsafe {
        let mut t = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t);
        t
    };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

// ───────────────────────── 送出インターフェースの解決 ─────────────────────────

/// NIC 一覧と「自動選択」の出口のスナップショット。バックグラウンドで定期的に差し替える
struct NetView {
    at: Instant,
    ifaces: Vec<winnet::Iface>,
    /// TUN 以外で最優先の既定経路を持つ NIC の LUID（[IPv4, IPv6]）
    auto: [Option<u64>; 2],
}

impl NetView {
    /// ブロッキング（IP Helper API を複数回呼ぶ）。非同期タスクからは spawn_blocking 経由で呼ぶ
    fn load(tun_luid: u64) -> Self {
        let ifaces = winnet::list_interfaces().unwrap_or_default();
        let routes = winnet::list_routes().unwrap_or_default();
        let auto = [false, true].map(|v6| winnet::best_default_route(&routes, tun_luid, v6).map(|r| r.luid));
        Self { at: Instant::now(), ifaces, auto }
    }

    /// この PC 自身のアドレスか（ループバック・未指定・いずれかの NIC のアドレス）
    fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || self.ifaces.iter().any(|i| i.addrs.iter().any(|(a, _)| *a == ip))
    }
}

/// 送出NICに固定するための情報
struct Bound {
    name: String,
    index: u32,
    src: IpAddr,
}

/// 接続先と出口。`bind` が None なら OS の経路表に任せる（DNAT で -o 省略時）
struct Egress {
    bind: Option<Bound>,
    to: SocketAddr,
}

struct Ctx {
    shared: Arc<Shared>,
    tun_luid: u64,
    tun_nets: Vec<IpNet>,
    net: ArcSwap<NetView>,
    started: Instant,
    throttle_at: AtomicU64,
    throttle_skipped: AtomicU64,
    connect_rate: TokenBucket,
    connect_slots: Slots,
    connect_fails: FailCache,
}

impl Ctx {
    async fn reload_net(&self) {
        let luid = self.tun_luid;
        if let Ok(v) = tokio::task::spawn_blocking(move || NetView::load(luid)).await {
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
    async fn paced_connect(&self, eg: &Egress) -> io::Result<TcpStream> {
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
    fn log_throttled(&self, msg: String) {
        let now = self.started.elapsed().as_secs();
        let last = self.throttle_at.swap(now, Ordering::Relaxed);
        let skipped = self.throttle_skipped.fetch_add(1, Ordering::Relaxed);
        if now != last || skipped == 0 {
            self.throttle_skipped.store(0, Ordering::Relaxed);
            let more = if skipped > 1 { format!("（ほか {} 件）", skipped - 1) } else { String::new() };
            self.shared.log(format!("{msg}{more}"));
        }
    }

    fn resolve_in(&self, net: &NetView, target: &Target, dst: IpAddr) -> Result<Bound, String> {
        let v6 = dst.is_ipv6();
        let fam = if v6 { "IPv6" } else { "IPv4" };
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
        let src = winnet::best_source(iface.luid, dst).or_else(|| iface.first_addr(v6)).ok_or_else(|| format!("\"{}\" に {fam} アドレスがありません", iface.name))?;
        Ok(Bound { name: iface.name.clone(), index: iface.index, src })
    }

    /// TUN 宛て・マルチキャスト・ブロードキャストは外へ出さず黙って捨てる
    fn is_local_noise(&self, dst: IpAddr) -> bool {
        let special = match dst {
            IpAddr::V4(a) => a.is_multicast() || a.is_broadcast() || a.is_link_local(),
            IpAddr::V6(a) => a.is_multicast() || a.is_unicast_link_local(),
        };
        special || self.tun_nets.iter().any(|n| n.contains(&dst))
    }

    /// `since` はフローが TUN に届いた時刻（接続テーブルのスナップショットを使い回せるかの判断に使う）
    async fn evaluate(self: &Arc<Self>, proto: Proto, src: SocketAddr, dst: SocketAddr, since: Instant) -> Decision {
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
                    let (line, target) =
                        decide(&rules, &net, proto, src, dst, Some(owner.as_ref())).expect("プロセスが既知なら必ず決まる");
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

    fn finish(&self, id: u64, state: ConnState) {
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

async fn net_refresher(ctx: Arc<Ctx>) {
    let mut tick = tokio::time::interval(NETVIEW_TTL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        ctx.reload_net().await;
    }
}

struct Decision {
    id: u64,
    egress: Option<Egress>,
    counters: Arc<Counters>,
    /// DROP / REJECT で遮断した
    blocked: bool,
    /// 評価に使ったルール（変更されたかの判定用）
    rules: Arc<RuleSet>,
}

// ───────────────────────── 送出ソケット ─────────────────────────

fn bound_socket(b: &Bound, dst: SocketAddr, ty: Type, proto: Protocol) -> io::Result<Socket> {
    let s = Socket::new(Domain::for_address(dst), ty, Some(proto))?;
    winnet::set_unicast_if(s.as_raw_socket() as usize, b.index, dst.is_ipv6())?;
    s.bind(&SocketAddr::new(b.src, 0).into())?;
    s.set_nonblocking(true)?;
    Ok(s)
}

fn plain_socket(dst: SocketAddr, ty: Type, proto: Protocol) -> io::Result<Socket> {
    let s = Socket::new(Domain::for_address(dst), ty, Some(proto))?;
    s.set_nonblocking(true)?;
    Ok(s)
}

async fn connect_tcp(eg: &Egress) -> io::Result<TcpStream> {
    let s = match &eg.bind {
        Some(b) => bound_socket(b, eg.to, Type::STREAM, Protocol::TCP)?,
        None => plain_socket(eg.to, Type::STREAM, Protocol::TCP)?,
    };
    s.set_tcp_nodelay(true)?;
    let sock = TcpSocket::from_std_stream(s.into());
    tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(eg.to))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "接続タイムアウト"))?
}

fn bind_udp(eg: &Egress) -> io::Result<UdpSocket> {
    let s = match &eg.bind {
        Some(b) => bound_socket(b, eg.to, Type::DGRAM, Protocol::UDP)?,
        None => plain_socket(eg.to, Type::DGRAM, Protocol::UDP)?,
    };
    s.connect(&eg.to.into())?;
    UdpSocket::from_std(s.into())
}

async fn pipe(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
    ctr: &AtomicU64,
    total: &AtomicU64,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        ctr.fetch_add(n as u64, Ordering::Relaxed);
        total.fetch_add(n as u64, Ordering::Relaxed);
    }
    w.shutdown().await
}

// ───────────────────────── フローごとの処理 ─────────────────────────

async fn handle_tcp(ctx: Arc<Ctx>, tcp: ipstack::IpStackTcpStream) {
    let (src, dst, since) = (tcp.local_addr(), tcp.peer_addr(), Instant::now());
    if ctx.is_local_noise(dst.ip()) {
        return;
    }
    let d = ctx.evaluate(Proto::Tcp, src, dst, since).await;
    // DROP/REJECT/解決失敗時は tcp を drop して RST を返す
    let Some(eg) = d.egress else { return };
    let res = ctx.paced_connect(&eg).await;
    let remote = match res {
        Ok(s) => s,
        Err(e) => return ctx.finish(d.id, ConnState::Failed(e.to_string())),
    };
    ctx.finish(d.id, ConnState::Open);
    ctx.shared.active.fetch_add(1, Ordering::Relaxed);
    let (ar, aw) = tokio::io::split(tcp);
    let (br, bw) = remote.into_split();
    let s = &ctx.shared;
    let res = tokio::try_join!(pipe(ar, bw, &d.counters.up, &s.bytes_up), pipe(br, aw, &d.counters.down, &s.bytes_down));
    s.active.fetch_sub(1, Ordering::Relaxed);
    ctx.finish(d.id, match res {
        Ok(_) => ConnState::Closed,
        Err(e) if is_benign(&e) => ConnState::Closed,
        Err(e) => ConnState::Failed(e.to_string()),
    });
}

fn is_benign(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe | TimedOut | UnexpectedEof | NotConnected)
}

async fn handle_udp(ctx: Arc<Ctx>, mut udp: ipstack::IpStackUdpStream) {
    let (src, dst, since) = (udp.local_addr(), udp.peer_addr(), Instant::now());
    if ctx.is_local_noise(dst.ip()) {
        return;
    }
    let d = ctx.evaluate(Proto::Udp, src, dst, since).await;
    if d.blocked {
        return hold_blocked_udp(&ctx, udp, &d).await;
    }
    let Some(eg) = d.egress else { return };
    let sock = match bind_udp(&eg) {
        Ok(s) => s,
        Err(e) => return ctx.finish(d.id, ConnState::Failed(e.to_string())),
    };
    ctx.finish(d.id, ConnState::Open);
    let s = &ctx.shared;
    s.active.fetch_add(1, Ordering::Relaxed);
    let mut a = vec![0u8; 65536];
    let mut b = vec![0u8; 65536];
    let res: io::Result<()> = async {
        loop {
            tokio::select! {
                // アイドルが続くと ipstack 側が TimedOut を返して終わる
                n = udp.read(&mut a) => {
                    let n = n?;
                    if n == 0 { return Ok(()) }
                    sock.send(&a[..n]).await?;
                    d.counters.up.fetch_add(n as u64, Ordering::Relaxed);
                    s.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                }
                n = sock.recv(&mut b) => match n {
                    Ok(n) => {
                        udp.write_all(&b[..n]).await?;
                        d.counters.down.fetch_add(n as u64, Ordering::Relaxed);
                        s.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    // ICMP Port Unreachable を受けると Windows は WSAECONNRESET を返すが、UDP では無視してよい
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(e) => return Err(e),
                },
            }
        }
    }
    .await;
    s.active.fetch_sub(1, Ordering::Relaxed);
    ctx.finish(d.id, match res {
        Ok(()) => ConnState::Closed,
        Err(e) if is_benign(&e) => ConnState::Closed,
        Err(e) => ConnState::Failed(e.to_string()),
    });
}

/// 遮断した UDP フローはすぐ閉じると、アプリの再送（QUIC など）のたびに別フローとして評価・記録し直し、
/// そのたびに接続テーブルも引くことになる。フローを開いたまま読み捨てて接続表の 1 件にまとめる。
/// アイドルで ipstack がフローを閉じるか、ルールが変わったら終わる（次のパケットで評価し直す）
async fn hold_blocked_udp(ctx: &Ctx, mut udp: ipstack::IpStackUdpStream, d: &Decision) {
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            n = udp.read(&mut buf) => match n {
                Ok(0) | Err(_) => return,
                // 遮断した量を「↑」に出す（全体の送信量には数えない）
                Ok(n) => drop(d.counters.up.fetch_add(n as u64, Ordering::Relaxed)),
            },
            _ = tokio::time::sleep(BLOCKED_UDP_RECHECK) => {}
        }
        if !Arc::ptr_eq(&ctx.shared.rules.load(), &d.rules) {
            return;
        }
    }
}

async fn handle_icmp(ctx: Arc<Ctx>, u: ipstack::IpStackUnknownTransport) {
    use etherparse::{Icmpv4Header, Icmpv4Type};
    let (IpAddr::V4(_), IpAddr::V4(dst)) = (u.src_addr(), u.dst_addr()) else { return };
    if u.ip_protocol() != IpNumber::ICMP || ctx.is_local_noise(dst.into()) {
        return;
    }
    let Ok((hdr, data)) = Icmpv4Header::from_slice(u.payload()) else { return };
    let Icmpv4Type::EchoRequest(echo) = hdr.icmp_type else { return };
    let d = ctx.evaluate(Proto::Icmp, SocketAddr::new(u.src_addr(), 0), SocketAddr::new(dst.into(), 0), Instant::now()).await;
    let Some(eg) = d.egress else { return };
    let Some(IpAddr::V4(src)) = eg.bind.map(|b| b.src) else { return };
    let req = data.to_vec();
    d.counters.up.fetch_add(req.len() as u64, Ordering::Relaxed);
    let reply = tokio::task::spawn_blocking(move || icmp::echo_v4(src, dst, &req, 64, 4000)).await.ok().flatten();
    let Some(payload) = reply else {
        return ctx.finish(d.id, ConnState::Failed("応答なし".into()));
    };
    d.counters.down.fetch_add(payload.len() as u64, Ordering::Relaxed);
    let mut resp = Icmpv4Header::new(Icmpv4Type::EchoReply(echo));
    resp.update_checksum(&payload);
    let mut pkt = resp.to_bytes().to_vec();
    pkt.extend_from_slice(&payload);
    let _ = u.send(pkt);
    ctx.finish(d.id, ConnState::Closed);
}

async fn accept_loop(ctx: Arc<Ctx>, mut stack: IpStack) {
    loop {
        let stream = match stack.accept().await {
            Ok(s) => s,
            Err(e) => {
                ctx.shared.log(format!("IP スタック停止: {e}"));
                return;
            }
        };
        let c = ctx.clone();
        match stream {
            IpStackStream::Tcp(t) => drop(tokio::spawn(handle_tcp(c, t))),
            IpStackStream::Udp(u) => drop(tokio::spawn(handle_udp(c, u))),
            IpStackStream::UnknownTransport(u) => drop(tokio::spawn(handle_icmp(c, u))),
            IpStackStream::UnknownNetwork(_) => {}
        }
    }
}

// ───────────────────────── 起動・停止・経路管理 ─────────────────────────

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
    adapter: Arc<Adapter>,
    rx_thread: std::thread::JoinHandle<()>,
    tun_routes: Vec<InstalledRoute>,
    bypass: Vec<(BypassRoute, InstalledRoute)>,
    shared: Arc<Shared>,
    pub tun_luid: u64,
}

impl Engine {
    pub fn start(config: EngineConfig, shared: Arc<Shared>) -> anyhow::Result<Engine> {
        let wintun = load_wintun()?;
        let adapter = Adapter::create(&wintun, &config.tun_name, "WinIptables", Some(ADAPTER_GUID))
            .context("Wintun アダプタの作成に失敗（管理者権限が必要です）")?;
        let tun_luid = unsafe { adapter.get_luid().Value };

        winnet::add_address(tun_luid, config.tun_ipv4.into(), config.tun_prefix).context("TUN への IPv4 付与に失敗")?;
        let mut tun_nets = vec![IpNet::new(config.tun_ipv4.into(), config.tun_prefix)?.trunc()];
        if config.capture_ipv6 {
            winnet::add_address(tun_luid, config.tun_ipv6.into(), 64).context("TUN への IPv6 付与に失敗")?;
            tun_nets.push(IpNet::new(config.tun_ipv6.into(), 64)?.trunc());
        }
        if let Err(e) = adapter.set_mtu(config.mtu as usize) {
            shared.log(format!("MTU 設定に失敗（続行）: {e}"));
        }
        // ICS などで他の端末から転送されてきたフローの応答は TUN から入って LAN 側へ転送されるので、
        // TUN でも転送を有効にしておく（アダプタごと消えるので停止時の後始末は不要）
        let fwd_families = if config.tun_forwarding { 1 + config.capture_ipv6 as usize } else { 0 };
        for v6 in [false, true].into_iter().take(fwd_families) {
            if let Err(e) = winnet::enable_forwarding(tun_luid, v6) {
                shared.log(format!("TUN の IP 転送を有効にできません（転送されてきた通信の中継に影響、続行）: {e}"));
            }
        }
        let session = adapter.start_session(wintun_bindings::MAX_RING_CAPACITY)?;

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("router").build()?;
        let net = ArcSwap::from_pointee(NetView::load(tun_luid));
        let ctx = Arc::new(Ctx {
            shared: shared.clone(),
            tun_luid,
            tun_nets,
            net,
            started: Instant::now(),
            throttle_at: AtomicU64::new(u64::MAX),
            throttle_skipped: AtomicU64::new(0),
            connect_rate: TokenBucket::new(config.connect_rate, config.connect_burst),
            connect_slots: Slots::new(config.connect_concurrency),
            connect_fails: FailCache::new(Duration::from_secs(config.connect_fail_hold as u64)),
        });
        // ACCEPT の出口（調査用）
        let probes: [IpAddr; 2] = [Ipv4Addr::new(8, 8, 8, 8).into(), "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap().into()];
        for probe in probes {
            let fam = if probe.is_ipv6() { "IPv6" } else { "IPv4" };
            match ctx.resolve_in(&ctx.net.load(), &Target::Accept, probe) {
                Ok(b) => shared.log(format!("{fam} の自動選択の出口: \"{}\" (#{}) 送信元 {}", b.name, b.index, b.src)),
                Err(e) => shared.log(format!("{fam} の自動選択の出口: なし（{e}）")),
            }
        }

        let mut tcp = TcpConfig::default();
        tcp.timeout = Duration::from_secs(600);
        tcp.max_unacked_bytes = TCP_BUF as u32;
        tcp.read_buffer_size = TCP_BUF;
        let mut ipcfg = IpStackConfig::default();
        ipcfg.mtu(config.mtu)?.udp_timeout(Duration::from_secs(60)).with_tcp_config(tcp);
        let tun_addrs = vec![config.tun_ipv4.into(), config.tun_ipv6.into()];
        let (device, rx_thread) = TunDevice::new(session.clone(), config.mtu as usize, tun_addrs);
        let stack = rt.block_on(async { IpStack::new(ipcfg, device) });
        rt.spawn(net_refresher(ctx.clone()));
        rt.spawn(accept_loop(ctx, stack));

        let mut engine = Engine {
            config,
            rt,
            session,
            adapter,
            rx_thread,
            tun_routes: Vec::new(),
            bypass: Vec::new(),
            shared,
            tun_luid,
        };
        if let Err(e) = engine.install_tun_routes() {
            engine.stop();
            return Err(e);
        }
        let rules = engine.shared.rules.load_full();
        engine.sync_bypass(&rules);
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
        let mut nets: Vec<IpNet> = vec!["0.0.0.0/1".parse()?, "128.0.0.0/1".parse()?];
        if self.config.capture_ipv6 {
            nets.extend(["::/1".parse::<IpNet>()?, "8000::/1".parse()?]);
        }
        for dst in nets {
            // アダプタ起動直後はインターフェースが未準備で失敗することがあるので少し待って再試行
            let mut last = None;
            for _ in 0..20 {
                match winnet::add_route(self.tun_luid, dst, None, TUN_ROUTE_METRIC) {
                    Ok(()) => {
                        last = None;
                        break;
                    }
                    Err(e) => last = Some(e),
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            if let Some(e) = last {
                bail!("経路 {dst} → TUN の追加に失敗: {e}");
            }
            self.tun_routes.push(InstalledRoute { luid: self.tun_luid, dst, gw: None });
        }
        Ok(())
    }

    /// BYPASS ルールとカーネル経路を同期する（差分だけ追加・削除）
    pub fn sync_bypass(&mut self, rules: &RuleSet) {
        let (keep, remove): (Vec<_>, Vec<_>) = std::mem::take(&mut self.bypass).into_iter().partition(|(b, _)| rules.bypass.contains(b));
        for (b, r) in remove {
            match r.remove() {
                Ok(()) => self.shared.log(format!("BYPASS 経路を削除: {} → {}", b.dst, b.oif)),
                Err(e) => self.shared.log(format!("BYPASS 経路の削除に失敗: {} ({e})", b.dst)),
            }
        }
        self.bypass = keep;
        for b in &rules.bypass {
            if self.bypass.iter().any(|(x, _)| x == b) {
                continue;
            }
            match add_route_by_name(&b.oif, b.dst, b.gw, b.metric.unwrap_or(TUN_ROUTE_METRIC)) {
                Ok(r) => {
                    self.shared.log(format!("BYPASS 経路を追加: {} → {}", b.dst, b.oif));
                    self.bypass.push((b.clone(), r));
                }
                Err(e) => self.shared.log(format!("{e:#}")),
            }
        }
    }

    /// 経路を先に消すので、後段（アダプタの削除など）が戻らずに打ち切られても通信は物理NICに戻る。
    /// どこで止まったか分かるよう段階ごとにログを残す
    pub fn stop(self) {
        self.shared.log_conn_summary();
        self.shared.log("停止: 経路を削除");
        for (_, r) in &self.bypass {
            let _ = r.remove();
        }
        for r in &self.tun_routes {
            let _ = r.remove();
        }
        self.shared.log("停止: 受信スレッドの終了待ち");
        let _ = self.session.shutdown();
        let _ = self.rx_thread.join();
        self.shared.log("停止: 中継処理の終了待ち");
        self.rt.shutdown_timeout(Duration::from_secs(2));
        // 共有したまま消すと ICS の設定が壊れて残り、ホットスポットも共有を設定できなくなる
        self.shared.log("停止: TUN の共有（ICS）を確認");
        match crate::ics::release(&adapter_guid_string()) {
            Ok(true) => self.shared.log("TUN の共有（ICS）を解除しました"),
            Ok(false) => {}
            Err(e) => self.shared.log(format!("TUN の共有（ICS）を確認できません（続行）: {e}")),
        }
        self.shared.log("停止: TUN アダプタを削除");
        drop(self.session);
        // 作成したアダプタは CloseAdapter で削除され、TUN 向けの経路も一緒に消える
        drop(self.adapter);
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

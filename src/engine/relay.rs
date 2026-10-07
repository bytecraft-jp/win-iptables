//! TCP・UDP・ICMP フローの中継。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ipstack::{IpNumber, IpStack, IpStackStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::flow::{Ctx, Decision};
use super::network::bind_udp;
use super::state::ConnState;
use crate::{icmp, rules::Proto};

const RELAY_BUF: usize = 64 * 1024;
/// UDP データグラムの最大長
const UDP_BUF: usize = 65536;
/// 遮断中の UDP フローがルールの変更を確かめる間隔
const BLOCKED_UDP_RECHECK: Duration = Duration::from_secs(1);

/// 接続ごとの量と全体の量を数える
fn count(conn: &AtomicU64, total: &AtomicU64, n: usize) {
    conn.fetch_add(n as u64, Ordering::Relaxed);
    total.fetch_add(n as u64, Ordering::Relaxed);
}

async fn pipe(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin, ctr: &AtomicU64, total: &AtomicU64) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        count(ctr, total, n);
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
        Err(e) => {
            if e.kind() == io::ErrorKind::ConnectionRefused && eg.to.ip().is_loopback() {
                ctx.log_throttled(format!("転送先 {} が接続を拒否しました。プロキシなどが起動しているか確認してください", eg.to));
            }
            return ctx.finish(d.id, ConnState::Failed(e.to_string()));
        }
    };
    let connection = ctx.shared.open_conn(d.id);
    let (ar, aw) = tokio::io::split(tcp);
    let (br, bw) = remote.into_split();
    let s = &ctx.shared;
    let res = tokio::try_join!(pipe(ar, bw, &d.counters.up, &s.bytes_up), pipe(br, aw, &d.counters.down, &s.bytes_down));
    connection.finish(res.map(|_| ()));
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
    let s = &ctx.shared;
    let connection = s.open_conn(d.id);
    let mut a = vec![0u8; UDP_BUF];
    let mut b = vec![0u8; UDP_BUF];
    let res: io::Result<()> = async {
        loop {
            tokio::select! {
                // アイドルが続くと ipstack 側が TimedOut を返して終わる
                n = udp.read(&mut a) => {
                    let n = n?;
                    if n == 0 { return Ok(()) }
                    sock.send(&a[..n]).await?;
                    count(&d.counters.up, &s.bytes_up, n);
                }
                n = sock.recv(&mut b) => match n {
                    Ok(n) => {
                        udp.write_all(&b[..n]).await?;
                        count(&d.counters.down, &s.bytes_down, n);
                    }
                    // ICMP Port Unreachable を受けると Windows は WSAECONNRESET を返すが、UDP では無視してよい
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(e) => return Err(e),
                },
            }
        }
    }
    .await;
    connection.finish(res);
}

/// 遮断した UDP フローはすぐ閉じると、アプリの再送（QUIC など）のたびに別フローとして評価・記録し直し、
/// そのたびに接続テーブルも引くことになる。フローを開いたまま読み捨てて接続表の 1 件にまとめる。
/// アイドルで ipstack がフローを閉じるか、ルールが変わったら終わる（次のパケットで評価し直す）
async fn hold_blocked_udp(ctx: &Ctx, mut udp: ipstack::IpStackUdpStream, d: &Decision) {
    let mut buf = vec![0u8; UDP_BUF];
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

pub(super) async fn accept_loop(ctx: Arc<Ctx>, mut stack: IpStack) {
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

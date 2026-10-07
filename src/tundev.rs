//! Wintun セッションを tokio の AsyncRead/AsyncWrite として見せるデバイス。
//!
//! 受信は専用スレッド 1 本がリングを読み続ける。リングにパケットがある間は
//! システムコールなしで連続して取り出し、空になったときだけイベントで眠る。
//! wintun-bindings の AsyncSession のように待機のたびにスレッドプールへ投げないので、
//! 起床ごとのスレッド受け渡しが無くなる。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::thread::JoinHandle;

use arc_swap::ArcSwapOption;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wintun_bindings::Session;

/// 受信キューの深さ。溢れると読み取りスレッドが待つ（＝リング側で背圧がかかる）
const RX_QUEUE: usize = 4096;

/// 他の端末（ICS / モバイルホットスポット配下など）へ転送されるパケットの上限。
/// ipstack は相手の MSS を見ずに TUN の MTU いっぱいの DF 付きセグメントを作るので、
/// そのままだと Windows が MTU 1500 の LAN 側へ転送できずに捨て、大きな応答が届かない
const FORWARD_MTU: usize = 1500;

/// 送信に使うセッション。停止時に空にすると、IP スタック側の後片付けが済んでいなくても
/// セッション（とアダプタ）を閉じられる。空の間に書かれたパケットは捨てる
pub type SessionSlot = Arc<ArcSwapOption<Session>>;

pub struct TunDevice {
    session: SessionSlot,
    rx: mpsc::Receiver<Vec<u8>>,
    mtu: usize,
    /// TUN 自身のアドレス。これ以外が宛先のパケットは Windows が他の端末へ転送する
    local: Vec<IpAddr>,
    /// true の間は宛先によらず分け直す。TUN を共有元にしたホットスポットでは、端末宛てのパケットも
    /// 共有の NAT を戻す前は TUN 自身宛てに見えるため、宛先では見分けられない
    split_all: Arc<AtomicBool>,
}

impl TunDevice {
    /// 戻り値の [`SessionSlot`] は停止時に空にする
    pub fn new(session: Arc<Session>, mtu: usize, local: Vec<IpAddr>, split_all: Arc<AtomicBool>) -> (Self, JoinHandle<()>, SessionSlot) {
        let (tx, rx) = mpsc::channel(RX_QUEUE);
        let reader = session.clone();
        let handle = std::thread::Builder::new()
            .name("wintun-rx".into())
            .spawn(move || {
                // shutdown() されると receive_blocking が Err を返して抜ける
                while let Ok(pkt) = reader.receive_blocking() {
                    if tx.blocking_send(pkt.bytes().to_vec()).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn wintun-rx");
        let slot: SessionSlot = Arc::new(ArcSwapOption::from(Some(session)));
        (Self { session: slot.clone(), rx, mtu, local, split_all }, handle, slot)
    }

    fn send(&self, buf: &[u8]) {
        let session = self.session.load();
        let Some(session) = session.as_ref() else { return };
        // 送信リングが満杯なら NIC と同じくパケットを落とす（TCP は再送で回復する）
        if let Ok(mut pkt) = session.allocate_send_packet(buf.len() as u16) {
            pkt.bytes_mut().copy_from_slice(buf);
            session.send_packet(pkt);
        }
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.rx.poll_recv(cx) {
                // MTU を超えるパケットは IP スタックの読み取りバッファに入らないので捨てる
                Poll::Ready(Some(p)) if p.len() > self.mtu || p.len() > buf.remaining() => continue,
                Poll::Ready(Some(p)) => {
                    buf.put_slice(&p);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // ipstack は 1 回の書き込みで 1 パケットを渡す
        if buf.len() > FORWARD_MTU
            && (self.split_all.load(Ordering::Relaxed) || dst_of(buf).is_some_and(|d| !self.local.contains(&d)))
            && let Some(parts) = split_for_forward(buf)
        {
            for p in &parts {
                self.send(p);
            }
        } else {
            self.send(buf);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ───────────────────────── 転送先向けの分割 ─────────────────────────

const PROTO_TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const IPV4_DF: u8 = 0x40;

fn dst_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(pkt.get(16..20)?).ok()?).into()),
        6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(24..40)?).ok()?).into()),
        _ => None,
    }
}

/// `pkt` を [`FORWARD_MTU`] 以下に収める。TCP はセグメントに分け直し、
/// それ以外の IPv4 は DF を外して Windows に IP フラグメントさせる。扱えない形なら None（そのまま書く）
fn split_for_forward(pkt: &[u8]) -> Option<Vec<Vec<u8>>> {
    let v4 = pkt[0] >> 4 == 4;
    // IPv6 は拡張ヘッダなし（ipstack は付けない）のときだけ扱う
    let (ip_len, proto) = if v4 { ((pkt[0] & 0x0f) as usize * 4, *pkt.get(9)?) } else { (40, *pkt.get(6)?) };
    if proto != PROTO_TCP {
        if !v4 {
            return None;
        }
        let mut p = pkt.to_vec();
        p[6] &= !IPV4_DF;
        ipv4_checksum(&mut p, ip_len);
        return Some(vec![p]);
    }
    let tcp_len = (*pkt.get(ip_len + 12)? >> 4) as usize * 4;
    let hdr = ip_len + tcp_len;
    let mss = FORWARD_MTU.checked_sub(hdr).filter(|&m| m > 0)?;
    let payload = pkt.get(hdr..).filter(|p| !p.is_empty())?;
    let seq = u32::from_be_bytes(pkt[ip_len + 4..ip_len + 8].try_into().ok()?);
    let flags = pkt[ip_len + 13];
    let last = payload.len().div_ceil(mss) - 1;
    let parts = payload
        .chunks(mss)
        .enumerate()
        .map(|(i, chunk)| {
            let mut p = Vec::with_capacity(hdr + chunk.len());
            p.extend_from_slice(&pkt[..hdr]);
            p.extend_from_slice(chunk);
            let total = p.len() as u16;
            if v4 {
                p[2..4].copy_from_slice(&total.to_be_bytes());
                ipv4_checksum(&mut p, ip_len);
            } else {
                p[4..6].copy_from_slice(&(total - 40).to_be_bytes());
            }
            p[ip_len + 4..ip_len + 8].copy_from_slice(&seq.wrapping_add((i * mss) as u32).to_be_bytes());
            // FIN と PSH は最後のセグメントにだけ残す
            if i != last {
                p[ip_len + 13] = flags & !(TCP_FIN | TCP_PSH);
            }
            tcp_checksum(&mut p, ip_len, v4);
            p
        })
        .collect();
    Some(parts)
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    for c in data.chunks(2) {
        acc += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn ipv4_checksum(p: &mut [u8], ihl: usize) {
    p[10..12].fill(0);
    let c = fold(sum16(&p[..ihl], 0));
    p[10..12].copy_from_slice(&c.to_be_bytes());
}

fn tcp_checksum(p: &mut [u8], ip_len: usize, v4: bool) {
    p[ip_len + 16..ip_len + 18].fill(0);
    // 疑似ヘッダ: 送信元・宛先アドレス + プロトコル + TCP 長
    let addrs = if v4 { &p[12..20] } else { &p[8..40] };
    let acc = sum16(addrs, PROTO_TCP as u32 + (p.len() - ip_len) as u32);
    let c = fold(sum16(&p[ip_len..], acc));
    p[ip_len + 16..ip_len + 18].copy_from_slice(&c.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, TransportHeader};

    fn big_tcp(v4: bool, len: usize, fin: bool) -> Vec<u8> {
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let b =
            if v4 { PacketBuilder::ipv4([8, 8, 8, 8], [192, 168, 137, 50], 64) } else { PacketBuilder::ipv6([0x20; 16], [0xfd; 16], 64) };
        let mut b = b.tcp(443, 50000, 0xffff_fff0, 65535).ack(1234).psh();
        if fin {
            b = b.fin();
        }
        let mut out = Vec::new();
        b.write(&mut out, &payload).unwrap();
        out
    }

    fn check(pkt: &[u8], fin: bool) {
        let parts = split_for_forward(pkt).unwrap();
        let orig = PacketHeaders::from_ip_slice(pkt).unwrap();
        let mut joined = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            assert!(p.len() <= FORWARD_MTU);
            let h = PacketHeaders::from_ip_slice(p).unwrap();
            let Some(TransportHeader::Tcp(tcp)) = &h.transport else { panic!() };
            let data = h.payload.slice();
            let sum = match &h.net {
                Some(NetHeaders::Ipv4(ip, _)) => {
                    assert_eq!(ip.header_checksum, ip.calc_header_checksum());
                    assert!(ip.dont_fragment);
                    tcp.calc_checksum_ipv4(ip, data).unwrap()
                }
                Some(NetHeaders::Ipv6(ip, _)) => tcp.calc_checksum_ipv6(ip, data).unwrap(),
                _ => panic!(),
            };
            assert_eq!(tcp.checksum, sum, "segment {i}");
            assert_eq!(tcp.sequence_number, 0xffff_fff0u32.wrapping_add(joined.len() as u32));
            let is_last = i == parts.len() - 1;
            assert_eq!(tcp.psh, is_last);
            assert_eq!(tcp.fin, is_last && fin);
            assert!(tcp.ack);
            joined.extend_from_slice(data);
        }
        assert_eq!(joined, orig.payload.slice());
    }

    #[test]
    fn splits_tcp_for_forwarding() {
        check(&big_tcp(true, 8900, true), true);
        check(&big_tcp(false, 8900, false), false);
        assert_eq!(split_for_forward(&big_tcp(true, 1460 * 3, false)).unwrap().len(), 3);
    }

    #[test]
    fn clears_df_on_large_ipv4_udp() {
        let mut out = Vec::new();
        PacketBuilder::ipv4([8, 8, 8, 8], [192, 168, 137, 50], 64).udp(53, 50000).write(&mut out, &[0u8; 4000]).unwrap();
        let parts = split_for_forward(&out).unwrap();
        let h = PacketHeaders::from_ip_slice(&parts[0]).unwrap();
        let Some(NetHeaders::Ipv4(ip, _)) = &h.net else { panic!() };
        assert!(!ip.dont_fragment);
        assert_eq!(ip.header_checksum, ip.calc_header_checksum());
        assert_eq!(dst_of(&out), Some("192.168.137.50".parse().unwrap()));
    }
}

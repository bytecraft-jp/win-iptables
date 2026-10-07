//! NIC スナップショット、転送設定、送出ソケット。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use super::state::Shared;
use crate::winnet;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// NIC 一覧と「自動選択」の出口のスナップショット。バックグラウンドで定期的に差し替える
pub(super) struct NetView {
    pub(super) at: Instant,
    pub(super) ifaces: Vec<winnet::Iface>,
    /// TUN 以外で最優先の既定経路を持つ NIC の LUID（[IPv4, IPv6]）
    pub(super) auto: [Option<u64>; 2],
}

impl NetView {
    /// ブロッキング（IP Helper API を複数回呼ぶ）。非同期タスクからは spawn_blocking 経由で呼ぶ
    pub(super) fn load(tun_luid: u64) -> Self {
        let ifaces = winnet::list_interfaces().unwrap_or_default();
        let routes = winnet::list_routes().unwrap_or_default();
        let auto = [false, true].map(|v6| winnet::best_default_route(&routes, tun_luid, v6).map(|r| r.luid));
        Self { at: Instant::now(), ifaces, auto }
    }

    /// この PC 自身のアドレスか（ループバック・未指定・いずれかの NIC のアドレス）
    pub(super) fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || self.ifaces.iter().any(|i| i.addrs.iter().any(|(a, _)| *a == ip))
    }
}

/// 出口 NIC の IP 転送を無効に保つ。ホットスポット（ICS）は共有元の NIC で転送を有効にするが、
/// 転送が有効な NIC から出すパケットは bind / IP_UNICAST_IF を無視して経路表どおりに送られ、
/// TUN の 0.0.0.0/1 に吸い込まれて自分の送出が TUN へ戻るループになる。
/// 端末からの通信はホットスポット側の NIC → TUN と流れるので、出口側の転送は無くても中継できる
#[derive(Default)]
pub(super) struct EgressForwarding {
    state: Mutex<ForwardingState>,
}

#[derive(Default)]
struct ForwardingState {
    stopped: bool,
    /// 無効にした (LUID, IPv6 か, 名前)
    disabled: Vec<(u64, bool, String)>,
}

impl EgressForwarding {
    /// ブロッキング。既定ゲートウェイを持つ NIC（ホットスポット側の NIC は持たない）を対象にする
    pub(super) fn enforce(&self, net: &NetView, tun_luid: u64, shared: &Shared) {
        let mut state = self.state.lock();
        if state.stopped {
            return;
        }
        for i in net.ifaces.iter().filter(|i| i.up && !i.loopback && i.luid != tun_luid) {
            for v6 in [false, true] {
                if i.gateway(v6).is_none() || winnet::forwarding_enabled(i.luid, v6) != Some(true) {
                    continue;
                }
                let fam = winnet::family(v6);
                match winnet::set_forwarding(i.luid, v6, false) {
                    Ok(()) => {
                        shared.log(format!(
                            "\"{}\" の {fam} 転送が有効になったので無効にしました（Windows の設定からホットスポットをオンにした場合など。有効のままだと送出が TUN に戻ってループする。端末の通信も通すには win-iptables の「ホットスポット」ボタンを使ってください）",
                            i.name
                        ));
                        if !state.disabled.iter().any(|(l, f, _)| *l == i.luid && *f == v6) {
                            state.disabled.push((i.luid, v6, i.name.clone()));
                        }
                    }
                    Err(e) => shared.log(format!("\"{}\" の {fam} 転送を無効にできません（送出がループするおそれ）: {e}", i.name)),
                }
            }
        }
    }

    /// 停止時に戻す。ICS がまだ動いている（ほかの NIC で転送が有効な）ときだけ戻し、
    /// ホットスポットが先に止まっていたら無効のままにする（ICS が止めるときも無効に戻すため）
    pub(super) fn restore(&self, tun_luid: u64, shared: &Shared) {
        let disabled = {
            let mut state = self.state.lock();
            state.stopped = true;
            std::mem::take(&mut state.disabled)
        };
        if disabled.is_empty() {
            return;
        }
        let ifs = winnet::list_interfaces().unwrap_or_default();
        let ics_active = ifs.iter().filter(|i| i.up && !i.loopback && i.luid != tun_luid).any(|i| {
            [false, true].into_iter().any(|v6| {
                !disabled.iter().any(|(l, f, _)| *l == i.luid && *f == v6) && winnet::forwarding_enabled(i.luid, v6) == Some(true)
            })
        });
        if !ics_active {
            return;
        }
        for (luid, v6, name) in disabled {
            let fam = winnet::family(v6);
            match winnet::set_forwarding(luid, v6, true) {
                Ok(()) => shared.log(format!("\"{name}\" の {fam} 転送を元に戻しました（ホットスポット用）")),
                Err(e) => shared.log(format!("\"{name}\" の {fam} 転送を元に戻せません: {e}")),
            }
        }
    }
}

/// 送出NICに固定するための情報
pub(super) struct Bound {
    pub(super) name: String,
    pub(super) index: u32,
    pub(super) src: IpAddr,
}

/// 接続先と出口。`bind` が None なら OS の経路表に任せる（DNAT で -o 省略時）
pub(super) struct Egress {
    pub(super) bind: Option<Bound>,
    pub(super) to: SocketAddr,
}

impl Egress {
    fn socket(&self, ty: Type, proto: Protocol) -> io::Result<Socket> {
        let socket = Socket::new(Domain::for_address(self.to), ty, Some(proto))?;
        if let Some(bound) = &self.bind {
            winnet::set_unicast_if(socket.as_raw_socket() as usize, bound.index, self.to.is_ipv6())?;
            socket.bind(&SocketAddr::new(bound.src, 0).into())?;
        }
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}

pub(super) async fn connect_tcp(eg: &Egress) -> io::Result<TcpStream> {
    let s = eg.socket(Type::STREAM, Protocol::TCP)?;
    s.set_tcp_nodelay(true)?;
    let sock = TcpSocket::from_std_stream(s.into());
    tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(eg.to))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "接続タイムアウト"))?
}

pub(super) fn bind_udp(eg: &Egress) -> io::Result<UdpSocket> {
    let s = eg.socket(Type::DGRAM, Protocol::UDP)?;
    s.connect(&eg.to.into())?;
    UdpSocket::from_std(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn unbound_tcp_and_udp_reach_local_destination() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let egress = Egress { bind: None, to: listener.local_addr().unwrap() };
            let mut client = connect_tcp(&egress).await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            client.write_all(b"request").await.unwrap();
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");

            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let egress = Egress { bind: None, to: server.local_addr().unwrap() };
            let client = bind_udp(&egress).unwrap();
            client.send(b"request").await.unwrap();
            let (size, source) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..size], b"request");
            server.send_to(b"reply", source).await.unwrap();
            let size = client.recv(&mut request).await.unwrap();
            assert_eq!(&request[..size], b"reply");
        })
        .await
        .expect("local relay timed out");
    }
}

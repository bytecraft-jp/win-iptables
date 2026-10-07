//! TUN に入ってきたフローの送信元ポートから、通信しているプロセスを特定する

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::rules::Proto;

/// テーブル取得 API を呼び、行のスライスを返す（先頭 4 バイトが行数）
fn fetch_table<R: Copy>(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Vec<R> {
    let mut size = 0u32;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        let r = call(if buf.is_empty() { ptr::null_mut() } else { buf.as_mut_ptr().cast() }, &mut size);
        if r == ERROR_INSUFFICIENT_BUFFER {
            buf = vec![0; (size as usize).div_ceil(8) + 64];
            size = (buf.len() * 8) as u32;
            continue;
        }
        if r != ERROR_SUCCESS || buf.is_empty() {
            return Vec::new();
        }
        let n = unsafe { *(buf.as_ptr() as *const u32) } as usize;
        let rows = unsafe { (buf.as_ptr() as *const u8).add(4) as *const R };
        return unsafe { std::slice::from_raw_parts(rows, n) }.to_vec();
    }
    Vec::new()
}

fn tcp_table<R: Copy>(af: u16) -> Vec<R> {
    fetch_table(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, af as u32, TCP_TABLE_OWNER_PID_ALL, 0) })
}

fn udp_table<R: Copy>(af: u16) -> Vec<R> {
    fetch_table(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, af as u32, UDP_TABLE_OWNER_PID, 0) })
}

fn port_of(p: u32) -> u16 {
    u16::from_be(p as u16)
}

fn v4(addr: u32) -> IpAddr {
    Ipv4Addr::from(addr.to_ne_bytes()).into()
}

/// 接続テーブル 1 回分のスナップショット（ローカルポート → (ローカルアドレス, PID)）
struct Table {
    at: Instant,
    rows: HashMap<u16, Vec<(IpAddr, u32)>>,
}

impl Table {
    fn fetch(proto: Proto, v6: bool) -> Self {
        // 取得前の時刻を記録する（これより前に存在したソケットは必ず含まれる）
        let at = Instant::now();
        let mut rows: HashMap<u16, Vec<(IpAddr, u32)>> = HashMap::new();
        let mut push = |port: u32, addr: IpAddr, pid: u32| rows.entry(port_of(port)).or_default().push((addr, pid));
        match (proto, v6) {
            (Proto::Tcp, false) => {
                tcp_table::<MIB_TCPROW_OWNER_PID>(AF_INET).iter().for_each(|r| push(r.dwLocalPort, v4(r.dwLocalAddr), r.dwOwningPid))
            }
            (Proto::Tcp, true) => tcp_table::<MIB_TCP6ROW_OWNER_PID>(AF_INET6)
                .iter()
                .for_each(|r| push(r.dwLocalPort, Ipv6Addr::from(r.ucLocalAddr).into(), r.dwOwningPid)),
            (Proto::Udp, false) => {
                udp_table::<MIB_UDPROW_OWNER_PID>(AF_INET).iter().for_each(|r| push(r.dwLocalPort, v4(r.dwLocalAddr), r.dwOwningPid))
            }
            (Proto::Udp, true) => udp_table::<MIB_UDP6ROW_OWNER_PID>(AF_INET6)
                .iter()
                .for_each(|r| push(r.dwLocalPort, Ipv6Addr::from(r.ucLocalAddr).into(), r.dwOwningPid)),
            (Proto::Icmp, _) => {}
        }
        Self { at, rows }
    }

    fn find(&self, proto: Proto, local: SocketAddr) -> Option<u32> {
        let hits = self.rows.get(&local.port())?;
        let exact = hits.iter().find(|(a, _)| *a == local.ip());
        match proto {
            // UDP はワイルドカード bind が多いので、アドレス一致を優先しつつポートだけでも拾う
            Proto::Udp => exact.or(hits.first()),
            _ => exact,
        }
        .map(|(_, pid)| *pid)
    }
}

/// [TCPv4, TCPv6, UDPv4, UDPv6] の直近のスナップショット
static TABLES: [Mutex<Option<Table>>; 4] = [const { Mutex::new(None) }; 4];

/// TUN 側から見た送信元アドレス（= アプリが bind したローカルアドレス）の所有 PID
pub fn owner_pid(proto: Proto, local: SocketAddr) -> Option<u32> {
    owner_pid_since(proto, local, Instant::now())
}

/// `since`（フローが TUN に届いた時刻）より後に取ったスナップショットがあれば、テーブルを引き直さずにそれを使う。
/// フローのソケットはその時点で既にあるので、後から取ったスナップショットには必ず載っている。
/// 取得中はロックを握るので、同時に来たフローの問い合わせは 1 回の取得にまとまる
pub fn owner_pid_since(proto: Proto, local: SocketAddr, since: Instant) -> Option<u32> {
    let idx = match proto {
        Proto::Tcp => 0,
        Proto::Udp => 2,
        Proto::Icmp => return None,
    } + local.is_ipv6() as usize;
    let mut slot = TABLES[idx].lock();
    if let Some(t) = slot.as_ref()
        && t.at >= since
    {
        return t.find(proto, local);
    }
    let t = Table::fetch(proto, local.is_ipv6());
    let pid = t.find(proto, local);
    *slot = Some(t);
    pid
}

const MIB_TCP_STATE_LISTEN: u32 = 2;
const LISTENER_TTL: Duration = Duration::from_secs(2);

type ListenerCache = HashMap<(bool, u16), (Option<u32>, Instant)>;
static LISTENER_CACHE: LazyLock<Mutex<ListenerCache>> = LazyLock::new(Default::default);

/// ローカルで `port` を待ち受けているプロセスの PID（TCP は LISTEN、UDP は bind 中）。
/// DNAT 先のプロキシ自身の通信を見分けるのに使う。接続ごとに呼ばれるので短時間キャッシュする
pub fn listener_pid(proto: Proto, port: u16) -> Option<u32> {
    let tcp = proto == Proto::Tcp;
    let key = (tcp, port);
    if let Some((pid, at)) = LISTENER_CACHE.lock().get(&key)
        && at.elapsed() < LISTENER_TTL
    {
        return *pid;
    }
    let pid = if tcp {
        let listening = |state: u32, local_port: u32| state == MIB_TCP_STATE_LISTEN && port_of(local_port) == port;
        tcp_table::<MIB_TCPROW_OWNER_PID>(AF_INET).iter().find(|r| listening(r.dwState, r.dwLocalPort)).map(|r| r.dwOwningPid).or_else(
            || tcp_table::<MIB_TCP6ROW_OWNER_PID>(AF_INET6).iter().find(|r| listening(r.dwState, r.dwLocalPort)).map(|r| r.dwOwningPid),
        )
    } else {
        owner_pid(Proto::Udp, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
            .or_else(|| owner_pid(Proto::Udp, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)))
    };
    LISTENER_CACHE.lock().insert(key, (pid, Instant::now()));
    pid
}

const CACHE_TTL: Duration = Duration::from_secs(30);

const NAME_CACHE_MAX: usize = 4096;

static NAME_CACHE: LazyLock<Mutex<HashMap<u32, (String, Instant)>>> = LazyLock::new(Default::default);

/// PID から小文字の実行ファイル名（例: "chrome.exe"）を得る
pub fn process_name(pid: u32) -> Option<String> {
    match pid {
        0 => return Some("idle".into()),
        4 => return Some("system".into()),
        _ => {}
    }
    let mut map = NAME_CACHE.lock();
    if let Some((name, at)) = map.get(&pid)
        && at.elapsed() < CACHE_TTL
    {
        return Some(name.clone());
    }
    let name = query_image_name(pid)?;
    if map.len() > NAME_CACHE_MAX {
        map.retain(|_, (_, at)| at.elapsed() < CACHE_TTL);
    }
    map.insert(pid, (name.clone(), Instant::now()));
    Some(name)
}

fn query_image_name(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        Some(path.rsplit('\\').next().unwrap_or(&path).to_lowercase())
    }
}

/// `since` はフローが TUN に届いた時刻（[`owner_pid_since`] を参照）
pub fn lookup(proto: Proto, local: SocketAddr, since: Instant) -> Option<(u32, String)> {
    let pid = owner_pid_since(proto, local, since)?;
    Some((pid, process_name(pid).unwrap_or_else(|| format!("pid:{pid}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_tcp_and_udp_sockets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let me = std::process::id();
        assert_eq!(owner_pid(Proto::Tcp, client.local_addr().unwrap()), Some(me));
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(owner_pid(Proto::Udp, udp.local_addr().unwrap()), Some(me));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(listener_pid(Proto::Tcp, listener.local_addr().unwrap().port()), Some(me));
        assert_eq!(listener_pid(Proto::Udp, udp.local_addr().unwrap().port()), Some(me));
        // 古いスナップショットは使わず、後から開いたソケットも見つかる
        let udp2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(owner_pid_since(Proto::Udp, udp2.local_addr().unwrap(), Instant::now()), Some(me));
        // 届いた時刻より後のスナップショットは再利用される
        let since = Instant::now();
        let udp3 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(owner_pid_since(Proto::Udp, udp3.local_addr().unwrap(), since), Some(me));
        let at = TABLES[2].lock().as_ref().unwrap().at;
        assert_eq!(owner_pid_since(Proto::Udp, udp3.local_addr().unwrap(), since), Some(me));
        assert_eq!(TABLES[2].lock().as_ref().unwrap().at, at);
        let name = process_name(me).unwrap();
        assert!(name.starts_with("win_iptables") && name.ends_with(".exe"), "{name}");
    }
}

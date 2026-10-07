//! IP Helper API の薄いラッパ（インターフェース列挙・経路・アドレス・ソケットの送出NIC固定）

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use ipnet::IpNet;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN_ADDR, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
    MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET, setsockopt,
};

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub description: String,
    pub index: u32,
    pub luid: u64,
    pub up: bool,
    pub loopback: bool,
    pub addrs: Vec<(IpAddr, u8)>,
    pub gateways: Vec<IpAddr>,
}

impl Iface {
    pub fn first_addr(&self, v6: bool) -> Option<IpAddr> {
        let usable = |a: &IpAddr| match a {
            IpAddr::V4(a) => !v6 && !a.is_link_local(),
            // リンクローカルは送信元として使えないので除外
            IpAddr::V6(a) => v6 && !a.is_unicast_link_local(),
        };
        self.addrs.iter().map(|(a, _)| *a).find(usable)
    }

    pub fn gateway(&self, v6: bool) -> Option<IpAddr> {
        self.gateways.iter().copied().find(|g| g.is_ipv6() == v6)
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub dst: IpNet,
    pub next_hop: IpAddr,
    pub luid: u64,
    pub metric: u32,
    pub protocol: i32,
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(code as i32)) }
}

fn luid(v: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: v }
}

unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

unsafe fn from_sockaddr(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let sin = &*(sa as *const SOCKADDR_IN);
                Some(Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()).into())
            }
            AF_INET6 => {
                let sin6 = &*(sa as *const SOCKADDR_IN6);
                Some(Ipv6Addr::from(sin6.sin6_addr.u.Byte).into())
            }
            _ => None,
        }
    }
}

fn from_inet(sa: &SOCKADDR_INET) -> IpAddr {
    unsafe {
        if sa.si_family == AF_INET6 {
            Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte).into()
        } else {
            Ipv4Addr::from(sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()
        }
    }
}

fn to_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(a) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: unsafe { std::mem::transmute::<[u8; 4], _>(a.octets()) } },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(a) => unsafe {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr = IN6_ADDR { u: std::mem::transmute::<[u8; 16], _>(a.octets()) };
        },
    }
    sa
}

pub fn list_interfaces() -> io::Result<Vec<Iface>> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64>;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let p = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), p, &mut size) };
        if r == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        check(r)?;
        break;
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        let a = unsafe { &*p };
        let mut addrs = Vec::new();
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            let ua = unsafe { &*u };
            if let Some(ip) = unsafe { from_sockaddr(ua.Address.lpSockaddr) } {
                addrs.push((ip, ua.OnLinkPrefixLength));
            }
            u = ua.Next;
        }
        let mut gateways = Vec::new();
        let mut g = a.FirstGatewayAddress;
        while !g.is_null() {
            let ga = unsafe { &*g };
            if let Some(ip) = unsafe { from_sockaddr(ga.Address.lpSockaddr) } {
                gateways.push(ip);
            }
            g = ga.Next;
        }
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        out.push(Iface {
            name: unsafe { wstr(a.FriendlyName) },
            description: unsafe { wstr(a.Description) },
            index: if index != 0 { index } else { a.Ipv6IfIndex },
            luid: unsafe { a.Luid.Value },
            up: a.OperStatus == IfOperStatusUp,
            loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
            addrs,
            gateways,
        });
        p = a.Next;
    }
    Ok(out)
}

/// インターフェースを名前（大文字小文字無視）・説明・`#インデックス` のいずれかで探す
pub fn find_iface<'a>(ifs: &'a [Iface], key: &str) -> Option<&'a Iface> {
    if let Some(idx) = key.strip_prefix('#').and_then(|s| s.parse::<u32>().ok()) {
        return ifs.iter().find(|i| i.index == idx);
    }
    ifs.iter()
        .find(|i| i.name.eq_ignore_ascii_case(key))
        .or_else(|| ifs.iter().find(|i| i.description.eq_ignore_ascii_case(key)))
}

pub fn list_routes() -> io::Result<Vec<Route>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    check(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })?;
    let rows = unsafe {
        let n = (*table).NumEntries as usize;
        std::slice::from_raw_parts(ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(), n)
    };
    let out = rows
        .iter()
        .filter_map(|r| {
            let dst = IpNet::new(from_inet(&r.DestinationPrefix.Prefix), r.DestinationPrefix.PrefixLength).ok()?;
            Some(Route {
                dst,
                next_hop: from_inet(&r.NextHop),
                luid: unsafe { r.InterfaceLuid.Value },
                metric: r.Metric,
                protocol: r.Protocol,
            })
        })
        .collect();
    unsafe { FreeMibTable(table as _) };
    Ok(out)
}

fn route_row(if_luid: u64, dst: IpNet, next_hop: Option<IpAddr>, metric: u32) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(if_luid);
    row.DestinationPrefix.Prefix = to_inet(dst.network());
    row.DestinationPrefix.PrefixLength = dst.prefix_len();
    let unspecified = match dst {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    row.NextHop = to_inet(next_hop.unwrap_or(unspecified));
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// 経路を追加する（アクティブストアのみ。再起動で消える）
pub fn add_route(if_luid: u64, dst: IpNet, next_hop: Option<IpAddr>, metric: u32) -> io::Result<()> {
    check(unsafe { CreateIpForwardEntry2(&route_row(if_luid, dst, next_hop, metric)) })
}

pub fn delete_route(if_luid: u64, dst: IpNet, next_hop: Option<IpAddr>) -> io::Result<()> {
    check(unsafe { DeleteIpForwardEntry2(&route_row(if_luid, dst, next_hop, 0)) })
}

pub fn add_address(if_luid: u64, addr: IpAddr, prefix: u8) -> io::Result<()> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid(if_luid);
    row.Address = to_inet(addr);
    row.OnLinkPrefixLength = prefix;
    row.DadState = windows_sys::Win32::Networking::WinSock::IpDadStatePreferred;
    check(unsafe { CreateUnicastIpAddressEntry(&row) })
}

pub fn interface_metric(if_luid: u64, v6: bool) -> Option<u32> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = if v6 { AF_INET6 } else { AF_INET };
    row.InterfaceLuid = luid(if_luid);
    check(unsafe { GetIpInterfaceEntry(&mut row) }).ok()?;
    Some(row.Metric)
}

/// `if_luid` の NIC から `dst` へ送るときに Windows が選ぶ送信元アドレス（RFC 6724。IPv6 なら一時アドレスを優先）
pub fn best_source(if_luid: u64, dst: IpAddr) -> Option<IpAddr> {
    let luid = luid(if_luid);
    let dst = to_inet(dst);
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    check(unsafe { GetBestRoute2(&luid, 0, ptr::null(), &dst, 0, &mut route, &mut src) }).ok()?;
    let ip = from_inet(&src);
    (!ip.is_unspecified()).then_some(ip)
}

/// インターフェースの IP 転送を有効にする（受信したインターフェースで転送が有効でないと Windows は転送しない）
pub fn enable_forwarding(if_luid: u64, v6: bool) -> io::Result<()> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = if v6 { AF_INET6 } else { AF_INET };
    row.InterfaceLuid = luid(if_luid);
    check(unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.ForwardingEnabled = true;
    // IPv4 では SitePrefixLength を 0 にしないと SetIpInterfaceEntry が失敗する
    if !v6 {
        row.SitePrefixLength = 0;
    }
    check(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// `exclude_luid` 以外で最も優先される既定経路のインターフェースインデックス
pub fn best_default_route(routes: &[Route], exclude_luid: u64, v6: bool) -> Option<&Route> {
    routes
        .iter()
        .filter(|r| r.dst.prefix_len() == 0 && r.dst.addr().is_ipv6() == v6 && r.luid != exclude_luid)
        .min_by_key(|r| r.metric.saturating_add(interface_metric(r.luid, v6).unwrap_or(0)))
}

/// ソケットの送出インターフェースを固定する（ルーティングテーブルの最長一致より優先される）
pub fn set_unicast_if(sock: SOCKET, if_index: u32, v6: bool) -> io::Result<()> {
    // IPv4 はネットワークバイトオーダー、IPv6 はホストバイトオーダーで渡す仕様
    let (level, opt, val) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, if_index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, if_index.to_be())
    };
    let r = unsafe { setsockopt(sock, level, opt, ptr::addr_of!(val).cast(), 4) };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_interfaces_and_routes() {
        let ifs = list_interfaces().unwrap();
        assert!(ifs.iter().any(|i| i.loopback), "loopback should exist");
        let routes = list_routes().unwrap();
        assert!(routes.iter().any(|r| r.dst == "127.0.0.0/8".parse::<IpNet>().unwrap()));
        // 経路の LUID はインターフェース一覧から引けるはず
        assert!(routes.iter().all(|r| ifs.iter().any(|i| i.luid == r.luid)));
    }

    #[test]
    fn best_source_is_an_address_of_that_interface() {
        let ifs = list_interfaces().unwrap();
        let dsts: [IpAddr; 2] = [Ipv4Addr::new(8, 8, 8, 8).into(), "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap().into()];
        for i in ifs.iter().filter(|i| i.up && !i.loopback) {
            for dst in dsts {
                if i.gateway(dst.is_ipv6()).is_none() {
                    continue;
                }
                if let Some(src) = best_source(i.luid, dst) {
                    println!("{} {dst} -> {src}", i.name);
                    assert!(i.addrs.iter().any(|(a, _)| *a == src), "{} {src}", i.name);
                }
            }
        }
    }
}

//! ICMP echo の中継。生ソケットを使わず、送信元アドレス指定付きの IcmpSendEcho2Ex で物理NICから送る。

use std::net::Ipv4Addr;
use std::ptr;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, IP_SUCCESS, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex,
};

/// 成功すれば応答ペイロードを返す（ブロッキング）
pub fn echo_v4(src: Ipv4Addr, dst: Ipv4Addr, data: &[u8], ttl: u8, timeout_ms: u32) -> Option<Vec<u8>> {
    unsafe {
        let h = IcmpCreateFile();
        if h.is_null() || h as isize == -1 {
            return None;
        }
        let opts = IP_OPTION_INFORMATION { Ttl: ttl, Tos: 0, Flags: 0, OptionsSize: 0, OptionsData: ptr::null_mut() };
        let size = size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + 64;
        let mut reply = vec![0u64; size.div_ceil(8)];
        let n = IcmpSendEcho2Ex(
            h,
            ptr::null_mut(),
            None,
            ptr::null(),
            u32::from_ne_bytes(src.octets()),
            u32::from_ne_bytes(dst.octets()),
            data.as_ptr().cast(),
            data.len() as u16,
            &opts,
            reply.as_mut_ptr().cast(),
            (reply.len() * 8) as u32,
            timeout_ms,
        );
        let out = (n > 0)
            .then(|| &*(reply.as_ptr() as *const ICMP_ECHO_REPLY))
            .filter(|r| r.Status == IP_SUCCESS)
            .map(|r| std::slice::from_raw_parts(r.Data as *const u8, r.DataSize as usize).to_vec());
        IcmpCloseHandle(h);
        out
    }
}

//! 設定とルールを %APPDATA%\win-iptables に保存する

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    /// 0.0.0.0/1 + 128.0.0.0/1 を TUN に向ける（既存の既定経路は触らない）
    Split,
    /// 経路は追加しない。「経路」タブで TUN 向けの経路を手動で入れる
    Manual,
}

impl RouteMode {
    fn as_str(self) -> &'static str {
        match self {
            RouteMode::Split => "split",
            RouteMode::Manual => "manual",
        }
    }
}

/// TUN の IPv6 アドレスのプレフィックス長
pub const TUN_IPV6_PREFIX: u8 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    pub tun_name: String,
    pub tun_ipv4: Ipv4Addr,
    pub tun_prefix: u8,
    pub capture_ipv6: bool,
    pub tun_ipv6: Ipv6Addr,
    pub mtu: u16,
    pub route_mode: RouteMode,
    /// 開始と同時に、TUN を共有元にしたモバイル ホットスポットもオンにする
    pub hotspot_auto: bool,
    /// ホットスポットの名前（SSID）。空欄なら Windows の設定画面のもの
    pub hotspot_ssid: String,
    /// ホットスポットのパスワード。空欄なら Windows の設定画面のもの
    pub hotspot_passphrase: String,
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
            hotspot_auto: false,
            hotspot_ssid: String::new(),
            hotspot_passphrase: String::new(),
            // ルーターの「IP フラッド検出」などに引っかからない程度に抑える
            connect_rate: 10,
            connect_burst: 30,
            connect_concurrency: 16,
            connect_fail_hold: 10,
        }
    }
}

impl EngineConfig {
    /// TUN に付けるアドレスとプレフィックス長（IPv6 は捕捉するときだけ）
    pub fn tun_addrs(&self) -> Vec<(IpAddr, u8)> {
        let mut v = vec![(self.tun_ipv4.into(), self.tun_prefix)];
        if self.capture_ipv6 {
            v.push((self.tun_ipv6.into(), TUN_IPV6_PREFIX));
        }
        v
    }
}

fn dir() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    base.join("win-iptables")
}

/// ログの書き出し先。画面のログは閉じると消えるので、調査用に同じ内容をここへ追記していく
pub fn log_path() -> PathBuf {
    dir().join("win-iptables.log")
}

/// 1 MB を超えたら .old に回して新しく始める
const LOG_MAX: u64 = 1024 * 1024;

pub fn append_log(line: &str) {
    use std::io::Write;
    let path = log_path();
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = std::fs::rename(&path, path.with_extension("log.old"));
    }
    let _ = std::fs::create_dir_all(dir());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

pub fn rules_path() -> PathBuf {
    dir().join("rules.conf")
}

fn settings_path() -> PathBuf {
    dir().join("settings.conf")
}

pub fn load_rules() -> String {
    std::fs::read_to_string(rules_path()).unwrap_or_else(|_| crate::rules::SAMPLE.to_string())
}

fn write(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir())?;
    std::fs::write(path, contents)
}

pub fn save_rules(text: &str) -> std::io::Result<()> {
    write(&rules_path(), text)
}

pub fn load_settings() -> EngineConfig {
    parse_settings(&std::fs::read_to_string(settings_path()).unwrap_or_default())
}

fn parse_settings(text: &str) -> EngineConfig {
    let mut c = EngineConfig::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        match k.trim() {
            "tun_name" if !v.is_empty() => c.tun_name = v.to_string(),
            "tun_ipv4" => c.tun_ipv4 = v.parse().unwrap_or(c.tun_ipv4),
            "tun_prefix" => c.tun_prefix = v.parse().unwrap_or(c.tun_prefix),
            "capture_ipv6" => c.capture_ipv6 = v == "true",
            "tun_ipv6" => c.tun_ipv6 = v.parse().unwrap_or(c.tun_ipv6),
            "mtu" => c.mtu = v.parse().unwrap_or(c.mtu),
            "route_mode" => c.route_mode = if v == RouteMode::Manual.as_str() { RouteMode::Manual } else { RouteMode::Split },
            "hotspot_auto" => c.hotspot_auto = v.parse().unwrap_or(c.hotspot_auto),
            "hotspot_ssid" => c.hotspot_ssid = v.to_string(),
            "hotspot_passphrase" => c.hotspot_passphrase = v.to_string(),
            "connect_rate" => c.connect_rate = v.parse().unwrap_or(c.connect_rate),
            "connect_burst" => c.connect_burst = v.parse().unwrap_or(c.connect_burst),
            "connect_concurrency" => c.connect_concurrency = v.parse().unwrap_or(c.connect_concurrency),
            "connect_fail_hold" => c.connect_fail_hold = v.parse().unwrap_or(c.connect_fail_hold),
            _ => {}
        }
    }
    c
}

pub fn save_settings(c: &EngineConfig) -> std::io::Result<()> {
    write(&settings_path(), &format_settings(c))
}

fn format_settings(c: &EngineConfig) -> String {
    let pairs: [(&str, &dyn std::fmt::Display); 14] = [
        ("tun_name", &c.tun_name),
        ("tun_ipv4", &c.tun_ipv4),
        ("tun_prefix", &c.tun_prefix),
        ("capture_ipv6", &c.capture_ipv6),
        ("tun_ipv6", &c.tun_ipv6),
        ("mtu", &c.mtu),
        ("route_mode", &c.route_mode.as_str()),
        ("connect_rate", &c.connect_rate),
        ("connect_burst", &c.connect_burst),
        ("connect_concurrency", &c.connect_concurrency),
        ("connect_fail_hold", &c.connect_fail_hold),
        ("hotspot_auto", &c.hotspot_auto),
        ("hotspot_ssid", &c.hotspot_ssid),
        ("hotspot_passphrase", &c.hotspot_passphrase),
    ];
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={v}
"
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let custom = EngineConfig {
            tun_name: "テスト TUN=2".into(),
            tun_ipv4: "192.0.2.2".parse().unwrap(),
            tun_prefix: 28,
            capture_ipv6: false,
            tun_ipv6: "fd00::123".parse().unwrap(),
            mtu: 1500,
            route_mode: RouteMode::Manual,
            hotspot_auto: true,
            hotspot_ssid: "テスト SSID".into(),
            hotspot_passphrase: "p@ss=word 123".into(),
            connect_rate: 0,
            connect_burst: 50,
            connect_concurrency: 8,
            connect_fail_hold: 20,
        };
        for config in [EngineConfig::default(), custom] {
            assert_eq!(parse_settings(&format_settings(&config)), config);
        }
    }

    #[test]
    fn missing_invalid_and_legacy_settings_keep_defaults() {
        assert_eq!(parse_settings(""), EngineConfig::default());
        let text = "# old settings\nunknown=value\ntun_forwarding=false\ncapture_hotspot=true\ntun_name=\n\
                    tun_ipv4=invalid\ntun_ipv6=invalid\ntun_prefix=256\nmtu=invalid\n\
                    connect_rate=-1\nconnect_burst=invalid\nconnect_concurrency=invalid\nconnect_fail_hold=invalid\n";
        assert_eq!(parse_settings(text), EngineConfig::default());
    }

    #[test]
    fn whitespace_and_repeated_settings_remain_compatible() {
        let config = parse_settings(" mtu = 1500 \r\nmtu=invalid\n route_mode = manual \ncapture_ipv6=false\n");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.route_mode, RouteMode::Manual);
        assert!(!config.capture_ipv6);
    }
}

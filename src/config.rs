//! 設定とルールを %APPDATA%\win-iptables に保存する

use std::path::PathBuf;

use crate::engine::{EngineConfig, RouteMode};

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

pub fn save_rules(text: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir())?;
    std::fs::write(rules_path(), text)
}

pub fn load_settings() -> EngineConfig {
    let mut c = EngineConfig::default();
    let Ok(text) = std::fs::read_to_string(settings_path()) else { return c };
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
            "route_mode" => c.route_mode = if v == "manual" { RouteMode::Manual } else { RouteMode::Split },
            "tun_forwarding" => c.tun_forwarding = v == "true",
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
    std::fs::create_dir_all(dir())?;
    let mode = match c.route_mode {
        RouteMode::Split => "split",
        RouteMode::Manual => "manual",
    };
    std::fs::write(
        settings_path(),
        format!(
            "tun_name={}\ntun_ipv4={}\ntun_prefix={}\ncapture_ipv6={}\ntun_ipv6={}\nmtu={}\nroute_mode={mode}\ntun_forwarding={}\n\
             connect_rate={}\nconnect_burst={}\nconnect_concurrency={}\nconnect_fail_hold={}\n",
            c.tun_name,
            c.tun_ipv4,
            c.tun_prefix,
            c.capture_ipv6,
            c.tun_ipv6,
            c.mtu,
            c.tun_forwarding,
            c.connect_rate,
            c.connect_burst,
            c.connect_concurrency,
            c.connect_fail_hold
        ),
    )
}

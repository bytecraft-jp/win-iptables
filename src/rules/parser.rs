//! ルール言語の字句解析と構文解析。評価は親モジュールに置く。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnet::IpNet;

use super::{BypassRoute, Cond, Match, ParseError, PortRange, Proto, Rule, RuleSet, Target};

/// 引用符と `#` コメントを考慮して1行をトークンに分割する
pub(super) fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    in_token = true;
                }
                '#' => break,
                c if c.is_whitespace() => {
                    if in_token {
                        out.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                }
                c => {
                    cur.push(c);
                    in_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err("引用符が閉じていません".into());
    }
    if in_token {
        out.push(cur);
    }
    Ok(out)
}

/// `CIDR` または単一アドレス（ホスト経路）。ホスト部は切り捨てる
pub fn parse_cidr(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>().or_else(|_| s.parse::<IpAddr>().map(IpNet::from)).ok().map(|n| n.trunc())
}

fn parse_net(s: &str) -> Result<IpNet, String> {
    if s.eq_ignore_ascii_case("any") {
        return Ok("0.0.0.0/0".parse().unwrap());
    }
    parse_cidr(s).ok_or_else(|| format!("不正なアドレス/CIDR: {s}"))
}

fn parse_nets(s: &str) -> Result<Vec<IpNet>, String> {
    s.split(',').map(parse_net).collect()
}

fn parse_port(s: &str) -> Result<u16, String> {
    s.parse().map_err(|_| format!("不正なポート番号: {s}"))
}

fn parse_ports(s: &str) -> Result<Vec<PortRange>, String> {
    s.split(',')
        .map(|p| match p.split_once(':').or_else(|| p.split_once('-')) {
            Some((a, b)) => {
                let (a, b) = (parse_port(a)?, parse_port(b)?);
                if a > b {
                    return Err(format!("ポート範囲が逆順です: {p}"));
                }
                Ok(PortRange(a, b))
            }
            None => parse_port(p).map(|n| PortRange(n, n)),
        })
        .collect()
}

fn parse_proto(s: &str) -> Result<Option<Proto>, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        "icmp" | "icmpv6" | "ipv6-icmp" => Some(Proto::Icmp),
        "all" | "any" => None,
        _ => return Err(format!("未対応のプロトコル: {s}")),
    })
}

#[derive(PartialEq)]
enum Chain {
    Output,
    Bypass,
}

pub fn parse(text: &str) -> Result<RuleSet, Vec<ParseError>> {
    let mut rs = RuleSet::default();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        if let Err(msg) = parse_line(raw, line, &mut rs) {
            errors.push(ParseError { line, msg });
        }
    }
    if errors.is_empty() { Ok(rs) } else { Err(errors) }
}

fn parse_line(raw: &str, line: usize, rs: &mut RuleSet) -> Result<(), String> {
    let toks = tokenize(raw)?;
    let Some(cmd) = toks.first() else { return Ok(()) };
    let mut it = toks[1..].iter().map(String::as_str);

    let (insert, chain) = match cmd.as_str() {
        "-A" | "-I" | "-P" => {
            let chain = match take(&mut it, cmd)?.to_ascii_uppercase().as_str() {
                "OUTPUT" => Chain::Output,
                "BYPASS" if cmd != "-P" => Chain::Bypass,
                c => return Err(format!("未対応のチェイン: {c}")),
            };
            (cmd == "-I", chain)
        }
        c => return Err(format!("不明なコマンド: {c}（-A / -I / -P のいずれか）")),
    };

    if cmd == "-P" {
        let target = take(&mut it, "-P")?.to_ascii_uppercase();
        let mut opts = TargetOpts::default();
        while let Some(t) = it.next() {
            if !opts.parse(t, &mut it)? {
                return Err(format!("-P で使えないオプション: {t}"));
            }
        }
        rs.policy = make_target(&target, opts)?;
        return Ok(());
    }

    let mut m = Match::default();
    let mut target: Option<String> = None;
    let mut opts = TargetOpts::default();
    let mut gw: Option<IpAddr> = None;
    let mut metric: Option<u32> = None;
    let mut negate = false;

    while let Some(t) = it.next() {
        if t == "!" {
            negate = true;
            continue;
        }
        let mut val = || take(&mut it, t);
        let neg = std::mem::take(&mut negate);
        match t {
            // ここから条件（! で否定できる）
            "-p" | "--protocol" => {
                if let Some(p) = parse_proto(val()?)? {
                    m.proto = cond(neg, vec![p]);
                }
            }
            "-s" | "--source" => m.src = cond(neg, parse_nets(val()?)?),
            "-d" | "--destination" => m.dst = cond(neg, parse_nets(val()?)?),
            "--dport" | "--dports" | "--destination-port" => m.dport = cond(neg, parse_ports(val()?)?),
            "--process" | "--proc" | "--cmd-owner" => {
                m.process = cond(neg, val()?.split(',').map(|s| s.trim().to_lowercase()).collect());
            }
            "-m" | "--match" => {
                // owner / multiport などは iptables 互換のため読み捨てる。
                // `! -m owner --process x` の ! は次の条件に引き継ぐ
                val()?;
                negate = neg;
            }
            _ if neg => return Err(format!("{t} に ! は付けられません")),
            // ここから条件以外
            "-j" | "--jump" => target = Some(val()?.to_ascii_uppercase()),
            "--gw" | "--gateway" => {
                let v = val()?;
                gw = Some(v.parse().map_err(|_| format!("不正なゲートウェイ: {v}"))?);
            }
            "--metric" => {
                let v = val()?;
                metric = Some(v.parse().map_err(|_| format!("不正なメトリック: {v}"))?);
            }
            _ => {
                if !opts.parse(t, &mut it)? {
                    return Err(format!("不明なオプション: {t}"));
                }
            }
        }
    }
    if negate {
        return Err("! の後にオプションがありません".into());
    }

    match chain {
        Chain::Bypass => {
            let dst = match &m.dst {
                Some(c) if !c.negate && c.values.len() == 1 => c.values[0],
                _ => return Err("BYPASS には単一の -d CIDR が必要です（! 不可）".into()),
            };
            if m.proto.is_some() || m.src.is_some() || m.dport.is_some() || m.process.is_some() || opts.to.is_some() {
                return Err("BYPASS はカーネル経路なので -d と -o 以外の条件は使えません".into());
            }
            let oif = opts.oif.ok_or("BYPASS には -o インターフェースが必要です")?;
            rs.bypass.push(BypassRoute { dst, oif, gw, metric });
        }
        Chain::Output => {
            if gw.is_some() || metric.is_some() {
                return Err("--gw / --metric は BYPASS チェイン専用です".into());
            }
            // -j 省略かつ -o 指定なら ROUTE とみなす
            let target = match target {
                Some(t) => make_target(&t, opts)?,
                None if opts.oif.is_some() => make_target("ROUTE", opts)?,
                None => return Err("-j ターゲットがありません".into()),
            };
            let rule = Rule { line, text: raw.trim().to_string(), m, target };
            if insert {
                rs.rules.insert(0, rule);
            } else {
                rs.rules.push(rule);
            }
        }
    }
    Ok(())
}

fn cond<T>(negate: bool, values: Vec<T>) -> Option<Cond<T>> {
    Some(Cond { negate, values })
}

fn take<'a>(it: &mut impl Iterator<Item = &'a str>, opt: &str) -> Result<&'a str, String> {
    it.next().ok_or_else(|| format!("{opt} に値がありません"))
}

/// ターゲットに付くオプション（-o / --to-destination / --to-ports）
#[derive(Default)]
struct TargetOpts {
    oif: Option<String>,
    /// (アドレス, ポート)。REDIRECT はアドレス None（= 127.0.0.1）
    to: Option<(Option<IpAddr>, Option<u16>)>,
}

impl TargetOpts {
    /// ターゲット用オプションなら値を読んで true を返す
    fn parse<'a>(&mut self, t: &str, it: &mut impl Iterator<Item = &'a str>) -> Result<bool, String> {
        match t {
            "-o" | "--oif" | "--out-interface" => self.oif = Some(take(it, t)?.to_string()),
            "--to-destination" | "--to" => self.to = Some(parse_dest(take(it, t)?)?),
            "--to-ports" | "--to-port" => {
                let v = take(it, t)?;
                if v.contains([',', ':', '-']) {
                    return Err(format!("--to-ports は単一ポートのみ対応です: {v}"));
                }
                self.to = Some((None, Some(parse_port(v)?)));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// `127.0.0.1:8080` / `127.0.0.1` / `[::1]:8080` / `::1`
fn parse_dest(s: &str) -> Result<(Option<IpAddr>, Option<u16>), String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok((Some(sa.ip()), Some(sa.port())));
    }
    let bare = s.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>().map(|a| (Some(a), None)).map_err(|_| format!("不正な転送先: {s}"))
}

fn make_target(name: &str, opts: TargetOpts) -> Result<Target, String> {
    let TargetOpts { oif, to } = opts;
    match name {
        "DNAT" => {
            let Some((Some(addr), port)) = to else {
                return Err("DNAT には --to-destination ADDR[:PORT] が必要です".into());
            };
            return Ok(Target::Dnat { addr, port, oif });
        }
        "REDIRECT" => {
            let Some((None, Some(port))) = to else {
                return Err("REDIRECT には --to-ports PORT が必要です（アドレス指定は DNAT を使用）".into());
            };
            if oif.is_some() {
                return Err("REDIRECT はローカル宛てなので -o は指定できません".into());
            }
            return Ok(Target::Dnat { addr: Ipv4Addr::LOCALHOST.into(), port: Some(port), oif: None });
        }
        _ if to.is_some() => return Err(format!("{name} に --to-destination / --to-ports は指定できません")),
        _ => {}
    }
    match (name, oif) {
        ("ROUTE" | "ACCEPT", Some(i)) => Ok(Target::Route(i)),
        ("ROUTE", None) => Err("ROUTE には -o インターフェースが必要です".into()),
        ("ACCEPT", None) => Ok(Target::Accept),
        ("DROP", None) => Ok(Target::Drop),
        ("REJECT", None) => Ok(Target::Reject),
        ("DROP" | "REJECT", Some(_)) => Err(format!("{name} に -o は指定できません")),
        (t, _) => Err(format!("不明なターゲット: {t}")),
    }
}

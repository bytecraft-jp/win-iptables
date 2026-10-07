//! iptables 風のルール言語。
//!
//! ```text
//! -P OUTPUT ROUTE -o "Wi-Fi"                       # 既定ポリシー
//! -A OUTPUT -m owner --process outlook.exe -j ROUTE -o "Ethernet 2"
//! -A OUTPUT -p tcp -d 10.0.0.0/8 --dport 443 -j ROUTE -o Ethernet
//! -A OUTPUT -p udp --dport 443 -j DROP             # QUIC を遮断
//! -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080   # ローカルのプロキシへ
//! -A OUTPUT -s 192.168.137.50 -j ROUTE -o "Wi-Fi"  # 特定の端末（ICS 配下など）の通信
//! -A BYPASS -d 192.168.100.0/24 -o Ethernet        # TUN を通さずカーネル経路で直送
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnet::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// 指定インターフェースから送出する
    Route(String),
    /// 既定（自動選択）インターフェースから送出する
    Accept,
    Drop,
    Reject,
    /// 宛先を書き換えて接続する。`port` が None なら元の宛先ポートのまま。
    /// `oif` 指定時はそのNICから、未指定なら OS の経路表に従って接続する
    Dnat { addr: IpAddr, port: Option<u16>, oif: Option<String> },
}

impl Target {
    /// DNAT の接続先（`orig_port` は元の宛先ポート）
    pub fn dnat_dest(&self, orig_port: u16) -> Option<SocketAddr> {
        match self {
            Target::Dnat { addr, port, .. } => Some(SocketAddr::new(*addr, port.unwrap_or(orig_port))),
            _ => None,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Route(i) => write!(f, "ROUTE -o \"{i}\""),
            Target::Accept => f.write_str("ACCEPT"),
            Target::Drop => f.write_str("DROP"),
            Target::Reject => f.write_str("REJECT"),
            Target::Dnat { addr, port, oif } => {
                match (addr, port) {
                    (IpAddr::V6(a), Some(p)) => write!(f, "DNAT [{a}]:{p}")?,
                    (a, Some(p)) => write!(f, "DNAT {a}:{p}")?,
                    (a, None) => write!(f, "DNAT {a}")?,
                }
                match oif {
                    Some(i) => write!(f, " -o \"{i}\""),
                    None => Ok(()),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange(pub u16, pub u16);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cond<T> {
    negate: bool,
    values: Vec<T>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    proto: Option<Cond<Proto>>,
    src: Option<Cond<IpNet>>,
    dst: Option<Cond<IpNet>>,
    dport: Option<Cond<PortRange>>,
    process: Option<Cond<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub line: usize,
    pub text: String,
    m: Match,
    pub target: Target,
}

/// TUN を経由させずに OS のルーティングテーブルへ直接入れる経路
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BypassRoute {
    pub dst: IpNet,
    pub oif: String,
    pub gw: Option<IpAddr>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub policy: Target,
    pub bypass: Vec<BypassRoute>,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self { rules: Vec::new(), policy: Target::Accept, bypass: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}行目: {}", self.line, self.msg)
    }
}

/// 評価対象のフロー
pub struct Flow<'a> {
    pub proto: Proto,
    /// TUN に入ってきた時点の送信元（この PC のアプリなら TUN のアドレス、転送されてきた通信なら元の端末）
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dport: u16,
    pub process: Owner<'a>,
}

/// フローの送信元プロセス。PID 判定は接続テーブルを引くので重く、必要になるまで `Unknown` のまま評価する
#[derive(Debug, Clone, Copy)]
pub enum Owner<'a> {
    Unknown,
    /// 小文字化済みの実行ファイル名（例: "chrome.exe"）。None は判定できなかった
    Known(Option<&'a str>),
}

/// DNAT が使えないときなどに使う既定動作
static ACCEPT: Target = Target::Accept;

/// 評価結果。`rule` はマッチしたルールの添字（None ならポリシー）
pub struct Verdict<'a> {
    pub rule: Option<usize>,
    pub target: &'a Target,
}

impl RuleSet {
    #[cfg(test)]
    pub fn evaluate(&self, flow: &Flow) -> Verdict<'_> {
        self.evaluate_with(flow, |_| Some(true)).expect("プロセスが既知なら必ず決まる")
    }

    /// `allow` が false を返したターゲットのルールは飛ばして次を評価する。
    /// ポリシーが飛ばされた場合は ACCEPT になる。
    /// 結果を決めるのにプロセス情報が要る行に達したら（`--process` の条件、または `allow` が None）None を返す。
    /// それより前の行で決まればプロセスは引かずに済む
    pub fn evaluate_with(&self, flow: &Flow, mut allow: impl FnMut(&Target) -> Option<bool>) -> Option<Verdict<'_>> {
        for (i, r) in self.rules.iter().enumerate() {
            if r.m.matches(flow)? && allow(&r.target)? {
                return Some(Verdict { rule: Some(i), target: &r.target });
            }
        }
        let target = if allow(&self.policy)? { &self.policy } else { &ACCEPT };
        Some(Verdict { rule: None, target })
    }

    /// ルールが参照しているインターフェース名（重複なし）
    pub fn referenced_interfaces(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        let targets = self.rules.iter().map(|r| &r.target).chain(std::iter::once(&self.policy));
        for t in targets {
            match t {
                Target::Route(i) | Target::Dnat { oif: Some(i), .. } => v.push(i),
                _ => {}
            }
        }
        v.extend(self.bypass.iter().map(|b| b.oif.as_str()));
        v.sort_unstable();
        v.dedup();
        v
    }
}

impl<T> Cond<T> {
    fn test(&self, f: impl Fn(&T) -> bool) -> bool {
        self.values.iter().any(f) != self.negate
    }
}

impl Match {
    /// プロセス名の条件があってプロセスが未判定なら None。
    /// 他の条件で外れるならプロセスは見ずに Some(false) を返す
    fn matches(&self, flow: &Flow) -> Option<bool> {
        if let Some(c) = &self.proto
            && !c.test(|p| *p == flow.proto)
        {
            return Some(false);
        }
        if let Some(c) = &self.src
            && !c.test(|n| n.contains(&flow.src))
        {
            return Some(false);
        }
        if let Some(c) = &self.dst
            && !c.test(|n| n.contains(&flow.dst))
        {
            return Some(false);
        }
        if let Some(c) = &self.dport {
            // ポートを持たないプロトコルは --dport 付きルールにマッチしない
            if flow.proto == Proto::Icmp || !c.test(|r| (r.0..=r.1).contains(&flow.dport)) {
                return Some(false);
            }
        }
        if let Some(c) = &self.process {
            let Owner::Known(process) = flow.process else { return None };
            let hit = |pat: &String| process.is_some_and(|name| process_matches(pat, name));
            if !c.test(hit) {
                return Some(false);
            }
        }
        Some(true)
    }
}

/// `pat` は小文字化済み。`*` ワイルドカード対応、拡張子 `.exe` は省略可。
fn process_matches(pat: &str, name: &str) -> bool {
    if wildcard(pat, name) {
        return true;
    }
    !pat.ends_with(".exe") && name.strip_suffix(".exe").is_some_and(|stem| wildcard(pat, stem))
}

fn wildcard(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == s[si] || p[pi] == b'?') {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// 引用符と `#` コメントを考慮して1行をトークンに分割する
fn tokenize(line: &str) -> Result<Vec<String>, String> {
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

fn parse_net(s: &str) -> Result<IpNet, String> {
    if s.eq_ignore_ascii_case("any") {
        return Ok("0.0.0.0/0".parse().unwrap());
    }
    if let Ok(n) = s.parse::<IpNet>() {
        return Ok(n.trunc());
    }
    s.parse::<IpAddr>().map(IpNet::from).map_err(|_| format!("不正なアドレス/CIDR: {s}"))
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
            "-p" | "--protocol" => {
                if let Some(p) = parse_proto(val()?)? {
                    m.proto = Some(Cond { negate: neg, values: vec![p] });
                }
            }
            "-s" | "--source" => {
                let v = val()?.split(',').map(parse_net).collect::<Result<_, _>>()?;
                m.src = Some(Cond { negate: neg, values: v });
            }
            "-d" | "--destination" => {
                let v = val()?.split(',').map(parse_net).collect::<Result<_, _>>()?;
                m.dst = Some(Cond { negate: neg, values: v });
            }
            "--dport" | "--dports" | "--destination-port" => {
                m.dport = Some(Cond { negate: neg, values: parse_ports(val()?)? });
            }
            "--process" | "--proc" | "--cmd-owner" => {
                let v = val()?.split(',').map(|s| s.trim().to_lowercase()).collect();
                m.process = Some(Cond { negate: neg, values: v });
            }
            "-m" | "--match" => {
                // owner / multiport などは iptables 互換のため読み捨てる。
                // `! -m owner --process x` の ! は次の条件に引き継ぐ
                val()?;
                negate = neg;
                continue;
            }
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
        if neg && !matches!(t, "-p" | "--protocol" | "-s" | "--source" | "-d" | "--destination" | "--dport" | "--dports" | "--destination-port" | "--process" | "--proc" | "--cmd-owner") {
            return Err(format!("{t} に ! は付けられません"));
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

pub const SAMPLE: &str = r#"# win-iptables ルール
# 書式は iptables 風。上から順に評価され、最初にマッチしたルールが適用されます。
#
#   -P OUTPUT <ACCEPT|ROUTE -o IF|DROP>           既定ポリシー（ACCEPT = 自動選択したNIC）
#   -A OUTPUT [条件...] -j <ROUTE -o IF|ACCEPT|DROP|REJECT>
#   -I OUTPUT ...                                 先頭に挿入
#   -A OUTPUT [条件...] -j REDIRECT --to-ports PORT        127.0.0.1:PORT へ転送
#   -A OUTPUT [条件...] -j DNAT --to-destination ADDR[:PORT] [-o IF]  宛先を書き換えて転送
#   -A BYPASS -d CIDR -o IF [--gw IP] [--metric N] TUN を通さずOS経路で直送
#
# 条件: -p tcp|udp|icmp  -s CIDR[,CIDR]  -d CIDR[,CIDR]  --dport 80,443,8000:8080
#       -m owner --process chrome.exe,msedge*   （各条件の前に ! で否定）
#       -s は送信元。この PC のアプリは TUN のアドレス、ICS などで転送されてきた通信は元の端末のアドレス
# インターフェース名は「インターフェース」タブの名前（空白を含む場合は "..." で囲む）

-P OUTPUT ACCEPT

# 例: Outlook は有線NICから出す
# -A OUTPUT -m owner --process outlook.exe -j ROUTE -o "イーサネット"

# 例: Chrome の QUIC (UDP/443) を止めて TCP にフォールバックさせる
# -A OUTPUT -m owner --process chrome.exe -p udp --dport 443 -j DROP

# 例: HTTP/HTTPS をローカルのプロキシ (127.0.0.1:8080) へ。QUIC は止めて TCP に寄せる
#     （8080 で待ち受けているプロセス自身の通信は自動的に除外されるのでループしません）
# -A OUTPUT -p udp --dport 443 -j DROP
# -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080

# 例: 社内網は TUN を経由せず直接
# -A BYPASS -d 10.0.0.0/8 -o "イーサネット"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn flow<'a>(proto: Proto, dst: &str, dport: u16, process: Option<&'a str>) -> Flow<'a> {
        Flow { proto, src: "10.233.0.2".parse().unwrap(), dst: dst.parse().unwrap(), dport, process: Owner::Known(process) }
    }

    #[test]
    fn sample_parses() {
        let rs = parse(SAMPLE).unwrap();
        assert_eq!(rs.policy, Target::Accept);
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn first_match_wins() {
        let rs = parse(
            r#"
            -P OUTPUT ROUTE -o "Wi-Fi"
            -A OUTPUT -m owner --process outlook -j ROUTE -o "Ethernet 2"
            -A OUTPUT -p udp --dport 443 -j DROP
            -A OUTPUT -p tcp -d 10.0.0.0/8,172.16.0.0/12 --dport 80,8000:8080 -o eth
            "#,
        )
        .unwrap();
        let t = |f: Flow| rs.evaluate(&f).target.clone();
        assert_eq!(t(flow(Proto::Tcp, "1.1.1.1", 443, Some("outlook.exe"))), Target::Route("Ethernet 2".into()));
        assert_eq!(t(flow(Proto::Udp, "1.1.1.1", 443, Some("chrome.exe"))), Target::Drop);
        assert_eq!(t(flow(Proto::Tcp, "10.1.2.3", 8080, None)), Target::Route("eth".into()));
        assert_eq!(t(flow(Proto::Tcp, "10.1.2.3", 8081, None)), Target::Route("Wi-Fi".into()));
        assert_eq!(t(flow(Proto::Tcp, "11.0.0.1", 80, None)), Target::Route("Wi-Fi".into()));
        assert_eq!(rs.evaluate(&flow(Proto::Tcp, "11.0.0.1", 80, None)).rule, None);
    }

    #[test]
    fn negation_and_insert() {
        let rs = parse(
            "-A OUTPUT ! -d 192.168.0.0/16 -j REJECT\n-I OUTPUT ! -m owner --process chrome* -p tcp -j DROP",
        )
        .unwrap();
        assert_eq!(rs.rules[0].line, 2);
        assert_eq!(*rs.evaluate(&flow(Proto::Tcp, "192.168.1.1", 1, None)).target, Target::Drop);
        assert_eq!(*rs.evaluate(&flow(Proto::Tcp, "8.8.8.8", 1, Some("chrome.exe"))).target, Target::Reject);
        assert_eq!(*rs.evaluate(&flow(Proto::Udp, "192.168.1.1", 1, None)).target, Target::Accept);
    }

    #[test]
    fn icmp_never_matches_dport() {
        let rs = parse("-A OUTPUT --dport 1:65535 -j DROP").unwrap();
        assert_eq!(*rs.evaluate(&flow(Proto::Icmp, "8.8.8.8", 0, None)).target, Target::Accept);
    }

    #[test]
    fn bypass_routes() {
        let rs = parse("-A BYPASS -d 10.0.0.1 -o \"Ethernet 2\" --gw 192.168.1.1 --metric 5").unwrap();
        assert_eq!(
            rs.bypass,
            vec![BypassRoute {
                dst: "10.0.0.1/32".parse().unwrap(),
                oif: "Ethernet 2".into(),
                gw: Some("192.168.1.1".parse().unwrap()),
                metric: Some(5),
            }]
        );
        assert!(parse("-A BYPASS -d 10.0.0.0/8 -p tcp -o x").is_err());
        assert!(parse("-A BYPASS -o x").is_err());
    }

    #[test]
    fn dnat_and_redirect() {
        let rs = parse(
            "-A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080\n\
             -A OUTPUT -d 10.0.0.0/8 -j DNAT --to-destination [::1] -o eth\n\
             -P OUTPUT DNAT --to 192.0.2.1:3128",
        )
        .unwrap();
        let redirect = Target::Dnat { addr: "127.0.0.1".parse().unwrap(), port: Some(8080), oif: None };
        assert_eq!(rs.rules[0].target, redirect);
        assert_eq!(redirect.dnat_dest(443), Some("127.0.0.1:8080".parse().unwrap()));
        let v6 = &rs.rules[1].target;
        assert_eq!(v6.dnat_dest(53), Some("[::1]:53".parse().unwrap()));
        assert_eq!(v6.to_string(), "DNAT ::1 -o \"eth\"");
        assert_eq!(rs.policy.dnat_dest(1), Some("192.0.2.1:3128".parse().unwrap()));
        assert_eq!(rs.referenced_interfaces(), vec!["eth"]);

        assert!(parse("-A OUTPUT -j REDIRECT").is_err());
        assert!(parse("-A OUTPUT -j REDIRECT --to-ports 1:2").is_err());
        assert!(parse("-A OUTPUT -j DNAT --to-ports 8080").is_err());
        assert!(parse("-A OUTPUT -j DROP --to 1.2.3.4").is_err());
        assert!(parse("-A OUTPUT ! -j DROP").is_err());
    }

    #[test]
    fn skipped_targets_fall_through() {
        let rs = parse("-A OUTPUT -p tcp -j REDIRECT --to-ports 8080\n-A OUTPUT -j DROP\n-P OUTPUT DNAT --to 1.1.1.1").unwrap();
        let f = flow(Proto::Tcp, "8.8.8.8", 443, None);
        let not_dnat = |t: &Target| Some(!matches!(t, Target::Dnat { .. }));
        let v = rs.evaluate_with(&f, not_dnat).unwrap();
        assert_eq!((v.rule, v.target), (Some(1), &Target::Drop));
        let empty = parse("-P OUTPUT DNAT --to 1.1.1.1").unwrap();
        assert_eq!(*empty.evaluate_with(&f, not_dnat).unwrap().target, Target::Accept);
    }

    #[test]
    fn process_is_needed_only_when_reached() {
        let rs = parse(
            "-A OUTPUT -p udp --dport 443 -j DROP
             -A OUTPUT -d 10.0.0.0/8 -m owner --process outlook -j ROUTE -o eth
             -A OUTPUT -p tcp --dport 80 -j DROP",
        )
        .unwrap();
        let unknown = |proto, dst: &str, dport| Flow {
            proto,
            src: "10.233.0.2".parse().unwrap(),
            dst: dst.parse().unwrap(),
            dport,
            process: Owner::Unknown,
        };
        let eval = |f: &Flow| rs.evaluate_with(f, |_| Some(true)).map(|v| v.rule);
        // プロセス条件の行より前で決まる
        assert_eq!(eval(&unknown(Proto::Udp, "10.1.1.1", 443)), Some(Some(0)));
        // プロセス条件の行は -d で外れるので見なくてよい
        assert_eq!(eval(&unknown(Proto::Tcp, "8.8.8.8", 80)), Some(Some(2)));
        assert_eq!(eval(&unknown(Proto::Tcp, "8.8.8.8", 81)), Some(None));
        // -d が一致してプロセス条件の行に達したら判定が要る
        assert_eq!(eval(&unknown(Proto::Tcp, "10.1.1.1", 80)), None);
        // DNAT のループ防止でプロセスが要る場合も None
        assert!(rs.evaluate_with(&unknown(Proto::Tcp, "8.8.8.8", 81), |_| None).is_none());
    }

    #[test]
    fn hotspot_clients_to_transparent_proxy() {
        // README の「モバイル ホットスポットの端末の通信を扱う」の例
        let rs = parse(
            "-A OUTPUT -s 192.168.137.0/24 -p udp --dport 443 -j DROP\n\
             -A OUTPUT -s 192.168.137.0/24 -p tcp --dport 80,443 -j REDIRECT --to-ports 8080",
        )
        .unwrap();
        let from = |src: &str, proto, dport| Flow {
            proto,
            src: src.parse().unwrap(),
            dst: "17.253.69.204".parse().unwrap(),
            dport,
            process: Owner::Known(None),
        };
        let proxy = Target::Dnat { addr: "127.0.0.1".parse().unwrap(), port: Some(8080), oif: None };
        assert_eq!(*rs.evaluate(&from("192.168.137.121", Proto::Tcp, 443)).target, proxy);
        assert_eq!(*rs.evaluate(&from("192.168.137.121", Proto::Udp, 443)).target, Target::Drop);
        // PC 自身（プロキシの上流接続を含む）は対象外
        assert_eq!(*rs.evaluate(&from("10.233.0.2", Proto::Tcp, 443)).target, Target::Accept);
    }

    #[test]
    fn source_address() {
        let rs = parse("-A OUTPUT -s 192.168.137.0/24,fd00::/8 -j ROUTE -o eth
-A OUTPUT ! -s 10.233.0.2 -j DROP").unwrap();
        let from = |src: &str| Flow {
            proto: Proto::Tcp,
            src: src.parse().unwrap(),
            dst: "8.8.8.8".parse().unwrap(),
            dport: 443,
            process: Owner::Known(None),
        };
        assert_eq!(*rs.evaluate(&from("192.168.137.50")).target, Target::Route("eth".into()));
        assert_eq!(*rs.evaluate(&from("fd00::1")).target, Target::Route("eth".into()));
        assert_eq!(*rs.evaluate(&from("10.233.0.2")).target, Target::Accept);
        assert_eq!(*rs.evaluate(&from("192.168.1.5")).target, Target::Drop);
        assert!(parse("-A BYPASS -s 192.168.137.0/24 -d 10.0.0.0/8 -o x").is_err());
        assert!(parse("-A OUTPUT -s 1.2.3.999 -j DROP").is_err());
    }

    #[test]
    fn errors_report_lines() {
        let errs = parse("-A OUTPUT -j ROUTE\n\n-A OUTPUT -d 999.1.1.1 -j DROP\n-X").unwrap_err();
        assert_eq!(errs.iter().map(|e| e.line).collect::<Vec<_>>(), vec![1, 3, 4]);
    }

    #[test]
    fn wildcards() {
        assert!(process_matches("msedge*", "msedgewebview2.exe"));
        assert!(process_matches("teams", "teams.exe"));
        assert!(!process_matches("teams", "msteams.exe"));
        assert!(process_matches("*teams*", "msteams.exe"));
        assert!(process_matches("ms?eams.exe", "msteams.exe"));
    }

    #[test]
    fn tokenizer_handles_quotes_and_comments() {
        assert_eq!(tokenize(r#"-o "Ethernet 2" -j X # c"#).unwrap(), vec!["-o", "Ethernet 2", "-j", "X"]);
        assert_eq!(tokenize(r#"-o 'a "b"'"#).unwrap(), vec!["-o", "a \"b\""]);
        assert!(tokenize("-o \"x").is_err());
    }
}

//! ルール画面に出す用途別の例と書き方の説明。
//!
//! 例の `{IF}` は、画面側で既定経路を持つ NIC の名前に置き換えてから挿入する。

pub struct Example {
    pub title: &'static str,
    pub description: &'static str,
    pub rules: &'static str,
}

pub struct Category {
    pub name: &'static str,
    pub examples: &'static [Example],
}

/// 例のインターフェース名の置き換え用
pub const IFACE_PLACEHOLDER: &str = "{IF}";

pub const EXAMPLES: &[Category] = &[
    Category {
        name: "基本（既定の動作）",
        examples: &[
            Example {
                title: "すべて自動選択の NIC から出す",
                description: "どのルールにも当たらない通信は、Windows が普段使う NIC（既定経路）から出ます。最初はこれで動作を確かめてください。\
                              -P は既定ポリシーで、複数書くと最後の行が有効です。",
                rules: "-P OUTPUT ACCEPT",
            },
            Example {
                title: "ルールに当たらない通信を特定の NIC から出す",
                description: "Wi-Fi と有線など NIC が複数あるとき、既定の出口を固定します。\
                              インターフェース名は「インターフェース」タブの名前に合わせてください。",
                rules: r#"-P OUTPUT ROUTE -o "{IF}""#,
            },
            Example {
                title: "許可したアプリ以外は通信させない",
                description: "上から順に評価され、最初に当たった行で決まります。名前解決（DNS）は Windows のサービスが行うので先に許可し、\
                              最後の -P OUTPUT DROP で残りをすべて止めます。ホットスポットの端末の通信も止まるので注意してください。",
                rules: "-A OUTPUT -p udp --dport 53 -j ACCEPT\n\
                        -A OUTPUT -m owner --process chrome.exe,msedge.exe -j ACCEPT\n\
                        -P OUTPUT DROP",
            },
            Example {
                title: "既存のルールより優先させる（先頭に挿入）",
                description: "-A は末尾に追加、-I は先頭に追加します。後から足した例外を確実に先に効かせたいときに使います。",
                rules: "-I OUTPUT -d 203.0.113.10 -j DROP",
            },
        ],
    },
    Category {
        name: "アプリごと",
        examples: &[
            Example {
                title: "特定のアプリの通信を止める",
                description: "プロセス名はタスク マネージャーの「詳細」タブに出る名前です。.exe は省略でき、カンマ区切りで複数書けます。\
                              「接続」タブのプロセス欄でも確認できます。",
                rules: "-A OUTPUT -m owner --process example.exe -j DROP",
            },
            Example {
                title: "特定のアプリだけ別の NIC から出す",
                description: "メールや会議アプリは有線、それ以外は Wi-Fi のように、アプリごとに出口を分けます。",
                rules: r#"-A OUTPUT -m owner --process outlook.exe,teams.exe -j ROUTE -o "{IF}""#,
            },
            Example {
                title: "名前の一部でアプリを指定する",
                description: "* は任意の文字列、? は任意の 1 文字です。この例は名前に update を含むアプリ（自動更新など）を止めます。",
                rules: "-A OUTPUT -m owner --process *update* -j DROP",
            },
            Example {
                title: "あるアプリ以外の Web 通信を止める",
                description: "条件の前に ! を付けると逆の意味になります。この例は Chrome 以外の HTTP/HTTPS を止めます。\
                              プロセスの分からない通信（ホットスポットの端末など）も対象になります。",
                rules: "-A OUTPUT ! -m owner --process chrome.exe -p tcp --dport 80,443 -j DROP",
            },
            Example {
                title: "アプリの QUIC (HTTP/3) だけ止める",
                description: "ブラウザは QUIC が通らないと自動的に TCP で接続し直します。条件は全部そろったときだけ当たります。",
                rules: "-A OUTPUT -m owner --process chrome.exe -p udp --dport 443 -j DROP",
            },
        ],
    },
    Category {
        name: "宛先・ポート",
        examples: &[
            Example {
                title: "特定の宛先を止める",
                description: "-d は宛先です。単一の IP、CIDR（203.0.113.0/24）、カンマ区切りで複数書けます。\
                              ドメイン名は書けないので、nslookup などで調べた IP を書いてください。",
                rules: "-A OUTPUT -d 203.0.113.0/24,198.51.100.7 -j DROP",
            },
            Example {
                title: "宛先によって出口の NIC を分ける",
                description: "社内網などの宛先だけ別の NIC から出します。-j を省いて -o だけ書いても ROUTE になります。\
                              LAN 内など NIC に直結しているネットワーク宛ては TUN を通らないので、ルールは効きません。",
                rules: r#"-A OUTPUT -d 10.0.0.0/8,172.16.0.0/12 -j ROUTE -o "{IF}""#,
            },
            Example {
                title: "QUIC (HTTP/3) を全部止めて TCP に寄せる",
                description: "UDP 443 番を止めます。プロキシや TCP を前提にしたルールと組み合わせるときに使います。",
                rules: "-A OUTPUT -p udp --dport 443 -j DROP",
            },
            Example {
                title: "ポートの範囲で止める",
                description: "--dport は 80,443 のようにカンマ区切り、6881:6889 のようにコロンで範囲を書けます。",
                rules: "-A OUTPUT -p tcp --dport 6881:6889 -j DROP",
            },
            Example {
                title: "ping を止める",
                description: "-p icmp で ping（ICMP echo）に当たります。--dport を書いた行には ICMP は当たりません。",
                rules: "-A OUTPUT -p icmp -j DROP",
            },
            Example {
                title: "IPv6 の通信を止めて IPv4 に寄せる",
                description: "IPv6 で不具合が出るときの切り分けに使います。アプリは IPv4 で接続し直します。\
                              設定の「IPv6 も捕捉する」がオンのときだけ効きます。",
                rules: "-A OUTPUT -d ::/0 -j DROP",
            },
        ],
    },
    Category {
        name: "転送・プロキシ",
        examples: &[
            Example {
                title: "Web 通信をこの PC のプロキシ (8080) へ",
                description: "127.0.0.1:8080 で待ち受けているプロキシへ転送します。プロキシ自身の通信は自動で除外されるのでループしません。\
                              プロキシには生の HTTP/TLS が届くので、透過モード（Host ヘッダや SNI で宛先を判断する方式）にしてください。",
                rules: "-A OUTPUT -p udp --dport 443 -j DROP\n\
                        -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080",
            },
            Example {
                title: "特定のアプリだけプロキシへ",
                description: "条件にプロセス名を加えると、そのアプリの通信だけをプロキシへ回せます。",
                rules: "-A OUTPUT -m owner --process chrome.exe -p udp --dport 443 -j DROP\n\
                        -A OUTPUT -m owner --process chrome.exe -p tcp --dport 80,443 -j REDIRECT --to-ports 8080",
            },
            Example {
                title: "別の PC のプロキシへ転送する",
                description: "DNAT は宛先を書き換えます。ポートを省くと元の宛先ポートのままです。-o を付けるとその NIC から接続します。",
                rules: "-A OUTPUT -p tcp --dport 80,443 -j DNAT --to-destination 192.168.1.10:3128",
            },
            Example {
                title: "DNS の問い合わせ先を変える",
                description: "Windows の DNS 設定を変えずに、問い合わせをすべて指定のサーバーへ向けます（ポートは元の 53 のまま）。",
                rules: "-A OUTPUT -p udp --dport 53 -j DNAT --to-destination 1.1.1.1",
            },
        ],
    },
    Category {
        name: "ホットスポットの端末",
        examples: &[
            Example {
                title: "端末の Web 通信だけプロキシへ",
                description: "稼働中に上部の「ホットスポット」ボタンでオンにし、スマホなどをつなぎます（端末の DNS は手動で 1.1.1.1 などに）。\
                              端末の通信は PC 上のプロセスが見つからない通信（「接続」タブのプロセスが「?」）として見えるので、\
                              ! --process * でそれだけを選べます。PC 側でもまれにプロセスを特定できない通信が混ざります。",
                rules: "-A OUTPUT ! -m owner --process * -p udp --dport 443 -j DROP\n\
                        -A OUTPUT ! -m owner --process * -p tcp --dport 80,443 -j REDIRECT --to-ports 8080",
            },
            Example {
                title: "端末と PC の Web 通信をまとめてプロキシへ",
                description: "プロセスで区別せず、PC 自身の通信も含めて HTTP/HTTPS をプロキシへ回します。",
                rules: "-A OUTPUT -p udp --dport 443 -j DROP\n\
                        -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-ports 8080",
            },
            Example {
                title: "端末の通信だけ別の NIC から出す",
                description: "端末の通信を有線などの別の NIC から出します。共有の NAT を通るので、-s で端末ごとに分けることはできません。",
                rules: r#"-A OUTPUT ! -m owner --process * -j ROUTE -o "{IF}""#,
            },
        ],
    },
    Category {
        name: "TUN を通さない（BYPASS）",
        examples: &[
            Example {
                title: "社内網は TUN を通さず直接",
                description: "BYPASS は Windows の経路表に直接経路を入れ、その宛先の通信を TUN に通しません。\
                              ルールは効きませんが、中継しない分だけ速く、VPN などとも干渉しにくくなります。停止すると消えます。",
                rules: r#"-A BYPASS -d 10.0.0.0/8 -o "{IF}""#,
            },
            Example {
                title: "ゲートウェイとメトリックを指定する",
                description: "--gw を省くとその NIC の既定ゲートウェイ（なければ直結）を使います。--metric は小さいほど優先されます。",
                rules: r#"-A BYPASS -d 192.168.100.0/24 -o "{IF}" --gw 192.168.1.1 --metric 5"#,
            },
        ],
    },
];

/// 書き方の説明（見出し, [(書式, 説明)]）
pub const SYNTAX: &[(&str, &[(&str, &str)])] = &[
    (
        "行の種類",
        &[
            ("-A OUTPUT 条件… -j 動作", "ルールを末尾に追加する。上から順に評価し、最初に当たった行の動作になる"),
            ("-I OUTPUT 条件… -j 動作", "ルールを先頭に追加する"),
            ("-P OUTPUT 動作", "どの行にも当たらなかったときの動作（既定ポリシー）"),
            ("-A BYPASS -d 宛先 -o NIC", "TUN を通さず Windows の経路表に直接経路を入れる"),
            ("# コメント", "# から行末までは無視される"),
        ],
    ),
    (
        "条件（すべてそろうと当たる）",
        &[
            ("-p tcp | udp | icmp", "プロトコル。省略するとすべて"),
            ("-d 203.0.113.0/24,1.2.3.4", "宛先。単一の IP か CIDR をカンマ区切りで"),
            ("-s 10.233.0.2", "送信元。PC 自身のアプリも、ホットスポットの端末（共有の NAT 後）も TUN のアドレスとして見える"),
            ("--dport 80,443,8000:8080", "宛先ポート。コロンで範囲。ICMP には当たらない"),
            ("-m owner --process chrome.exe", "アプリ（プロセス名）。* と ? が使え .exe は省略可。-m owner は省いてもよい"),
            ("! 条件", "条件の前に ! を付けると逆の意味になる（例: ! -d 10.0.0.0/8）"),
        ],
    ),
    (
        "動作 (-j)",
        &[
            ("-j ACCEPT", "Windows が普段使う NIC（既定経路）から出す"),
            (r#"-j ROUTE -o "Wi-Fi""#, "指定した NIC から出す。-j を省いて -o だけでもよい"),
            ("-j DROP / -j REJECT", "止める（TCP はどちらもすぐ切断される）"),
            ("-j REDIRECT --to-ports 8080", "この PC の 127.0.0.1:8080 へ転送する"),
            ("-j DNAT --to-destination 1.2.3.4:3128", "宛先を書き換えて転送する。ポート省略で元のポート、-o で出口 NIC を指定"),
        ],
    ),
    (
        "インターフェース名",
        &[
            (r#"-o "イーサネット 2""#, "「インターフェース」タブの名前。空白を含むときは \"...\" で囲む"),
            ("-o #12", "# の後にインターフェース番号でも指定できる"),
            ("BYPASS の --gw / --metric", "ゲートウェイとメトリック（BYPASS の行だけ）"),
        ],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_examples_parse() {
        for category in EXAMPLES {
            for example in category.examples {
                let text = example.rules.replace(IFACE_PLACEHOLDER, "Wi-Fi");
                assert!(super::super::parse(&text).is_ok(), "{}: {text}", example.title);
            }
        }
    }
}

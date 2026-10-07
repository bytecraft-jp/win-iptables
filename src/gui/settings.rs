//! エンジン設定の編集。各項目の下に、何のための設定か・いつ変えるかの説明を出す。

use super::App;
use crate::config::{self, RouteMode};
use crate::hotspot::AccessPoint;
use eframe::egui::{self, Color32, RichText};

/// 説明文が読みやすいよう、横に広がりすぎないようにする
const MAX_WIDTH: f32 = 760.0;

impl App {
    pub(super) fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let locked = self.engine.is_some() || self.pending.is_some();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.set_max_width(MAX_WIDTH);
            if locked {
                ui.label(RichText::new("稼働中は変更できません。停止してから変更してください。").color(Color32::GOLD));
            }
            ui.add_enabled_ui(!locked, |ui| {
                self.settings_items(ui);
                ui.add_space(12.0);
                if ui.button("設定を保存").clicked() {
                    if let Err(e) = access_point(&self.settings).validate() {
                        self.status = Some((false, format!("保存できません: {e}")));
                        return;
                    }
                    match config::save_settings(&self.settings) {
                        Ok(()) => self.status = Some((true, "設定を保存しました。次に開始したときから反映されます".into())),
                        Err(e) => self.status = Some((false, format!("設定の保存に失敗: {e}"))),
                    }
                }
            });
        });
    }

    fn settings_items(&mut self, ui: &mut egui::Ui) {
        let s = &mut self.settings;

        section(ui, "捕捉する範囲");
        item(
            ui,
            "経路モード",
            "どの通信を win-iptables に通すか（＝ルールを効かせるか）を決めます。\n\
             ・全通信を捕捉: 開始すると PC のすべての通信が仮想 NIC（TUN）を通り、ルールが適用されます。通常はこちらです。\n\
             ・手動: 開始しても通信を TUN へ引き込みません。「経路」タブで TUN 向けの経路を追加した宛先だけにルールが効きます。\
             特定の宛先だけで試したいときや、PC 全体に影響を出したくないとき向けです。",
            |ui| {
                ui.radio_value(&mut s.route_mode, RouteMode::Split, "全通信を捕捉（0.0.0.0/1 + 128.0.0.0/1 を TUN へ）");
                ui.radio_value(&mut s.route_mode, RouteMode::Manual, "手動（「経路」タブで TUN 向け経路を追加した宛先のみ）");
            },
        );
        if s.route_mode == RouteMode::Manual {
            manual_mode_steps(ui, &s.tun_name);
        }
        item(
            ui,
            "IPv6 も捕捉する",
            "オンにすると IPv6 の通信も TUN に引き込んでルールを適用します。オフにすると IPv6 の通信は win-iptables を素通りするため、\
             IPv6 が使える回線では、DROP したはずのサイトに IPv6 でつながってしまいます。\
             IPv6 で不具合が出るときの切り分け以外はオンのままにしてください。",
            |ui| {
                ui.checkbox(&mut s.capture_ipv6, "::/1 と 8000::/1 を TUN へ（IPv6 の素通りを防ぐ）");
            },
        );

        section(ui, "ホットスポット");
        item(
            ui,
            "開始時にホットスポットもオンにする",
            "スマホなどをこの PC のモバイル ホットスポットにつなぎ、その通信にもルールを適用するための機能です。\
             ホットスポットは Windows の設定画面ではなく、稼働中に上部の「ホットスポット」ボタンでオン・オフします\
             （Windows の設定画面では共有元に TUN を選べないため）。ここをオンにすると、開始と同時にオンになります。\n\
             端末の DNS は手動で設定してください（iPhone なら Wi-Fi の (i) →「DNSを構成」→「手動」で 1.1.1.1 など）。\
             TUN を共有元にすると Windows が端末に DNS サーバーを配らないため、自動のままではつながりません。\n\
             停止すると、ホットスポットも止めます。開始前に Windows 側でホットスポットを使っていた場合は、停止後に元の共有に戻します。\n\
             注意: 端末の通信は共有の NAT を通るので、送信元は TUN のアドレス（プロセスは「?」）として見え、-s で端末ごとに区別はできません。\
             Windows の「省電力」設定がオンだと、端末がつながっていないときにホットスポットが自動でオフになります。",
            |ui| {
                ui.checkbox(&mut s.hotspot_auto, "開始と同時に、TUN を共有元にしたホットスポットをオンにする");
            },
        );
        item(
            ui,
            "ネットワーク名（SSID）",
            "スマホの Wi-Fi 一覧に出る名前です。空欄なら Windows の設定画面（ネットワークとインターネット → モバイル ホットスポット）の名前を使います。",
            |ui| {
                ui.add(egui::TextEdit::singleline(&mut s.hotspot_ssid).hint_text("Windows の設定のまま").desired_width(260.0));
            },
        );
        item(
            ui,
            "パスワード",
            "8〜63 文字の半角英数字・記号。空欄なら Windows の設定画面のパスワードを使います。\
             ここで指定した名前とパスワードは win-iptables から開始したときだけ使い、Windows の設定画面のものは書き換えません。\
             設定ファイル（%APPDATA%\\win-iptables\\settings.conf）にそのまま保存されます。",
            |ui| {
                ui.horizontal(|ui| {
                    let id = ui.id().with("show_passphrase");
                    let mut show = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
                    ui.add(
                        egui::TextEdit::singleline(&mut s.hotspot_passphrase)
                            .password(!show)
                            .hint_text("Windows の設定のまま")
                            .desired_width(260.0),
                    );
                    ui.checkbox(&mut show, "表示");
                    ui.data_mut(|d| d.insert_temp(id, show));
                });
            },
        );
        if let Err(e) = access_point(s).validate() {
            ui.colored_label(Color32::RED, e);
        }

        section(ui, "接続の速度制限（ルーター対策）");
        ui.label(
            RichText::new(
                "開始直後などにアプリが一斉に接続すると、家庭用ルーターの「IP フラッド検出」などが攻撃とみなし、PC の通信を数分止めることがあります。\
                 そうならないよう、外へ出す新しい TCP 接続の勢いを抑えます。ページの表示が遅いと感じたら数を増やしてください。\
                 この PC 宛て（REDIRECT 先のプロキシなど）は対象外です。",
            )
            .weak(),
        );
        item(
            ui,
            "新規接続の上限",
            "1 秒あたりに外へ出す新しい接続の数と、しばらく接続がなかった後に待たずに出せる数（まとめて）です。\
             0 件/秒で無制限（ルーターにこの種の機能がない場合）。",
            |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.connect_rate).range(0..=1000).suffix(" 件/秒"));
                    ui.label("まとめて");
                    ui.add(egui::DragValue::new(&mut s.connect_burst).range(1..=1000).suffix(" 件"));
                });
            },
        );
        item(
            ui,
            "接続中の同時数",
            "応答待ち（つながるのを待っている）の接続を同時にいくつまで出すかです。応答しない宛先へ大量に接続するアプリがあっても、\
             ほかの通信が巻き込まれないようにします。0 で無制限。",
            |ui| {
                ui.add(egui::DragValue::new(&mut s.connect_concurrency).range(0..=1000).suffix(" 件"));
            },
        );
        item(
            ui,
            "失敗した宛先の保留",
            "つながらなかった宛先への再接続を、この秒数のあいだ外へ出さずにすぐ失敗させます。アプリの再試行が殺到してルーターに止められるのを防ぎます。0 で無効。",
            |ui| {
                ui.add(egui::DragValue::new(&mut s.connect_fail_hold).range(0..=600).suffix(" 秒"));
            },
        );

        section(ui, "仮想 NIC（TUN）— 通常は変更不要");
        item(
            ui,
            "TUN アダプタ名",
            "開始時に作る仮想 NIC の名前です。「経路」タブの出口や、Windows のネットワーク接続の一覧にこの名前で出ます。",
            |ui| {
                ui.text_edit_singleline(&mut s.tun_name);
            },
        );
        item(
            ui,
            "TUN IPv4 アドレス",
            "仮想 NIC に付けるアドレスです。家庭や会社の LAN、VPN と重ならない範囲にしてください（既定 10.233.0.2/24）。\
             PC 自身のアプリの通信は、ルールの -s ではこのアドレスから来たものとして見えます。",
            |ui| {
                ui.horizontal(|ui| {
                    ip_edit(ui, &mut s.tun_ipv4);
                    ui.label("/");
                    ui.add(egui::DragValue::new(&mut s.tun_prefix).range(8..=30));
                });
            },
        );
        item(
            ui,
            "TUN IPv6 アドレス",
            "仮想 NIC に付ける IPv6 アドレスです（fd00::/8 のプライベートな範囲）。",
            |ui| {
                ui.add_enabled_ui(s.capture_ipv6, |ui| ip_edit(ui, &mut s.tun_ipv6));
            },
        );
        item(
            ui,
            "MTU",
            "仮想 NIC が一度に扱うパケットの大きさです。TCP はこの PC の中で中継し直すので、実際の回線の MTU（1500 など）より大きくしても問題なく、\
             大きいほど速くなります。通信がおかしいときの切り分けに 1500 へ下げてみてください。",
            |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.mtu).range(1280..=16000));
                    ui.label(RichText::new("推奨 9000").weak());
                });
            },
        );
    }
}

fn access_point(s: &config::EngineConfig) -> AccessPoint {
    AccessPoint { ssid: s.hotspot_ssid.clone(), passphrase: s.hotspot_passphrase.clone() }
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(14.0);
    ui.heading(title);
    ui.separator();
}

/// 見出し・入力欄・説明の 1 項目
fn item(ui: &mut egui::Ui, title: &str, help: &str, control: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(8.0);
    ui.strong(title);
    control(ui);
    ui.label(RichText::new(help).weak());
}

/// 手動モードを選んだときに出す手順
fn manual_mode_steps(ui: &mut egui::Ui, tun_name: &str) {
    ui.add_space(6.0);
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
        ui.strong("手動モードの使い方");
        for step in [
            "「設定を保存」を押してから、上の「▶ 開始」で開始します（停止中は TUN がないので経路を追加できません）。".to_string(),
            "「経路」タブの「経路を追加」で、宛先にルールを効かせたい IP か範囲（例: 1.1.1.1/32、203.0.113.0/24）を入れます。".to_string(),
            format!("出口に「{tun_name}」を選び、ゲートウェイは空欄、メトリックは 1 のままで「＋ 追加」を押します。"),
            "経路一覧に青字の「TUN」として出れば完了です。その宛先への通信だけが TUN を通り、「接続」タブに現れます。".to_string(),
        ]
        .iter()
        .enumerate()
        {
            let (n, text) = step;
            ui.label(format!("{}. {text}", n + 1));
        }
        ui.label(
            RichText::new(
                "停止すると TUN と一緒に経路も消えるので、開始するたびに追加し直してください。\
                 ドメイン名では指定できないので、nslookup などで IP を調べて入れます。\
                 全通信を捕捉しつつ一部の宛先だけ TUN から外したいなら、手動モードではなくルールの -A BYPASS を使います。",
            )
            .weak(),
        );
    });
}

fn ip_edit<T: std::str::FromStr + ToString>(ui: &mut egui::Ui, v: &mut T) {
    let id = ui.next_auto_id();
    let mut text = ui.data_mut(|d| d.get_temp::<String>(id)).unwrap_or_else(|| v.to_string());
    let ok = text.parse::<T>().is_ok();
    let edit = egui::TextEdit::singleline(&mut text).desired_width(200.0).text_color_opt((!ok).then_some(Color32::RED));
    ui.add(edit);
    if let Ok(parsed) = text.parse::<T>() {
        *v = parsed;
    }
    ui.data_mut(|d| d.insert_temp(id, text));
}

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui::{self, Align, Color32, Layout, RichText};
use egui_extras::TableBuilder;

use crate::config::EngineConfig;
use crate::engine::{Engine, InstalledRoute, Shared};
use crate::rules::Proto;
use crate::{config, procinfo, rules, sys, winnet};

mod connections;
mod network;
mod rule_editor;
mod settings;

const RED: Color32 = Color32::from_rgb(220, 80, 60);
const GREEN: Color32 = Color32::from_rgb(60, 180, 90);
const ORANGE: Color32 = Color32::from_rgb(220, 120, 40);
const BLUE: Color32 = Color32::from_rgb(90, 150, 230);
/// ウィンドウを閉じたときに停止処理を待つ上限（開始途中なら経路の追加リトライも含む）
const EXIT_STOP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Rules,
    Conns,
    Routes,
    Ifaces,
    Settings,
    Log,
}

struct RouteForm {
    dst: String,
    oif: String,
    gw: String,
    metric: u32,
    temporary: bool,
}

/// 別スレッドで実行中の開始・停止処理（GUI を固めないため）
enum Pending {
    Starting(mpsc::Receiver<anyhow::Result<Engine>>),
    Stopping(mpsc::Receiver<()>),
}

pub struct App {
    /// exe 埋め込みのアイコンを最初のフレームでウィンドウに設定したか
    icon_set: bool,
    shared: Arc<Shared>,
    engine: Option<Engine>,
    pending: Option<Pending>,
    /// ホットスポットの切替（数秒かかるので別スレッドで行う）の結果待ち
    hotspot_task: Option<mpsc::Receiver<anyhow::Result<String>>>,
    settings: EngineConfig,
    tab: Tab,
    is_admin: bool,
    status: Option<(bool, String)>,

    rules_text: String,
    rule_errors: Vec<rules::ParseError>,
    /// ルール画面の「例と書き方」パネルを出すか
    rules_help: bool,

    conn_filter: String,
    show_closed: bool,

    ifaces: Vec<winnet::Iface>,
    routes: Vec<winnet::Route>,
    route_filter: String,
    route_hide_system: bool,
    route_show_v6: bool,
    route_form: RouteForm,
    /// 「経路」タブで追加し、停止・終了時に消す経路
    temp_routes: Vec<InstalledRoute>,
    confirm_delete: Option<usize>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_japanese_font(&cc.egui_ctx);
        let shared = Arc::new(Shared::default());
        let rules_text = config::load_rules();
        let rule_errors = match rules::parse(&rules_text) {
            Ok(rs) => {
                shared.rules.store(Arc::new(rs));
                Vec::new()
            }
            Err(e) => e,
        };
        let mut app = App {
            icon_set: false,
            shared,
            engine: None,
            pending: None,
            hotspot_task: None,
            settings: config::load_settings(),
            tab: Tab::Rules,
            is_admin: sys::is_admin(),
            status: None,
            rules_text,
            rule_errors,
            rules_help: true,
            conn_filter: String::new(),
            show_closed: true,
            ifaces: Vec::new(),
            routes: Vec::new(),
            route_filter: String::new(),
            route_hide_system: true,
            route_show_v6: true,
            route_form: RouteForm { dst: String::new(), oif: String::new(), gw: String::new(), metric: 1, temporary: true },
            temp_routes: Vec::new(),
            confirm_delete: None,
        };
        app.refresh_net();
        if !app.is_admin {
            app.status = Some((false, "管理者権限がありません。開始や経路変更には管理者として再起動してください".into()));
        }
        app
    }

    fn refresh_net(&mut self) {
        self.ifaces = winnet::list_interfaces().unwrap_or_default();
        self.routes = winnet::list_routes().unwrap_or_default();
        self.routes.sort_by(|a, b| a.dst.addr().is_ipv6().cmp(&b.dst.addr().is_ipv6()).then(a.dst.cmp(&b.dst)));
        self.confirm_delete = None;
        if self.route_form.oif.is_empty()
            && let Some(i) = self.main_iface()
        {
            self.route_form.oif = i.name.clone();
        }
    }

    /// 既定ゲートウェイを持つ（普段の出口になっている）NIC。フォームや例の既定値に使う
    fn main_iface(&self) -> Option<&winnet::Iface> {
        self.ifaces.iter().find(|i| i.up && !i.loopback && !i.gateways.is_empty())
    }

    fn set_status(&mut self, ok: bool, msg: impl Into<String>) {
        let msg = msg.into();
        self.shared.log(&msg);
        self.status = Some((ok, msg));
    }

    fn start(&mut self, ctx: &egui::Context) {
        if let Err(e) = config::save_settings(&self.settings) {
            self.shared.log(format!("設定の保存に失敗: {e}"));
        }
        let (tx, rx) = mpsc::channel();
        let (cfg, shared, ctx) = (self.settings.clone(), self.shared.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Engine::start(cfg, shared));
            ctx.request_repaint();
        });
        self.pending = Some(Pending::Starting(rx));
        self.status = Some((true, "開始しています…".into()));
    }

    fn stop(&mut self, ctx: &egui::Context) {
        self.remove_temp_routes();
        let Some(engine) = self.engine.take() else { return };
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            engine.stop();
            let _ = tx.send(());
            ctx.request_repaint();
        });
        self.pending = Some(Pending::Stopping(rx));
        self.status = Some((true, "停止しています…".into()));
    }

    fn poll_hotspot(&mut self) {
        let Some(rx) = &self.hotspot_task else { return };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err(anyhow::anyhow!("切替処理が異常終了しました")),
        };
        self.hotspot_task = None;
        match result {
            Ok(message) => self.set_status(true, message),
            Err(e) => self.set_status(false, format!("ホットスポット: {e:#}")),
        }
    }

    /// TUN を共有元にしたモバイル ホットスポットのオン・オフ
    fn hotspot_button(&mut self, ui: &mut egui::Ui) {
        let Some(engine) = &self.engine else { return };
        let hotspot = engine.hotspot();
        let state = if self.hotspot_task.is_some() { None } else { hotspot.status() };
        let Some(on) = state else {
            ui.add_enabled(false, egui::Button::new("ホットスポット 切替中…"));
            ui.spinner();
            return;
        };
        let text =
            if on { RichText::new("ホットスポット: オン").color(GREEN) } else { RichText::new("ホットスポット: オフ") };
        let hover = "TUN を共有元にして Windows のモバイル ホットスポットをオン・オフします。つないだ端末の通信にもルールが適用されます（名前とパスワードは Windows の設定のもの）";
        if !ui.button(text).on_hover_text(hover).clicked() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ui.ctx().clone();
        std::thread::spawn(move || {
            let _ = tx.send(if on { hotspot.turn_off() } else { hotspot.turn_on() });
            ctx.request_repaint();
        });
        self.hotspot_task = Some(rx);
        let msg = if on {
            "ホットスポットを停止しています…"
        } else {
            "ホットスポットを開始しています…（数秒かかります）"
        };
        self.status = Some((true, msg.into()));
    }

    fn poll_pending(&mut self) {
        match &self.pending {
            Some(Pending::Starting(rx)) => match rx.try_recv() {
                Ok(Ok(e)) => {
                    self.engine = Some(e);
                    self.pending = None;
                    self.status = Some((true, "稼働中".into()));
                    self.refresh_net();
                }
                Ok(Err(e)) => {
                    self.pending = None;
                    self.set_status(false, format!("開始に失敗: {e:#}"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.set_status(false, "開始処理が異常終了しました");
                }
            },
            Some(Pending::Stopping(rx)) if !matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)) => {
                self.pending = None;
                self.status = Some((true, "停止しました".into()));
                self.refresh_net();
            }
            Some(Pending::Stopping(_)) | None => {}
        }
    }

    fn remove_temp_routes(&mut self) {
        for r in std::mem::take(&mut self.temp_routes) {
            if let Err(e) = r.remove() {
                self.shared.log(format!("一時経路 {} の削除に失敗: {e}", r.dst));
            }
        }
    }

    fn apply_rules(&mut self) {
        match rules::parse(&self.rules_text) {
            Ok(rs) => {
                self.rule_errors.clear();
                let n = rs.rules.len();
                self.refresh_net();
                let missing: Vec<_> = rs
                    .referenced_interfaces()
                    .into_iter()
                    .filter(|name| winnet::find_iface(&self.ifaces, name).is_none())
                    .map(|name| format!("\"{name}\""))
                    .collect();
                let idle: Vec<String> = rs
                    .local_dnat_ports()
                    .into_iter()
                    .filter(|&port| procinfo::listener_pid(Proto::Tcp, port).is_none())
                    .map(|port| port.to_string())
                    .collect();
                let mut warnings = Vec::new();
                if !missing.is_empty() {
                    warnings.push(format!("存在しないインターフェース: {}", missing.join(", ")));
                }
                if !idle.is_empty() {
                    warnings.push(format!(
                        "転送先のポート {} で待ち受けているプロセスがありません（プロキシを起動しないと、転送する通信はすべて失敗します）",
                        idle.join(", ")
                    ));
                }
                if let Some(e) = &mut self.engine {
                    e.sync_bypass(&rs);
                }
                self.shared.rules.store(Arc::new(rs));
                match config::save_rules(&self.rules_text) {
                    Err(e) => self.set_status(false, format!("適用しましたが保存に失敗: {e}")),
                    Ok(()) if !warnings.is_empty() => {
                        self.set_status(false, format!("適用しました（{n} 件）。ただし{}", warnings.join("。")))
                    }
                    Ok(()) => self.set_status(true, format!("ルールを適用しました（{n} 件）")),
                }
                self.refresh_net();
            }
            Err(errs) => {
                self.status = Some((false, format!("ルールに {} 件のエラーがあります（未適用）", errs.len())));
                self.rule_errors = errs;
            }
        }
    }

    // ───────────────────────── 各タブ ─────────────────────────

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(p) = &self.pending {
                ui.add_enabled(false, egui::Button::new(RichText::new("処理中").size(16.0)));
                ui.spinner();
                ui.label(if matches!(p, Pending::Starting(_)) { "開始中…" } else { "停止中…" });
            } else if self.engine.is_some() {
                if ui.button(RichText::new("■ 停止").size(16.0)).clicked() {
                    self.stop(ui.ctx());
                }
                ui.label(RichText::new("● 稼働中").color(GREEN).strong());
                ui.separator();
                self.hotspot_button(ui);
            } else {
                let btn = ui.add_enabled(self.is_admin, egui::Button::new(RichText::new("▶ 開始").size(16.0)));
                if btn.clicked() {
                    self.start(ui.ctx());
                }
                ui.label(RichText::new("○ 停止中").color(Color32::GRAY));
                if !self.is_admin && ui.button("管理者として再起動").clicked() {
                    if let Err(e) = sys::relaunch_as_admin() {
                        self.set_status(false, format!("再起動に失敗: {e}"));
                    } else {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            ui.separator();
            let s = &self.shared;
            ui.label(format!(
                "アクティブ {}  合計 {}  ↑ {}  ↓ {}",
                s.active.load(Ordering::Relaxed),
                s.total.load(Ordering::Relaxed),
                fmt_bytes(s.bytes_up.load(Ordering::Relaxed)),
                fmt_bytes(s.bytes_down.load(Ordering::Relaxed)),
            ));
        });
        if let Some((ok, msg)) = &self.status {
            let color = if *ok { ui.visuals().text_color() } else { RED };
            ui.label(RichText::new(msg).color(color));
        }
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            for (t, label) in [
                (Tab::Rules, "ルール"),
                (Tab::Conns, "接続"),
                (Tab::Routes, "経路"),
                (Tab::Ifaces, "インターフェース"),
                (Tab::Settings, "設定"),
                (Tab::Log, "ログ"),
            ] {
                if ui.selectable_label(self.tab == t, label).clicked() {
                    if matches!(t, Tab::Routes | Tab::Ifaces) {
                        self.refresh_net();
                    }
                    self.tab = t;
                }
            }
        });
        ui.add_space(2.0);
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        let logs: Vec<String> = self.shared.logs.lock().iter().cloned().collect();
        egui::ScrollArea::vertical().auto_shrink(false).stick_to_bottom(true).show(ui, |ui| {
            for l in logs {
                ui.label(RichText::new(l).monospace());
            }
        });
    }
}

fn table(ui: &mut egui::Ui) -> TableBuilder<'_> {
    TableBuilder::new(ui).striped(true).resizable(false).cell_layout(Layout::left_to_right(Align::Center))
}

fn right(ui: &mut egui::Ui, text: String) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(text));
}

fn labeled(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).weak());
    add(ui);
    ui.add_space(8.0);
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        if !self.icon_set {
            self.icon_set = true;
            if let Ok(h) = raw_window_handle::HasWindowHandle::window_handle(frame)
                && let raw_window_handle::RawWindowHandle::Win32(w) = h.as_raw()
            {
                sys::set_window_icon(w.hwnd.get());
            }
        }
        self.poll_pending();
        self.poll_hotspot();
        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Rules => self.rules_tab(ui),
            Tab::Conns => self.conns_tab(ui),
            Tab::Routes => self.routes_tab(ui),
            Tab::Ifaces => self.ifaces_tab(ui),
            Tab::Settings => self.settings_tab(ui),
            Tab::Log => self.log_tab(ui),
        });
        if self.pending.is_some() || self.hotspot_task.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        } else if self.engine.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // ウィンドウを閉じたら必ず経路を元に戻す（開始・停止の途中なら終わるのを待つ）
        self.remove_temp_routes();
        let (pending, engine) = (self.pending.take(), self.engine.take());
        if pending.is_none() && engine.is_none() {
            return;
        }
        // 停止処理（アダプタの削除など）が戻らないとウィンドウが固まったままになるので、別スレッドで上限付きで待つ。
        // Engine::stop は経路を先に消すので、打ち切って終了しても通信は物理NICに戻り、
        // 残ったアダプタもプロセスの終了で消える
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            match pending {
                Some(Pending::Starting(rx)) => {
                    if let Ok(Ok(e)) = rx.recv() {
                        e.stop();
                    }
                }
                Some(Pending::Stopping(rx)) => {
                    let _ = rx.recv();
                }
                None => {}
            }
            if let Some(e) = engine {
                e.stop();
            }
            let _ = tx.send(());
        });
        if rx.recv_timeout(EXIT_STOP_TIMEOUT).is_err() {
            self.shared.log(format!("停止処理が {} 秒で終わらないため打ち切って終了します", EXIT_STOP_TIMEOUT.as_secs()));
        }
    }
}

fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

fn install_japanese_font(ctx: &egui::Context) {
    // 和文フォントは欧文フォールバックとベースラインがずれるので、フォントごとに下へ補正する
    let candidates = [("YuGothM.ttc", 0.25), ("meiryo.ttc", 0.1), ("msgothic.ttc", 0.0)];
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    for (name, y_offset_factor) in candidates {
        let Ok(bytes) = std::fs::read(format!(r"{windir}\Fonts\{name}")) else { continue };
        let families = [egui::FontFamily::Proportional, egui::FontFamily::Monospace]
            .into_iter()
            .map(|family| egui::epaint::text::InsertFontFamily { family, priority: egui::epaint::text::FontPriority::Lowest })
            .collect();
        let data = egui::FontData::from_owned(bytes).tweak(egui::FontTweak { y_offset_factor, ..Default::default() });
        ctx.add_font(egui::epaint::text::FontInsert::new("jp", data, families));
        return;
    }
}

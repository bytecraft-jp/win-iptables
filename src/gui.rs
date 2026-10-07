use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui::{self, Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};
use ipnet::IpNet;

use crate::engine::{self, ConnState, Engine, EngineConfig, InstalledRoute, RouteMode, Shared};
use crate::rules::Proto;
use crate::{config, rules, sys, winnet};

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

/// 接続表の 1 行。ロックを握ったまま描画しないよう、描画前にコピーする
struct ConnRow {
    time: String,
    proto: Proto,
    process: String,
    src: String,
    dst: String,
    line: String,
    action: String,
    up: u64,
    down: u64,
    state: ConnState,
}

pub struct App {
    /// exe 埋め込みのアイコンを最初のフレームでウィンドウに設定したか
    icon_set: bool,
    shared: Arc<Shared>,
    engine: Option<Engine>,
    pending: Option<Pending>,
    settings: EngineConfig,
    tab: Tab,
    is_admin: bool,
    status: Option<(bool, String)>,

    rules_text: String,
    rule_errors: Vec<rules::ParseError>,

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
            settings: config::load_settings(),
            tab: Tab::Rules,
            is_admin: sys::is_admin(),
            status: None,
            rules_text,
            rule_errors,
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
            && let Some(i) = self.ifaces.iter().find(|i| i.up && !i.loopback && !i.gateways.is_empty())
        {
            self.route_form.oif = i.name.clone();
        }
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
            Some(Pending::Stopping(rx)) => {
                if !matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    self.pending = None;
                    self.status = Some((true, "停止しました".into()));
                    self.refresh_net();
                }
            }
            None => {}
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
                if let Some(e) = &mut self.engine {
                    e.sync_bypass(&rs);
                }
                self.shared.rules.store(Arc::new(rs));
                match config::save_rules(&self.rules_text) {
                    Err(e) => self.set_status(false, format!("適用しましたが保存に失敗: {e}")),
                    Ok(()) if !missing.is_empty() => self.set_status(
                        false,
                        format!("適用しました（{n} 件）。ただし存在しないインターフェース: {}", missing.join(", ")),
                    ),
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

    fn rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("適用して保存 (Ctrl+S)").clicked() {
                self.apply_rules();
            }
            if ui.button("保存済みに戻す").clicked() {
                self.rules_text = config::load_rules();
                self.rule_errors.clear();
            }
            ui.label(RichText::new(config::rules_path().display().to_string()).weak().small());
        });
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.apply_rules();
        }
        for e in &self.rule_errors {
            ui.colored_label(RED, e.to_string());
        }
        egui::ScrollArea::both().auto_shrink(false).show(ui, |ui| {
            ui.add_sized(
                ui.available_size(),
                egui::TextEdit::multiline(&mut self.rules_text).code_editor().desired_width(f32::INFINITY),
            );
        });
    }

    fn conn_rows(&self) -> Vec<ConnRow> {
        let filter = self.conn_filter.to_lowercase();
        let conns = self.shared.conns.lock();
        conns
            .iter()
            .rev()
            .filter(|c| self.show_closed || matches!(c.state, ConnState::Open | ConnState::Connecting))
            .filter(|c| {
                filter.is_empty()
                    || c.process.as_deref().unwrap_or("").contains(&filter)
                    || c.src.ip().to_string().contains(&filter)
                    || c.dst.to_string().contains(&filter)
                    || c.action.to_lowercase().contains(&filter)
            })
            .map(|c| ConnRow {
                time: c.time.clone(),
                proto: c.proto,
                process: c.process.clone().unwrap_or_else(|| "?".into()),
                src: c.src.ip().to_string(),
                dst: c.dst.to_string(),
                line: c.rule_line.map_or("pol".into(), |l| l.to_string()),
                action: c.action.clone(),
                up: c.counters.up.load(Ordering::Relaxed),
                down: c.counters.down.load(Ordering::Relaxed),
                state: c.state.clone(),
            })
            .collect()
        // ここでロックを解放してから描画する
    }

    fn conns_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("絞り込み:");
            ui.text_edit_singleline(&mut self.conn_filter);
            ui.checkbox(&mut self.show_closed, "終了した接続も表示");
            if ui.button("クリア").clicked() {
                self.shared.conns.lock().retain(|c| matches!(c.state, ConnState::Open | ConnState::Connecting));
            }
        });
        let rows = self.conn_rows();
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        table(ui)
            .column(Column::exact(64.0))
            .column(Column::exact(44.0))
            .column(Column::initial(140.0).at_least(80.0).resizable(true))
            .column(Column::initial(110.0).at_least(60.0).resizable(true))
            .column(Column::initial(200.0).at_least(100.0).resizable(true))
            .column(Column::exact(40.0))
            .column(Column::initial(160.0).at_least(80.0).resizable(true))
            .column(Column::exact(76.0))
            .column(Column::exact(76.0))
            .column(Column::remainder().at_least(80.0))
            .header(22.0, |mut h| {
                for t in ["時刻", "proto", "プロセス", "送信元", "宛先", "行", "動作", "↑", "↓", "状態"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let c = &rows[row.index()];
                    row.col(|ui| {
                        ui.label(&c.time);
                    });
                    row.col(|ui| {
                        ui.label(c.proto.to_string());
                    });
                    row.col(|ui| {
                        ui.label(&c.process);
                    });
                    row.col(|ui| {
                        ui.label(&c.src).on_hover_text(&c.src);
                    });
                    row.col(|ui| {
                        ui.label(&c.dst);
                    });
                    row.col(|ui| {
                        ui.label(&c.line);
                    });
                    row.col(|ui| {
                        ui.label(&c.action);
                    });
                    row.col(|ui| {
                        right(ui, fmt_bytes(c.up));
                    });
                    row.col(|ui| {
                        right(ui, fmt_bytes(c.down));
                    });
                    row.col(|ui| {
                        let (text, color) = match &c.state {
                            ConnState::Connecting => ("接続中".to_string(), Color32::GOLD),
                            ConnState::Open => ("通信中".to_string(), GREEN),
                            ConnState::Closed => ("終了".to_string(), Color32::GRAY),
                            ConnState::Blocked => ("遮断".to_string(), ORANGE),
                            ConnState::Failed(m) => (format!("失敗: {m}"), RED),
                        };
                        ui.label(RichText::new(&text).color(color)).on_hover_text(text);
                    });
                });
            });
    }

    fn route_form_ui(&mut self, ui: &mut egui::Ui) {
        let is_admin = self.is_admin;
        let mut add = false;
        egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong("経路を追加");
            ui.add_space(4.0);
            let f = &mut self.route_form;
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                labeled(ui, "宛先", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.dst).hint_text("203.0.113.0/24").desired_width(170.0));
                });
                labeled(ui, "出口", |ui| {
                    egui::ComboBox::from_id_salt("route_oif").selected_text(f.oif.clone()).width(190.0).show_ui(ui, |ui| {
                        for i in self.ifaces.iter().filter(|i| i.up && !i.loopback) {
                            ui.selectable_value(&mut f.oif, i.name.clone(), &i.name);
                        }
                    });
                });
                labeled(ui, "ゲートウェイ", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.gw).hint_text("自動").desired_width(150.0))
                        .on_hover_text("空欄なら出口NICの既定ゲートウェイ（無ければオンリンク）");
                });
                labeled(ui, "メトリック", |ui| {
                    ui.add(egui::DragValue::new(&mut f.metric).range(0..=9999));
                });
                ui.checkbox(&mut f.temporary, "停止・終了時に削除");
                add = ui.add_enabled(is_admin, egui::Button::new("＋ 追加")).clicked();
            });
        });
        if add {
            self.add_route_from_form();
        }
    }

    fn is_system_route(r: &winnet::Route, loopbacks: &[u64]) -> bool {
        let multicast = match r.dst.addr() {
            IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
            IpAddr::V6(a) => a.is_multicast() || a.is_unicast_link_local(),
        };
        let host = r.dst.prefix_len() == r.dst.max_prefix_len() && r.next_hop.is_unspecified();
        multicast || host || loopbacks.contains(&r.luid)
    }

    fn routes_tab(&mut self, ui: &mut egui::Ui) {
        self.route_form_ui(ui);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("⟳ 再読込").clicked() {
                self.refresh_net();
            }
            ui.add(egui::TextEdit::singleline(&mut self.route_filter).hint_text("宛先・NIC名で絞り込み").desired_width(200.0));
            ui.checkbox(&mut self.route_hide_system, "システム経路を隠す")
                .on_hover_text("マルチキャスト・ブロードキャスト・ホスト経路・ループバックを非表示");
            ui.checkbox(&mut self.route_show_v6, "IPv6");
        });
        ui.add_space(4.0);

        let names: HashMap<u64, &str> = self.ifaces.iter().map(|i| (i.luid, i.name.as_str())).collect();
        let loopbacks: Vec<u64> = self.ifaces.iter().filter(|i| i.loopback).map(|i| i.luid).collect();
        let tun = self.engine.as_ref().map(|e| e.tun_luid);
        let filter = self.route_filter.to_lowercase();
        let is_temp = |r: &winnet::Route| self.temp_routes.iter().any(|t| t.luid == r.luid && t.dst == r.dst);
        let visible: Vec<usize> = (0..self.routes.len())
            .filter(|&i| {
                let r = &self.routes[i];
                let name = names.get(&r.luid).copied().unwrap_or("");
                let ours = Some(r.luid) == tun || is_temp(r);
                (self.route_show_v6 || r.dst.addr().is_ipv4())
                    && (ours || !self.route_hide_system || !Self::is_system_route(r, &loopbacks))
                    && (filter.is_empty() || r.dst.to_string().contains(&filter) || name.to_lowercase().contains(&filter))
            })
            .collect();
        if visible.is_empty() {
            ui.label(RichText::new("表示する経路がありません").weak());
            return;
        }

        let mut delete = None;
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        table(ui)
            .column(Column::initial(210.0).at_least(120.0).resizable(true))
            .column(Column::initial(190.0).at_least(100.0).resizable(true))
            .column(Column::remainder().at_least(140.0))
            .column(Column::exact(84.0))
            .column(Column::exact(56.0))
            .column(Column::exact(120.0))
            .header(24.0, |mut h| {
                h.col(|ui| {
                    ui.strong("宛先");
                });
                h.col(|ui| {
                    ui.strong("ゲートウェイ");
                });
                h.col(|ui| {
                    ui.strong("インターフェース");
                });
                h.col(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.strong("メトリック"));
                });
                h.col(|ui| {
                    ui.strong("種別");
                });
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(26.0, visible.len(), |mut row| {
                    let idx = visible[row.index()];
                    let r = &self.routes[idx];
                    let on_tun = Some(r.luid) == tun;
                    let temp = is_temp(r);
                    row.col(|ui| {
                        let t = RichText::new(r.dst.to_string()).monospace();
                        ui.label(if on_tun { t.color(BLUE) } else { t });
                    });
                    row.col(|ui| {
                        if r.next_hop.is_unspecified() {
                            ui.label(RichText::new("オンリンク").weak());
                        } else {
                            ui.label(RichText::new(r.next_hop.to_string()).monospace());
                        }
                    });
                    row.col(|ui| {
                        let name = names.get(&r.luid).copied().unwrap_or("?");
                        ui.label(name).on_hover_text(name);
                    });
                    row.col(|ui| {
                        right(ui, r.metric.to_string());
                    });
                    row.col(|ui| {
                        let (text, color) = match (on_tun, temp, r.protocol) {
                            (true, _, _) => ("TUN", BLUE),
                            (_, true, _) => ("一時", ORANGE),
                            (_, _, 3) => ("静的", ui.visuals().text_color()),
                            (_, _, 2) => ("自動", Color32::GRAY),
                            _ => ("その他", Color32::GRAY),
                        };
                        ui.label(RichText::new(text).color(color));
                    });
                    row.col(|ui| {
                        let confirming = self.confirm_delete == Some(idx);
                        let btn = if confirming {
                            egui::Button::new(RichText::new("本当に削除？").color(Color32::WHITE)).fill(RED)
                        } else {
                            egui::Button::new("削除")
                        };
                        if ui.add_enabled(self.is_admin, btn.min_size(egui::vec2(100.0, 0.0))).clicked() {
                            if confirming {
                                delete = Some(idx);
                            } else {
                                self.confirm_delete = Some(idx);
                            }
                        }
                    });
                });
            });
        if let Some(idx) = delete {
            self.confirm_delete = None;
            let r = self.routes[idx].clone();
            let gw = (!r.next_hop.is_unspecified()).then_some(r.next_hop);
            match winnet::delete_route(r.luid, r.dst, gw) {
                Ok(()) => {
                    self.temp_routes.retain(|t| !(t.luid == r.luid && t.dst == r.dst));
                    self.set_status(true, format!("経路 {} を削除しました", r.dst));
                }
                Err(e) => self.set_status(false, format!("経路 {} の削除に失敗: {e}", r.dst)),
            }
            self.refresh_net();
        }
    }

    fn add_route_from_form(&mut self) {
        let f = &self.route_form;
        let dst = match f.dst.trim().parse::<IpNet>().or_else(|_| f.dst.trim().parse::<IpAddr>().map(IpNet::from)) {
            Ok(n) => n.trunc(),
            Err(_) => return self.set_status(false, format!("宛先が不正です: {}", f.dst)),
        };
        let gw = match f.gw.trim() {
            "" => None,
            s => match s.parse::<IpAddr>() {
                Ok(g) => Some(g),
                Err(_) => return self.set_status(false, format!("ゲートウェイが不正です: {s}")),
            },
        };
        let (oif, metric, temporary) = (f.oif.clone(), f.metric, f.temporary);
        match engine::add_route_by_name(&oif, dst, gw, metric) {
            Ok(r) => {
                if temporary {
                    self.temp_routes.push(r);
                }
                self.set_status(true, format!("経路 {dst} → {oif} を追加しました"));
            }
            Err(e) => self.set_status(false, format!("{e:#}")),
        }
        self.refresh_net();
    }

    fn ifaces_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("⟳ 再読込").clicked() {
                self.refresh_net();
            }
            ui.label(RichText::new("名前をクリックするとコピーします（ルールの -o に使用）").weak());
        });
        let mut copied = None;
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        table(ui)
            .column(Column::initial(200.0).at_least(100.0).resizable(true))
            .column(Column::exact(50.0))
            .column(Column::exact(40.0))
            .column(Column::initial(340.0).at_least(120.0).resizable(true))
            .column(Column::initial(200.0).at_least(80.0).resizable(true))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                for t in ["名前", "状態", "#", "アドレス", "ゲートウェイ", "説明"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|mut body| {
                for i in self.ifaces.iter().filter(|i| !i.loopback) {
                    // リンクローカルは送出に使えないので表示しない
                    let addrs: Vec<String> = i
                        .addrs
                        .iter()
                        .filter(|(a, _)| match a {
                            IpAddr::V4(a) => !a.is_link_local(),
                            IpAddr::V6(a) => !a.is_unicast_link_local(),
                        })
                        .map(|(a, p)| format!("{a}/{p}"))
                        .collect();
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            if ui.link(&i.name).clicked() {
                                copied = Some(i.name.clone());
                            }
                        });
                        row.col(|ui| {
                            ui.label(if i.up { RichText::new("UP").color(GREEN) } else { RichText::new("down").weak() });
                        });
                        row.col(|ui| {
                            ui.label(i.index.to_string());
                        });
                        row.col(|ui| {
                            ui.label(addrs.join(", ")).on_hover_text(addrs.join("\n"));
                        });
                        row.col(|ui| {
                            ui.label(i.gateways.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(", "));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&i.description).weak());
                        });
                    });
                }
            });
        if let Some(name) = copied {
            ui.ctx().copy_text(name.clone());
            self.status = Some((true, format!("\"{name}\" をコピーしました")));
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let locked = self.engine.is_some() || self.pending.is_some();
        if locked {
            ui.label(RichText::new("稼働中は変更できません。停止してから変更してください。").weak());
        }
        ui.add_enabled_ui(!locked, |ui| {
            let s = &mut self.settings;
            egui::Grid::new("settings").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("TUN アダプタ名");
                ui.text_edit_singleline(&mut s.tun_name);
                ui.end_row();
                ui.label("TUN IPv4 アドレス");
                ui.horizontal(|ui| {
                    ip_edit(ui, &mut s.tun_ipv4);
                    ui.label("/");
                    ui.add(egui::DragValue::new(&mut s.tun_prefix).range(8..=30));
                });
                ui.end_row();
                ui.label("IPv6 も捕捉する");
                ui.checkbox(&mut s.capture_ipv6, "::/1 と 8000::/1 を TUN へ（IPv6 の素通りを防ぐ）");
                ui.end_row();
                ui.label("TUN IPv6 アドレス");
                ui.add_enabled_ui(s.capture_ipv6, |ui| ip_edit(ui, &mut s.tun_ipv6));
                ui.end_row();
                ui.label("MTU");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.mtu).range(1280..=16000));
                    ui.label(RichText::new("推奨 9000（大きいほど TUN の往復が減って速い）").weak());
                });
                ui.end_row();
                ui.label("経路モード");
                ui.vertical(|ui| {
                    ui.radio_value(&mut s.route_mode, RouteMode::Split, "全通信を捕捉（0.0.0.0/1 + 128.0.0.0/1 を TUN へ）");
                    ui.radio_value(&mut s.route_mode, RouteMode::Manual, "手動（「経路」タブで TUN 向け経路を追加した宛先のみ）");
                });
                ui.end_row();
                ui.label("TUN の IP 転送");
                ui.checkbox(&mut s.tun_forwarding, "有効（ホットスポットなどにつないだ端末の通信を中継するのに必要）");
                ui.end_row();
                ui.label("新規接続の上限");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.connect_rate).range(0..=1000).suffix(" 件/秒"));
                    ui.label("まとめて");
                    ui.add(egui::DragValue::new(&mut s.connect_burst).range(1..=1000).suffix(" 件"));
                    ui.label(RichText::new("ルーターの「IP フラッド検出」対策。0 で無制限").weak());
                });
                ui.end_row();
                ui.label("接続中の同時数");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.connect_concurrency).range(0..=1000).suffix(" 件"));
                    ui.label(RichText::new("応答待ちの接続をこれ以上は並べない。0 で無制限").weak());
                });
                ui.end_row();
                ui.label("失敗した宛先の保留");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut s.connect_fail_hold).range(0..=600).suffix(" 秒"));
                    ui.label(RichText::new("つながらなかった宛先への再試行を外へ出さずに失敗させる。0 で無効").weak());
                });
                ui.end_row();
            });
            if ui.button("設定を保存").clicked() {
                match config::save_settings(&self.settings) {
                    Ok(()) => self.status = Some((true, "設定を保存しました".into())),
                    Err(e) => self.status = Some((false, format!("設定の保存に失敗: {e}"))),
                }
            }
        });
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
        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Rules => self.rules_tab(ui),
            Tab::Conns => self.conns_tab(ui),
            Tab::Routes => self.routes_tab(ui),
            Tab::Ifaces => self.ifaces_tab(ui),
            Tab::Settings => self.settings_tab(ui),
            Tab::Log => self.log_tab(ui),
        });
        if self.pending.is_some() {
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

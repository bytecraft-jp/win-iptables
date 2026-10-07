//! 経路とインターフェースの表示・操作。

use super::{App, BLUE, GREEN, ORANGE, RED, labeled, right, table};
use crate::{engine, rules, winnet};
use eframe::egui::{self, Align, Color32, Layout, RichText};
use egui_extras::Column;
use std::collections::HashMap;
use std::net::IpAddr;

impl App {
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

    pub(super) fn routes_tab(&mut self, ui: &mut egui::Ui) {
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
                    && (ours || !self.route_hide_system || !is_system_route(r, &loopbacks))
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
        let Some(dst) = rules::parse_cidr(f.dst.trim()) else {
            return self.set_status(false, format!("宛先が不正です: {}", f.dst));
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

    pub(super) fn ifaces_tab(&mut self, ui: &mut egui::Ui) {
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
                    let addrs: Vec<String> =
                        i.addrs.iter().filter(|(a, _)| !winnet::is_link_local(*a)).map(|(a, p)| format!("{a}/{p}")).collect();
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
}

/// 「システム経路を隠す」で隠す経路（マルチキャスト・ブロードキャスト・ホスト経路・ループバック）
fn is_system_route(r: &winnet::Route, loopbacks: &[u64]) -> bool {
    let multicast = match r.dst.addr() {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast() || a.is_unicast_link_local(),
    };
    let host = r.dst.prefix_len() == r.dst.max_prefix_len() && r.next_hop.is_unspecified();
    multicast || host || loopbacks.contains(&r.luid)
}

//! 接続表のスナップショットと描画。

use super::{App, GREEN, ORANGE, RED, fmt_bytes, right, table};
use crate::engine::ConnState;
use crate::rules::Proto;
use eframe::egui::{self, Color32, RichText};
use egui_extras::Column;
use std::sync::atomic::Ordering;

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

impl App {
    fn conn_rows(&self) -> Vec<ConnRow> {
        let filter = self.conn_filter.to_lowercase();
        let conns = self.shared.conns.lock();
        conns
            .iter()
            .rev()
            .filter(|c| self.show_closed || c.state.is_active())
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

    pub(super) fn conns_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("絞り込み:");
            ui.text_edit_singleline(&mut self.conn_filter);
            ui.checkbox(&mut self.show_closed, "終了した接続も表示");
            if ui.button("クリア").clicked() {
                self.shared.clear_finished();
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
}

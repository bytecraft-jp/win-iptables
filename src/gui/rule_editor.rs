//! ルールの編集と、用途別の例・書き方のヘルプ。

use super::{App, RED};
use crate::config;
use crate::rules::examples::{EXAMPLES, Example, IFACE_PLACEHOLDER, SYNTAX};
use eframe::egui::{self, RichText};

impl App {
    pub(super) fn rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("適用して保存 (Ctrl+S)").clicked() {
                self.apply_rules();
            }
            if ui.button("保存済みに戻す").clicked() {
                self.rules_text = config::load_rules();
                self.rule_errors.clear();
            }
            ui.toggle_value(&mut self.rules_help, "例と書き方");
            ui.label(RichText::new(config::rules_path().display().to_string()).weak().small());
        });
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.apply_rules();
        }
        for e in &self.rule_errors {
            ui.colored_label(RED, e.to_string());
        }
        if self.rules_help {
            let iface = self.main_iface().map_or("Wi-Fi".to_string(), |i| i.name.clone());
            let mut insert = None;
            egui::Panel::right("rules_help").resizable(true).default_size(380.0).min_size(260.0).show(ui, |ui| {
                insert = help_ui(ui, &iface);
            });
            if let Some(example) = insert {
                self.insert_example(example, &iface);
            }
        }
        egui::CentralPanel::no_frame().show(ui, |ui| {
            egui::ScrollArea::both().auto_shrink(false).show(ui, |ui| {
                ui.add_sized(
                    ui.available_size(),
                    egui::TextEdit::multiline(&mut self.rules_text).code_editor().desired_width(f32::INFINITY),
                );
            });
        });
    }

    /// 例をルールの末尾に足す（適用はしない）
    fn insert_example(&mut self, example: &Example, iface: &str) {
        let text = &mut self.rules_text;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("\n# {}\n{}\n", example.title, example.rules.replace(IFACE_PLACEHOLDER, iface)));
        self.status =
            Some((true, format!("「{}」を末尾に追加しました。内容を確かめて「適用して保存」を押すと有効になります", example.title)));
    }
}

/// 例と書き方のパネル。例の `{IF}` は `iface` に置き換えて見せる。押された例を返す
fn help_ui(ui: &mut egui::Ui, iface: &str) -> Option<&'static Example> {
    let mut insert = None;
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        ui.heading("例");
        ui.label(
            RichText::new("「追加」を押すとルールの末尾に入ります。「適用して保存」を押すまで有効になりません。上の行ほど優先されるので、必要なら並べ替えてください。")
                .weak(),
        );
        for category in EXAMPLES {
            egui::CollapsingHeader::new(category.name).show(ui, |ui| {
                for example in category.examples {
                    ui.horizontal(|ui| {
                        if ui.button("追加").clicked() {
                            insert = Some(example);
                        }
                        ui.strong(example.title);
                    });
                    ui.label(RichText::new(example.description).weak());
                    ui.label(RichText::new(example.rules.replace(IFACE_PLACEHOLDER, iface)).monospace());
                    ui.separator();
                }
            });
        }
        ui.add_space(8.0);
        ui.heading("書き方");
        for (heading, items) in SYNTAX {
            egui::CollapsingHeader::new(*heading).show(ui, |ui| {
                for (syntax, meaning) in *items {
                    ui.label(RichText::new(*syntax).monospace().strong());
                    ui.label(RichText::new(*meaning).weak());
                    ui.add_space(4.0);
                }
            });
        }
    });
    insert
}

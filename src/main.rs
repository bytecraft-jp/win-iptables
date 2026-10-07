#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod engine;
mod gui;
mod hotspot;
mod icmp;
mod ics;
mod pacer;
mod procinfo;
mod rules;
mod sys;
mod tundev;
mod winnet;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("win-iptables")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([720.0, 420.0])
            // 空にすると eframe は既定アイコンを設定しない。exe 埋め込みのアイコンを gui 側で設定する
            .with_icon(std::sync::Arc::new(eframe::egui::IconData::default())),
        ..Default::default()
    };
    eframe::run_native("win-iptables", options, Box::new(|cc| Ok(Box::new(gui::App::new(cc)))))
}

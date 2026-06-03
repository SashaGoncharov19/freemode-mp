// FreeMode Launcher — egui GUI with GTA V auto-detection and launch flow.

use eframe::egui;
use std::path::PathBuf;
use std::process::Command;

mod dll_redirector;
mod executable_loader;
mod game_cache;
mod game_path;
mod process;
mod snapshot_injector;

fn find_game_path() -> Option<PathBuf> {
    game_path::find_game_path()
}

enum State { Main, Launching(f32), Launched, Error(String) }

struct LauncherApp {
    game_path: Option<PathBuf>,
    server_idx: usize,
    state: State,
    path_input: String,
}

const SERVERS: [&str; 2] = [
    "FreeMode Main (127.0.0.1:30120)",
    "FreeMode EU (185.16.100.1:30120)",
];

impl LauncherApp {
    fn new() -> Self {
        let game_path = find_game_path();
        let path_str = game_path.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "".into());
        Self { game_path, server_idx: 0, state: State::Main, path_input: path_str }
    }

    fn refresh_game_path(&mut self) {
        if self.path_input.is_empty() {
            self.game_path = None;
            return;
        }
        let path = PathBuf::from(&self.path_input);
        if path.join("GTA5.exe").exists() {
            self.game_path = Some(path);
            return;
        }
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("GTA5.exe");
                if candidate.exists() {
                    self.game_path = Some(entry.path());
                    return;
                }
            }
        }
        self.game_path = Some(path);
    }

    fn on_browse(&mut self) {
        let gta_v_path = r"C:\Program Files\Steam\steamapps\common\GTA V";
        if PathBuf::from(gta_v_path).exists() {
            let _ = Command::new("explorer.exe")
                .args(&["/select,", gta_v_path])
                .spawn();
        } else if let Some(ref gp) = self.game_path {
            let _ = Command::new("explorer.exe")
                .arg(gp.to_str().unwrap_or(gta_v_path))
                .spawn();
        } else {
            if let Ok(doc) = std::env::var("USERPROFILE") {
                let _ = Command::new("explorer.exe").arg(&doc).spawn();
            }
        }
    }

    fn on_apply_path(&mut self) {
        self.refresh_game_path();
    }

    fn on_play(&mut self) {
        if self.game_path.is_none() {
            self.state = State::Error("No game path set! Enter a path or use Browse...".into());
            return;
        }
        
        let gta5_path = self.game_path.as_ref().unwrap().join("GTA5.exe");
        
        if !gta5_path.exists() {
            self.state = State::Error(format!("GTA5.exe not found at:\n{}", gta5_path.display()));
            return;
        }

        match launch_game(&gta5_path) {
            Ok(_) => { self.state = State::Launching(0.0); }
            Err(e) => { self.state = State::Error(format!("Failed to launch:\n{}", e)); }
        }
    }
}

/// Launch GTA5.exe by spawning it directly.
fn launch_game(gta5_path: &PathBuf) -> Result<(), String> {
    let gta5_parent = gta5_path.parent().ok_or("Invalid GTA5 path")?;
    
    // Spawn GTA5 normally — this is exactly what a player would do to start the game
    std::process::Command::new(gta5_path)
        .current_dir(gta5_parent)
        .spawn()
        .map_err(|e| format!("Failed to spawn GTA5.exe: {}", e))?;
    
    Ok(())
}

impl eframe::App for LauncherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let State::Launching(t) = self.state {
            let new_t = (t + 0.016).min(1.0);
            self.state = if new_t >= 1.0 { State::Launched } else { State::Launching(new_t) };
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading("FreeMode MP Launcher");
        });

        let state_ref = std::mem::replace(&mut self.state, State::Main);
        match state_ref {
            State::Main => { self.state = State::Main; egui::CentralPanel::default().show(ctx, |ui| self.render_main(ui)); }
            State::Launching(p) => { self.state = State::Launching(p); egui::CentralPanel::default().show(ctx, |ui| self.render_launching(ui, p)); }
            State::Launched => { self.state = State::Launched; egui::CentralPanel::default().show(ctx, |ui| self.render_launched(ui)); }
            State::Error(_) => { self.state = State::Main; }
        }

        if matches!(self.state, State::Launched) { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
    }
}

impl LauncherApp {
    fn render_main(&mut self, ui: &mut egui::Ui) {
        let detected = self.game_path.is_some();

        ui.vertical_centered_justified(|ui| {
            ui.add_space(20.0);
            ui.label(egui::RichText::new("FreeMode MP").font(egui::FontId::proportional(28.0)).color(egui::Color32::LIGHT_BLUE));
            ui.separator();
            ui.add_space(5.0);

            ui.label("Game Path:");
            
            ui.horizontal(|ui| {
                let result = ui.add(egui::TextEdit::singleline(&mut self.path_input)
                    .desired_width(310.0)
                    .text_color(if detected { egui::Color32::GREEN } else { egui::Color32::DARK_RED })
                    .hint_text("C:\\Path\\To\\GTA V"));
                
                if result.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.refresh_game_path();
                }
            });

            ui.horizontal(|ui| {
                if ui.button("\u{1F4C1} Apply Path").clicked() {
                    self.on_apply_path();
                }
                if ui.button("\u{1F50D} Browse...").clicked() {
                    self.on_browse();
                }
            });

            if !detected && !self.path_input.is_empty() {
                ui.add_space(2.0);
                let hint = "Use Apply Path to verify the path";
                ui.label(egui::RichText::new(hint).size(11.0).color(egui::Color32::from_rgb(255, 200, 100)));
            } else if !detected {
                ui.add_space(2.0);
                let hint = "No GTA V in default locations — enter path manually";
                ui.label(egui::RichText::new(hint).size(11.0).color(egui::Color32::from_rgb(255, 200, 100)));
            }

            ui.separator();

            ui.label("Server:");
            let sel = SERVERS[self.server_idx].to_string();
            if ui.button(&sel).clicked() { ui.close_menu(); }
            egui::ComboBox::from_id_salt("srv")
                .width(310.0)
                .selected_text(&sel)
                .show_ui(ui, |ui| {
                    for (i, s) in SERVERS.iter().enumerate() {
                        ui.selectable_value(&mut self.server_idx, i, (*s).to_string());
                    }
                });

            ui.separator();

            let is_ready = detected;
            let btn = egui::Button::new(format!("\u{25B6}  LAUNCH GTA V")).min_size(egui::vec2(280.0, 44.0));
            if ui.add_enabled(is_ready, btn).clicked() { self.on_play(); }

            ui.add_space(10.0);
            let status_text = if detected { "\u{2713} Ready — click LAUNCH to start" } else { "Enter a GTA V path and press Apply Path" };
            let status_color = if detected { egui::Color32::GREEN } else { egui::Color32::DARK_GRAY };
            ui.label(egui::RichText::new(status_text).color(status_color));

            ui.separator();
            ui.label("FreeMode MP Launcher v0.1.0");
        });
    }

    fn render_launching(&mut self, ui: &mut egui::Ui, progress: f32) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(50.0);
            ui.label(egui::RichText::new("Launching GTA V...").color(egui::Color32::LIGHT_BLUE).size(20.0));
            ui.add_space(25.0);

            let bw = 300.0;
            let bg = egui::Color32::DARK_GRAY;
            let fg = egui::Color32::GREEN;
            
            let (rect, _) = ui.allocate_exact_size(egui::vec2(bw, 8.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 4.0, bg);
            if progress > 0.01 {
                let fill = egui::Rect::from_min_size(rect.min, egui::vec2(bw * progress, 8.0));
                ui.painter().rect_filled(fill, 4.0, fg);
            }

            ui.add_space(15.0);
            let pct = (progress * 100.0) as u32;
            let status_msg: String = if pct >= 100 { "GTA V is launching...".into() } else { format!("{}% — Loading assets...", pct) };
            ui.label(status_msg.as_str());

            if let Some(ref p) = self.game_path {
                ui.add_space(8.0);
                ui.label(format!("From: {}", p.display()).as_str());
            }
        });
    }

    fn render_launched(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(60.0);
            let p = self.game_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            let msg = if p.is_empty() { "GTA V Launched!".to_string() } else { format!("GTA V Launched!\nFrom: {}", p) };
            ui.label(egui::RichText::new("\u{2713}  Success!").color(egui::Color32::GREEN).size(24.0));
            ui.add_space(10.0);
            for line in msg.lines() { ui.label(line); }
        });
    }
}

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([480.0, 600.0]).with_decorations(true),
        ..Default::default()
    };
    eframe::run_native("FreeMode MP Launcher", opts, Box::new(|_cc| Ok(Box::new(LauncherApp::new()))))
}
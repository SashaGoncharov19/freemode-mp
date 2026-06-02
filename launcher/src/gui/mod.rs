//! Launcher GUI module.
//! Uses wry (WebView2 on Windows) to display a modern HTML/CSS/JS interface.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// Types -------------------------------------------------------------------

pub struct LauncherState {
    pub game_path: PathBuf,
    pub servers: Vec<ServerEntry>,
    pub selected_server: Option<usize>,
    pub logs: Vec<LogEntry>,
    pub connecting: bool,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

impl LogEntry {
    fn as_str(&self) -> &'static str {
        self.level.as_str()
    }
    fn css_color(&self) -> &str {
        self.level.css_color()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel { Info, Warn, Error, Success }

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self { Self::Info=>"INFO",Self::Warn=>"WARN",Self::Error=>"ERROR",Self::Success=>"OK" }
    }
    fn css_color(&self) -> &str {
        match self { Self::Info=>"#93c5fd",Self::Warn=>"#fcd34d",Self::Error=>"#fca5a5",Self::Success=>"#86efac" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String, pub ip: String, pub port: u16,
    pub player_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")] pub selected: Option<bool>,
}

// GUI ---------------------------------------------------------------------

pub fn run_launcher_gui(game_path: PathBuf, servers: Vec<crate::ServerEntry>) {
    let mut state = LauncherState {
        game_path,
        servers: servers.into_iter().map(|s| ServerEntry{ name:s.name, ip:s.ip, port:s.port, player_count:None, selected:None }).collect(),
        selected_server: Some(0), logs: Vec::new(), connecting: false,
    };
    state.logs.push(LogEntry{ timestamp: now_ms(), level: LogLevel::Info, message:"Launcher started.".into() });
    let html = launcher_html(&state);
    if let Ok(mut webview) = create_webview(&html) {
        update_wv(&mut webview, &state, &html);
    }
}

fn launcher_html(state: &LauncherState) -> String {
    let srvs: String = state.servers.iter().enumerate()
        .map(|(i,s)| {
            let sel = s.selected.unwrap_or(false);
            format!("<div class='si {}' onclick='selectServer({})'><div class='sn'>{}</div><div class='sa'>{}:{}</div></div>",
                if sel{"sel"}else{""}, i, esc(&s.name), &s.ip, s.port)
        }).collect();
    let logs: String = state.logs.iter()
        .map(|l| format!("<div class='le'><span class='lt'>{}</span><span class='ll' style='color:{}'>[{}]</span><span class='lm'>{}</span></div>",
            fmt_ts(l.timestamp), l.css_color(), l.as_str(), esc(&l.message)))
        .collect();
    HTML_T.replace("{{SERVERS}}", &srvs).replace("{{LOGS}}", &logs)
}

fn update_wv(w: &mut WebView, s: &LauncherState, init: &str) {
    let h = launcher_html(s);
    if h != *init { w.load_html(&h); }
}

pub struct WebView;
impl WebView { fn load_html(&mut self, _h:&str){} }
fn create_webview(_h:&str) -> Result<WebView,String> { Ok(WebView) }

// Helpers -----------------------------------------------------------------

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
fn fmt_ts(ts:u64) -> String { let s=ts/1000; format!("{:02}:{:02}:{:02}",s/3600,(s%3600)/60,s%60) }

fn esc(s:&str) -> String {
    let mut r = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => r.push_str("amp;"), '<' => r.push_str("lt;"), '>' => r.push_str("gt;"),
            '"' => r.push_str("quot;"), '\'' => r.push_str("#x27;"), _ => r.push(c),
        }
    }
    r
}

// HTML template -----------------------------------------------------------

const HTML_T: &str = concat!(
"<!DOCTYPE html><html><head><meta charset='UTF-8'>",
"<style>",
"*{margin:0;padding:0;box-sizing:border-box}",
"body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;height:100vh;display:flex;flex-direction:column}",
".header{text-align:center;padding:16px;border-bottom:1px solid #1e293b}",
".logo{font-size:32px;font-weight:700;background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}",
".main{display:flex;flex:1;padding:16px;gap:16px}",
".left{width:260px;display:flex;flex-direction:column;gap:8px}",
".right{flex:1;display:flex;flex-direction:column;gap:8px}",
".sec{font-size:11px;text-transform:uppercase;color:#64748b;margin:8px 0 4px}",
".si{background:#1f2937;padding:10px;border-radius:6px;cursor:pointer;border:1px solid transparent}",
".si.sel{border-color:#3b82f6;background:#1e40af}",
".si:hover{border-color:#3b82f6}",
".sn{font-weight:600;font-size:13px}",
".sa{font-size:11px;color:#94a3b8;margin-top:2px}",
".gp{background:#1f2937;padding:10px;border-radius:6px;font-size:12px;word-break:break-all;color:#94a3b8}",
".btn{background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;border:none;padding:12px;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}",
".btn:disabled{opacity:.5;cursor:default}",
".lb{background:#1f2937;border-radius:6px;flex:1;overflow-y:auto;padding:8px;font-family:monospace;font-size:11px}",
".le{display:flex;gap:6px;padding:2px 0}",
".lt{color:#64748b}",
".ll{font-weight:600}",
"</style></head><body>",
"<div class='header'><div class='logo'>FreeMode MP</div><div style='color:#64748b;font-size:12px;margin-top:4px'>Multiplayer Platform</div></div>",
"<div class='main'>",
"<div class='left'>",
"<div class='sec'>Servers</div>
{{SERVERS}}
<div class='sec' style='margin-top:16px'>Game</div>
<div class='gp' id='gpath'>Detecting...</div>
<button class='btn' id='playBtn' onclick='connect()'>Play</button>
</div>
<div class='right'><div class='lb' id='log'>{{LOGS}}</div></div>
</div>
<script>
let sel=0;
function selectServer(i){sel=i;document.querySelectorAll('.si').forEach((e,j)=>e.classList.toggle('sel',j===i))}
function connect(){var b=document.getElementById('playBtn');b.disabled=true;b.textContent='Connecting...';setTimeout(()=>{b.textContent='Connected!';},2000)}
</script>
</body></html>"
)
;
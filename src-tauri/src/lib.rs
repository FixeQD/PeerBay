mod app;
mod features;
mod identity;
mod platform;
mod protocol;
mod session;
mod storage;
mod transport;

use app::AppRuntime;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let runtime = AppRuntime::new();
    runtime.start().expect("application runtime should start");

    let run_result = tauri::Builder::default()
        .manage(runtime.clone())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!());

    runtime.shutdown();
    run_result.expect("error while running tauri application");
}

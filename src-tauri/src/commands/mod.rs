//! User-intent commands exposed through the Tauri bridge.

#[tauri::command]
pub(crate) fn greet(name: &str) -> String {
    format!("Hello, {name}! You've been greeted from Rust!")
}

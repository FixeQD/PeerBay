mod app;
mod commands;
mod events;
mod features;
mod identity;
mod platform;
mod protocol;
mod redaction;
mod session;
mod storage;
mod transport;
mod viewmodel;

use app::AppRuntime;
use events::{EventName, LifecyclePayload};
#[cfg(target_os = "android")]
use platform::AndroidBridgeState;
use platform::PlatformDescriptor;
use tauri::Emitter;
use viewmodel::ViewModelGateway;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let runtime = AppRuntime::new();
    runtime.start().expect("application runtime should start");

    let builder = tauri::Builder::default()
        .manage(runtime.clone())
        .manage(PlatformDescriptor::current())
        .manage(ViewModelGateway::new());

    #[cfg(target_os = "android")]
    let builder = builder.manage(AndroidBridgeState::new());

    let run_result = builder
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.handle()
                .emit(EventName::AppLifecycle.as_str(), LifecyclePayload::ready())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![commands::greet])
        .run(tauri::generate_context!());

    runtime.shutdown();
    run_result.expect("error while running tauri application");
}

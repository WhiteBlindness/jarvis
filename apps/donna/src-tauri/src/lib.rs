//! Donna: a desktop client for the JARVIS Core. The Core owns inference,
//! chat storage, policy and approvals; this app only shows them and relays
//! a person's choices over the local RPC.

mod commands;
mod core_proc;
mod error;
mod export;
mod log;
mod loops;
mod paths;
mod state;

use std::sync::Arc;

use tauri::{Manager, RunEvent};

use crate::state::AppState;

pub fn run() {
    let state = Arc::new(AppState::new());
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(Arc::clone(&state))
        .setup(|app| {
            let state = Arc::clone(app.state::<Arc<AppState>>().inner());
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(loops::status_loop(handle.clone(), Arc::clone(&state)));
            tauri::async_runtime::spawn(loops::approvals_loop(handle, Arc::clone(&state)));
            // Failures show up in the status events; nothing to do here.
            tauri::async_runtime::spawn(async move {
                let _ = state.ensure_core().await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::core_connect,
            commands::load_model,
            commands::unload_model,
            commands::set_context_size,
            commands::set_retention,
            commands::export_conversation,
            commands::chat_send,
            commands::chat_regenerate,
            commands::chat_cancel,
            commands::chat_follow,
            commands::list_conversations,
            commands::get_conversation,
            commands::delete_conversation,
            commands::delete_all_conversations,
            commands::list_approvals,
            commands::approve,
            commands::deny,
            commands::submit_copy_proposal,
            commands::get_job,
        ])
        .build(tauri::generate_context!());
    let app = match app {
        Ok(app) => app,
        Err(error) => {
            log::line(&format!("Donna could not start: {error}"));
            eprintln!("Donna could not start: {error}");
            std::process::exit(1);
        }
    };
    app.run(move |_handle, event| {
        if let RunEvent::Exit = event {
            tauri::async_runtime::block_on(state.stop_core());
        }
    });
}

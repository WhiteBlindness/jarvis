// Only the commands listed here exist for the frontend. Each gets an
// `allow-<command>` permission that capabilities/default.json grants.
const COMMANDS: &[&str] = &[
    "app_info",
    "core_connect",
    "load_model",
    "unload_model",
    "set_context_size",
    "set_retention",
    "export_conversation",
    "chat_send",
    "chat_regenerate",
    "chat_cancel",
    "chat_follow",
    "list_conversations",
    "get_conversation",
    "delete_conversation",
    "delete_all_conversations",
    "list_approvals",
    "approve",
    "deny",
    "submit_copy_proposal",
    "get_job",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(error) = tauri_build::try_build(attributes) {
        panic!("tauri build failed: {error:#}");
    }
}

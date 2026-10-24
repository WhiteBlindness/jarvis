//! The commands the frontend may call. Each is a thin, typed wrapper around
//! one RPC request; input is validated here, before anything is sent.

use std::sync::Arc;

use jarvis_protocol::{
    ApprovalId, ApprovalView, CONTEXT_SIZES, ChatLanguage, ChatText, ChatTurn, ClipboardProposal,
    ClipboardText, ConversationId, ConversationSummary, ConversationView, Fingerprint,
    InferenceView, JobId, JobView, MessageId, RETENTION_DAYS, RpcRequest, RpcResponse, SearchQuery,
    Summary, encode_rpc_request, strip_hidden,
};
use serde::Serialize;
use tauri::{AppHandle, State};

use crate::error::DonnaError;
use crate::export;
use crate::loops;
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;
type Reply<T> = Result<T, DonnaError>;

/// Largest request the Core accepts.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

fn parse<T, E: std::fmt::Display>(what: &str, value: Result<T, E>) -> Reply<T> {
    value.map_err(|error| DonnaError::invalid(format!("{what}: {error}")))
}

/// Invisible and control characters are removed first (an emoji with a
/// variation selector must still send); the checks that remain get codes the
/// UI turns into friendly messages.
fn chat_text(raw: &str) -> Reply<ChatText> {
    let cleaned = strip_hidden(raw);
    if cleaned.trim().is_empty() {
        return Err(DonnaError::coded("text_empty", "message is empty"));
    }
    if cleaned.chars().count() > ChatText::MAX_CHARS {
        return Err(DonnaError::coded("text_too_long", "message is too long"));
    }
    ChatText::try_from(cleaned).map_err(|error| DonnaError::coded("text_invalid", error))
}

fn conversation_id(value: String) -> Reply<ConversationId> {
    parse("conversation id", ConversationId::try_from(value))
}

fn language(value: &str) -> Reply<ChatLanguage> {
    match value {
        "pt_pt" => Ok(ChatLanguage::PtPt),
        "en" => Ok(ChatLanguage::En),
        "auto" => Ok(ChatLanguage::Auto),
        _ => Err(DonnaError::invalid("unknown language")),
    }
}

#[derive(Debug, Serialize)]
pub struct AppInfo {
    pub config_path: String,
    pub core_exe: Option<String>,
    pub started_by_app: bool,
    pub app_version: &'static str,
}

#[tauri::command]
pub async fn app_info(state: Shared<'_>) -> Reply<AppInfo> {
    Ok(AppInfo {
        config_path: state.config_path.display().to_string(),
        core_exe: crate::paths::core_exe().map(|path| path.display().to_string()),
        started_by_app: state.child.lock().await.is_some(),
        app_version: env!("CARGO_PKG_VERSION"),
    })
}

/// Connect to the Core, starting it if it is not running. Used for "Retry".
#[tauri::command]
pub async fn core_connect(state: Shared<'_>) -> Reply<()> {
    state.ensure_core().await
}

async fn inference(state: &AppState, request: &RpcRequest) -> Reply<InferenceView> {
    let result = match state.call(request).await? {
        RpcResponse::Inference(view) => Ok(view),
        other => Err(DonnaError::unexpected(&other)),
    };
    state.status_wake.notify_one();
    result
}

#[tauri::command]
pub async fn load_model(state: Shared<'_>) -> Reply<InferenceView> {
    inference(&state, &RpcRequest::LoadModel {}).await
}

#[tauri::command]
pub async fn unload_model(state: Shared<'_>) -> Reply<InferenceView> {
    inference(&state, &RpcRequest::UnloadModel {}).await
}

#[tauri::command]
pub async fn set_context_size(state: Shared<'_>, context_size: u32) -> Reply<InferenceView> {
    if !CONTEXT_SIZES.contains(&context_size) {
        return Err(DonnaError::invalid("unsupported context size"));
    }
    inference(&state, &RpcRequest::SetContextSize { context_size }).await
}

async fn start_turn(state: &Arc<AppState>, request: RpcRequest) -> Reply<ChatTurn> {
    // The frontend starts following with `chat_follow` once it is listening.
    match state.call(&request).await? {
        RpcResponse::ChatTurn(turn) => {
            state.status_wake.notify_one();
            Ok(turn)
        }
        other => Err(DonnaError::unexpected(&other)),
    }
}

#[tauri::command]
pub async fn chat_send(
    state: Shared<'_>,
    conversation_id: Option<String>,
    text: String,
    language: String,
) -> Reply<ChatTurn> {
    let conversation_id = conversation_id.map(self::conversation_id).transpose()?;
    let text = chat_text(&text)?;
    let request = RpcRequest::ChatSend {
        conversation_id,
        text,
        language: self::language(&language)?,
    };
    // The text limit counts characters; the request limit counts bytes.
    let size = parse("message", encode_rpc_request(&request))?.len() + 1;
    if size > MAX_REQUEST_BYTES {
        return Err(DonnaError::coded(
            "request_too_large",
            "message too large for one request",
        ));
    }
    start_turn(&state, request).await
}

#[tauri::command]
pub async fn chat_regenerate(
    state: Shared<'_>,
    conversation_id: String,
    language: String,
) -> Reply<ChatTurn> {
    let request = RpcRequest::ChatRegenerate {
        conversation_id: self::conversation_id(conversation_id)?,
        language: self::language(&language)?,
    };
    start_turn(&state, request).await
}

/// Start following a reply that is already being generated (for example
/// after opening a conversation whose last reply is still streaming).
#[tauri::command]
pub async fn chat_follow(
    app: AppHandle,
    state: Shared<'_>,
    turn_id: String,
    conversation_id: Option<String>,
) -> Reply<()> {
    let turn_id = parse("turn id", MessageId::try_from(turn_id))?;
    loops::follow(app, Arc::clone(&state), turn_id, conversation_id);
    Ok(())
}

#[tauri::command]
pub async fn chat_cancel(state: Shared<'_>, turn_id: String) -> Reply<()> {
    let turn_id = parse("turn id", MessageId::try_from(turn_id))?;
    state.call(&RpcRequest::ChatCancel { turn_id }).await?;
    Ok(())
}

#[tauri::command]
pub async fn list_conversations(
    state: Shared<'_>,
    query: Option<String>,
    limit: u32,
) -> Reply<Vec<ConversationSummary>> {
    let query = query
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .map(|text| parse("search", SearchQuery::try_from(strip_hidden(&text))))
        .transpose()?;
    let request = RpcRequest::ListConversations {
        query,
        limit: limit.clamp(1, 200),
    };
    match state.call(&request).await? {
        RpcResponse::Conversations { conversations } => Ok(conversations),
        other => Err(DonnaError::unexpected(&other)),
    }
}

#[tauri::command]
pub async fn get_conversation(
    state: Shared<'_>,
    conversation_id: String,
) -> Reply<ConversationView> {
    let request = RpcRequest::GetConversation {
        conversation_id: self::conversation_id(conversation_id)?,
    };
    match state.call(&request).await? {
        RpcResponse::Conversation(view) => Ok(view),
        other => Err(DonnaError::unexpected(&other)),
    }
}

#[tauri::command]
pub async fn delete_conversation(state: Shared<'_>, conversation_id: String) -> Reply<()> {
    let request = RpcRequest::DeleteConversation {
        conversation_id: self::conversation_id(conversation_id)?,
    };
    state.call(&request).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_all_conversations(state: Shared<'_>) -> Reply<u32> {
    match state.call(&RpcRequest::DeleteAllConversations {}).await? {
        RpcResponse::Deleted { conversations } => Ok(conversations),
        other => Err(DonnaError::unexpected(&other)),
    }
}

#[tauri::command]
pub async fn list_approvals(state: Shared<'_>) -> Reply<Vec<ApprovalView>> {
    match state
        .call(&RpcRequest::ListApprovals { wait_ms: 0 })
        .await?
    {
        RpcResponse::Approvals { approvals } => Ok(approvals),
        other => Err(DonnaError::unexpected(&other)),
    }
}

/// Approve with the exact fingerprint the person was shown.
#[tauri::command]
pub async fn approve(state: Shared<'_>, approval_id: String, fingerprint: String) -> Reply<()> {
    let request = RpcRequest::Approve {
        approval_id: parse("approval id", ApprovalId::try_from(approval_id))?,
        fingerprint: parse("fingerprint", Fingerprint::try_from(fingerprint))?,
    };
    let result = state.call(&request).await;
    state.approvals_wake.notify_one();
    result.map(|_| ())
}

#[tauri::command]
pub async fn deny(state: Shared<'_>, approval_id: String, reason: String) -> Reply<()> {
    let request = RpcRequest::Deny {
        approval_id: parse("approval id", ApprovalId::try_from(approval_id))?,
        reason: Summary::lossy(reason.trim()),
    };
    let result = state.call(&request).await;
    state.approvals_wake.notify_one();
    result.map(|_| ())
}

/// Submit the model's clipboard proposal as a clipboard job. The Core keeps
/// the text as a temporary payload and never writes it into the job (ADR
/// 0022). The person still has to approve the resulting request.
#[tauri::command]
pub async fn submit_copy_proposal(state: Shared<'_>, text: String) -> Reply<JobView> {
    let proposal = parse("proposal", ClipboardProposal::try_from(text))?;
    let text = parse(
        "proposal",
        ClipboardText::try_from(proposal.as_str().to_owned()),
    )?;
    let result = state.call(&RpcRequest::SubmitClipboardJob { text }).await;
    state.approvals_wake.notify_one();
    match result? {
        RpcResponse::Job(job) => Ok(job),
        other => Err(DonnaError::unexpected(&other)),
    }
}

#[tauri::command]
pub async fn get_job(state: Shared<'_>, job_id: String, wait_ms: u32) -> Reply<JobView> {
    let request = RpcRequest::GetJob {
        job_id: parse("job id", JobId::try_from(job_id))?,
        wait_ms: wait_ms.min(30_000),
    };
    match state.call(&request).await? {
        RpcResponse::Job(job) => Ok(job),
        other => Err(DonnaError::unexpected(&other)),
    }
}

/// Delete conversations not updated for `days` (0 keeps them).
#[tauri::command]
pub async fn set_retention(state: Shared<'_>, days: u32) -> Reply<InferenceView> {
    if !RETENTION_DAYS.contains(&days) {
        return Err(DonnaError::invalid("unsupported retention period"));
    }
    inference(&state, &RpcRequest::SetRetention { days }).await
}

/// Write one conversation as Markdown into the Downloads folder and return
/// the full path. Never overwrites an existing file.
#[tauri::command]
pub async fn export_conversation(
    state: Shared<'_>,
    conversation_id: String,
    lang: Option<String>,
) -> Reply<String> {
    let request = RpcRequest::GetConversation {
        conversation_id: self::conversation_id(conversation_id)?,
    };
    let view = match state.call(&request).await? {
        RpcResponse::Conversation(view) => view,
        other => return Err(DonnaError::unexpected(&other)),
    };
    let english = lang.as_deref() == Some("en");
    let unexpected = |message: String| DonnaError::Unexpected { message };
    let dir = export::downloads_dir().map_err(unexpected)?;
    let path = export::write_unique(&dir, &view, english).map_err(unexpected)?;
    Ok(path.display().to_string())
}

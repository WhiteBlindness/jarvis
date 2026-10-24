// Typed wrappers over the Tauri commands. Outside Tauri (a plain browser
// during development) every call fails with an "unreachable" error, so the
// UI shows its offline state instead of throwing.

import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppInfo,
  ApprovalView,
  ChatLanguage,
  ChatTurn,
  ConversationSummary,
  ConversationView,
  DeltaEvent,
  DonnaError,
  InferenceView,
  JobView,
  StatusEvent,
  StreamErrorEvent,
} from "./types";

export const hasBackend = (): boolean => {
  try {
    return isTauri();
  } catch {
    return false;
  }
};

const NO_BACKEND: DonnaError = {
  kind: "unreachable",
  message: "Tauri API not available (running outside the Donna desktop app).",
};

export function asDonnaError(value: unknown): DonnaError {
  if (value && typeof value === "object" && "kind" in value) return value as DonnaError;
  return { kind: "unexpected", message: typeof value === "string" ? value : String(value) };
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!hasBackend()) throw NO_BACKEND;
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw asDonnaError(error);
  }
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),
  coreConnect: () => call<void>("core_connect"),
  loadModel: () => call<InferenceView>("load_model"),
  unloadModel: () => call<InferenceView>("unload_model"),
  setContextSize: (contextSize: number) =>
    call<InferenceView>("set_context_size", { contextSize }),
  setRetention: (days: number) => call<InferenceView>("set_retention", { days }),
  exportConversation: (conversationId: string, lang: "pt" | "en") =>
    call<string>("export_conversation", { conversationId, lang }),
  chatSend: (conversationId: string | null, text: string, language: ChatLanguage) =>
    call<ChatTurn>("chat_send", { conversationId, text, language }),
  chatRegenerate: (conversationId: string, language: ChatLanguage) =>
    call<ChatTurn>("chat_regenerate", { conversationId, language }),
  chatFollow: (turnId: string, conversationId: string | null) =>
    call<void>("chat_follow", { turnId, conversationId }),
  chatCancel: (turnId: string) => call<void>("chat_cancel", { turnId }),
  listConversations: (query: string | null, limit = 100) =>
    call<ConversationSummary[]>("list_conversations", { query, limit }),
  getConversation: (conversationId: string) =>
    call<ConversationView>("get_conversation", { conversationId }),
  deleteConversation: (conversationId: string) =>
    call<void>("delete_conversation", { conversationId }),
  deleteAllConversations: () => call<number>("delete_all_conversations"),
  listApprovals: () => call<ApprovalView[]>("list_approvals"),
  approve: (approvalId: string, fingerprint: string) =>
    call<void>("approve", { approvalId, fingerprint }),
  deny: (approvalId: string, reason: string) => call<void>("deny", { approvalId, reason }),
  submitCopyProposal: (text: string) => call<JobView>("submit_copy_proposal", { text }),
  getJob: (jobId: string, waitMs = 0) => call<JobView>("get_job", { jobId, waitMs }),
};

export interface Listeners {
  status: (event: StatusEvent) => void;
  approvals: (approvals: ApprovalView[]) => void;
  delta: (event: DeltaEvent) => void;
  streamError: (event: StreamErrorEvent) => void;
}

/** Subscribe to the Rust loops. Returns a function that unsubscribes. */
export async function subscribe(listeners: Listeners): Promise<() => void> {
  if (!hasBackend()) return () => {};
  const unlisten: UnlistenFn[] = await Promise.all([
    listen<StatusEvent>("status", (e) => listeners.status(e.payload)),
    listen<{ approvals: ApprovalView[] }>("approvals", (e) =>
      listeners.approvals(e.payload.approvals),
    ),
    listen<DeltaEvent>("chat-delta", (e) => listeners.delta(e.payload)),
    listen<StreamErrorEvent>("chat-error", (e) => listeners.streamError(e.payload)),
  ]);
  return () => unlisten.forEach((fn) => fn());
}

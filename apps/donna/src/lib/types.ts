// TypeScript mirrors of the RPC v3 views the Tauri commands return.

export type MessageStatus = "streaming" | "complete" | "cancelled" | "failed" | "interrupted";
export type ChatRole = "user" | "assistant";
export type ChatLanguage = "pt_pt" | "en" | "auto";
export type InferenceState =
  | "disabled"
  | "unloaded"
  | "loading"
  | "ready"
  | "generating"
  | "paused_for_game"
  | "failed";

export interface TurnStats {
  prompt_tokens: number;
  completion_tokens: number;
  first_token_ms: number;
  tokens_per_second_x10: number;
}

export interface ChatTurn {
  conversation_id: string;
  user_message_id: string | null;
  turn_id: string;
}

export interface ChatDelta {
  turn_id: string;
  text: string;
  next_cursor: number;
  status: MessageStatus;
  error: string | null;
  stats: TurnStats | null;
  proposal: string | null;
}

export interface ConversationSummary {
  conversation_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  snippet: string | null;
}

export interface MessageView {
  message_id: string;
  role: ChatRole;
  content: string;
  status: MessageStatus;
  created_at: string;
  stats: TurnStats | null;
  proposal: string | null;
}

export interface ConversationView {
  conversation_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  messages: MessageView[];
}

export interface InferenceView {
  state: InferenceState;
  profile: "primary" | "fallback";
  model: string;
  model_sha256: string;
  context_size: number;
  gpu_layers: number;
  last_error: string | null;
  load_ms: number | null;
  last_stats: TurnStats | null;
  /** Conversations older than this many days are deleted; 0 keeps them. */
  retention_days: number;
  /** Speed measured by a short warm-up after each load (tenths of tokens per second). */
  warmup_tokens_per_second_x10: number | null;
  /** A GPU model measured below the configured floor. */
  slow: boolean;
}

export interface GovernorView {
  state: "off" | "open" | "held" | "releasing";
  reason: "starting" | "game" | "detection_failed" | null;
  process: string | null;
  held_ms: number | null;
  overdue: boolean;
}

export interface HealthReport {
  ok: boolean;
  core_version: string;
  rpc_protocol: number;
  uptime_ms: number;
  governor: GovernorView;
  queued_jobs: number;
  pending_approvals: number;
}

export interface ApprovalView {
  approval_id: string;
  status: string;
  task_id: string;
  job_id: string | null;
  request_id: string;
  tool: string;
  capabilities: string[];
  arguments: Record<string, string>;
  fingerprint: string;
  requested_at: string;
  expires_at: string;
  expires_in_ms: number;
}

export interface JobView {
  job_id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
  goal: string;
  summary: string | null;
  submitted_at: string;
  updated_at: string;
}

export type CoreStatus =
  | "ok"
  | "starting"
  | "unreachable"
  | "version_mismatch"
  | "config_error"
  | "launch_failed";

export interface StatusEvent {
  core: CoreStatus;
  error: DonnaError | null;
  health: HealthReport | null;
  inference: InferenceView | null;
  inference_error: string | null;
}

export interface DeltaEvent {
  turn_id: string;
  conversation_id: string | null;
  from_cursor: number;
  delta: ChatDelta;
}

export type DonnaError =
  | { kind: "unreachable"; message: string }
  | { kind: "version_mismatch"; found: number; expected: number }
  | { kind: "timeout"; message: string }
  | { kind: "rpc"; code: string; message: string }
  | { kind: "invalid_input"; code: string; message: string }
  | { kind: "config"; message: string; path: string }
  | { kind: "launch"; message: string }
  | { kind: "unexpected"; message: string };

export interface StreamErrorEvent {
  turn_id: string;
  conversation_id: string | null;
  error: DonnaError;
}

export interface AppInfo {
  config_path: string;
  core_exe: string | null;
  started_by_app: boolean;
  app_version: string;
}

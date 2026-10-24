// Application state and actions. The Core owns the truth (conversations,
// approvals, model state); this store only mirrors what the Tauri events and
// commands report.

import { useEffect, useState } from "preact/hooks";
import { api, asDonnaError, hasBackend, subscribe } from "./api";
import { type LangSetting, type StringKey, type UiLang, resolveLang, translate } from "./i18n";
import type {
  ApprovalView,
  ChatLanguage,
  ConversationSummary,
  DeltaEvent,
  DonnaError,
  HealthReport,
  InferenceView,
  MessageView,
  StatusEvent,
  StreamErrorEvent,
} from "./types";

export type CoreView = "connecting" | StatusEvent["core"];

export interface PendingApproval {
  view: ApprovalView;
  /** Local clock time (ms) when the approval expires. */
  deadline: number;
}

export type ProposalPhase = "submitting" | "waiting" | "done" | "failed" | "cancelled" | "error";
export interface ProposalState {
  phase: ProposalPhase;
  jobId?: string;
}

export interface Toast {
  id: number;
  text: string;
  tone: "info" | "error";
}

export interface State {
  setting: LangSetting;
  lang: UiLang;
  core: CoreView;
  coreError: DonnaError | null;
  health: HealthReport | null;
  inference: InferenceView | null;
  inferenceError: string | null;
  approvals: PendingApproval[];
  conversations: ConversationSummary[];
  search: string;
  activeId: string | null;
  messages: MessageView[];
  loadingConversation: boolean;
  streaming: { turnId: string; text: string } | null;
  sending: boolean;
  view: "chat" | "settings";
  drawer: boolean;
  modelPanel: boolean;
  sidebar: boolean;
  proposals: Record<string, ProposalState>;
  toasts: Toast[];
  announcement: string;
  contextError: string | null;
  /** The composer text; kept here so it survives screen changes. */
  draft: string;
}

const SETTINGS_KEY = "donna.settings";
const PROPOSALS_KEY = "donna.proposals";

function readJson<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function writeJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage may be unavailable; the app works without it.
  }
}

const systemLanguage = (): string =>
  typeof navigator === "undefined" ? "pt-PT" : navigator.language || "pt-PT";

function initialSetting(): LangSetting {
  const saved = readJson<{ language?: string }>(SETTINGS_KEY)?.language;
  return saved === "en" || saved === "auto" || saved === "pt_pt" ? saved : "pt_pt";
}

function initialState(): State {
  const setting = initialSetting();
  return {
    setting,
    lang: resolveLang(setting, systemLanguage()),
    core: "connecting",
    coreError: null,
    health: null,
    inference: null,
    inferenceError: null,
    approvals: [],
    conversations: [],
    search: "",
    activeId: null,
    messages: [],
    loadingConversation: false,
    streaming: null,
    sending: false,
    view: "chat",
    drawer: false,
    modelPanel: false,
    sidebar: true,
    proposals: {},
    toasts: [],
    announcement: "",
    contextError: null,
    draft: "",
  };
}

let state: State = initialState();
const listeners = new Set<() => void>();

export function getState(): State {
  return state;
}

export function setState(patch: Partial<State> | ((s: State) => Partial<State>)): void {
  const next = typeof patch === "function" ? patch(state) : patch;
  state = { ...state, ...next };
  listeners.forEach((listener) => listener());
}

export function useStore(): State {
  const [, force] = useState(0);
  useEffect(() => {
    const listener = () => force((n) => n + 1);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);
  return state;
}

export const t = (key: StringKey, vars?: Record<string, string | number>): string =>
  translate(state.lang, key, vars);

/** Language the assistant is asked to answer in. */
const chatLanguage = (): ChatLanguage => state.setting;

// ---- toasts ---------------------------------------------------------------

let toastId = 0;
export function toast(text: string, tone: Toast["tone"] = "info"): void {
  const id = (toastId += 1);
  setState((s) => ({ toasts: [...s.toasts, { id, text, tone }] }));
  setTimeout(() => dismissToast(id), tone === "error" ? 8000 : 4000);
}

export function dismissToast(id: number): void {
  setState((s) => ({ toasts: s.toasts.filter((item) => item.id !== id) }));
}

export function errorText(error: unknown): string {
  const e = asDonnaError(error);
  switch (e.kind) {
    case "invalid_input":
      switch (e.code) {
        case "text_too_long":
        case "request_too_large":
          return t("tooLong");
        case "text_empty":
          return t("emptyMessage");
        case "text_invalid":
          return t("invalidText");
        default:
          return t("genericError");
      }
    case "rpc":
    case "unreachable":
    case "timeout":
    case "launch":
    case "unexpected":
    case "config":
      return e.message;
    case "version_mismatch":
      return t("coreVersionBody", { found: e.found, expected: e.expected });
  }
}

// ---- settings -------------------------------------------------------------

export function setLanguage(setting: LangSetting): void {
  writeJson(SETTINGS_KEY, { language: setting });
  const lang = resolveLang(setting, systemLanguage());
  document.documentElement.lang = lang === "pt" ? "pt-PT" : "en";
  setState({ setting, lang });
}

export async function setContextSize(size: number): Promise<void> {
  setState({ contextError: null });
  try {
    const inference = await api.setContextSize(size);
    setState({ inference });
    toast(t("contextChanged"));
  } catch (error) {
    // Shown inline: the Core refuses (conflict) while loading or generating.
    setState({ contextError: `${t("contextFailed")} ${errorText(error)}` });
  }
}

export async function loadModel(): Promise<void> {
  // Optimistic: show "loading" at once; the Core's answer or the next status
  // event replaces it, and a failure puts the previous state back.
  const previous = state.inference;
  if (previous) setState({ inference: { ...previous, state: "loading", last_error: null } });
  try {
    setState({ inference: await api.loadModel() });
  } catch (error) {
    setState({ inference: previous });
    toast(errorText(error), "error");
  }
}

/** Unload, then load again (frees video memory that other programs held). */
export async function reloadModel(): Promise<void> {
  try {
    setState({ inference: await api.unloadModel() });
  } catch (error) {
    toast(errorText(error), "error");
    return;
  }
  await loadModel();
}

export async function setRetention(days: number): Promise<void> {
  try {
    setState({ inference: await api.setRetention(days) });
    toast(t("retentionChanged"));
    void refreshConversations();
  } catch (error) {
    toast(`${t("retentionFailed")} ${errorText(error)}`, "error");
  }
}

export async function exportConversation(id: string): Promise<void> {
  try {
    const path = await api.exportConversation(id, state.lang);
    toast(t("exportDone", { path }));
  } catch (error) {
    toast(`${t("exportFailed")} ${errorText(error)}`, "error");
  }
}

export async function unloadModel(): Promise<void> {
  try {
    setState({ inference: await api.unloadModel() });
  } catch (error) {
    toast(errorText(error), "error");
  }
}

// ---- conversations --------------------------------------------------------

let searchTimer: ReturnType<typeof setTimeout> | undefined;

export async function refreshConversations(): Promise<void> {
  const query = state.search.trim();
  try {
    const conversations = await api.listConversations(query === "" ? null : query);
    setState({ conversations });
  } catch (error) {
    // An unreachable Core is already explained by its own screen.
    if (state.core === "ok") toast(errorText(error), "error");
  }
}

export function setSearch(search: string): void {
  setState({ search });
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => void refreshConversations(), 180);
}

export function newConversation(): void {
  if (state.streaming || state.sending) return;
  setState({ activeId: null, messages: [], view: "chat" });
  document.getElementById("composer")?.focus();
}

export async function openConversation(id: string): Promise<void> {
  if (state.sending || (state.streaming && state.activeId !== id)) return;
  const previous = { activeId: state.activeId, messages: state.messages };
  setState({
    view: "chat",
    activeId: id,
    messages: id === previous.activeId ? state.messages : [],
    loadingConversation: true,
  });
  try {
    const conversation = await api.getConversation(id);
    if (state.activeId !== id) return; // a newer open owns the loading flag
    setState({ messages: conversation.messages, loadingConversation: false });
    resumeProposals(conversation.messages);
    const last = conversation.messages[conversation.messages.length - 1];
    if (last && last.role === "assistant" && last.status === "streaming" && !state.streaming) {
      setState({ streaming: { turnId: last.message_id, text: "" } });
      await api.chatFollow(last.message_id, id);
    }
  } catch (error) {
    if (state.activeId === id) {
      setState({ loadingConversation: false, ...previous });
    }
    toast(`${t("conversationLoadFailed")} ${errorText(error)}`, "error");
  }
}

export async function deleteConversation(id: string): Promise<void> {
  try {
    await api.deleteConversation(id);
    if (state.activeId === id) setState({ activeId: null, messages: [], streaming: null });
    await refreshConversations();
  } catch (error) {
    toast(errorText(error), "error");
  }
}

export async function deleteAllConversations(): Promise<void> {
  try {
    const n = await api.deleteAllConversations();
    setState({ activeId: null, messages: [], streaming: null, conversations: [] });
    toast(t("deleteAllDone", { n }));
  } catch (error) {
    toast(`${t("deleteAllFailed")} ${errorText(error)}`, "error");
  }
}

// ---- chat -----------------------------------------------------------------

const localId = (): string => `local-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

/** Bumped whenever the user starts a turn; late reloads of an older state are dropped. */
let turnEpoch = 0;

export async function sendMessage(text: string): Promise<boolean> {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (state.streaming || state.sending) {
    // Never swallow input: the caller keeps the draft and the person is told why.
    toast(t("chatBusy"), "error");
    return false;
  }
  turnEpoch += 1;
  setState({ sending: true });
  const userMessage: MessageView = {
    message_id: localId(),
    role: "user",
    content: trimmed,
    status: "complete",
    created_at: new Date().toISOString(),
    stats: null,
    proposal: null,
  };
  const before = state.messages;
  setState({ messages: [...before, userMessage] });
  try {
    const turn = await api.chatSend(state.activeId, trimmed, chatLanguage());
    setState({
      activeId: turn.conversation_id,
      sending: false,
      streaming: { turnId: turn.turn_id, text: "" },
    });
    follow(turn.turn_id, turn.conversation_id);
    void refreshConversations();
    return true;
  } catch (error) {
    setState({ sending: false, messages: before });
    const e = asDonnaError(error);
    toast(
      e.kind === "rpc" && e.code === "conflict" ? t("chatBusy") : `${t("sendFailed")} ${errorText(e)}`,
      "error",
    );
    return false;
  }
}

/** Start the Rust polling task only after the stream state exists to receive it. */
function follow(turnId: string, conversationId: string): void {
  api.chatFollow(turnId, conversationId).catch((error: unknown) => {
    if (state.streaming?.turnId !== turnId) return;
    void finishTurn(conversationId, {
      text: state.streaming.text,
      delta: null,
      error: errorText(error),
    });
  });
}

export async function regenerate(): Promise<void> {
  const id = state.activeId;
  if (!id || state.streaming || state.sending) return;
  turnEpoch += 1;
  setState({ sending: true });
  try {
    const turn = await api.chatRegenerate(id, chatLanguage());
    if (state.activeId !== id) {
      setState({ sending: false });
      return;
    }
    // The last reply is replaced; show it empty until the new text arrives.
    const messages = [...state.messages];
    const last = messages[messages.length - 1];
    if (last && last.role === "assistant") messages.pop();
    setState({ messages, sending: false, streaming: { turnId: turn.turn_id, text: "" } });
    follow(turn.turn_id, turn.conversation_id);
  } catch (error) {
    setState({ sending: false });
    toast(errorText(error), "error");
  }
}

export async function stopGenerating(): Promise<void> {
  const streaming = state.streaming;
  if (!streaming) return;
  try {
    await api.chatCancel(streaming.turnId);
  } catch (error) {
    toast(errorText(error), "error");
  }
}

/**
 * The reply is final: keep its text on screen at once (no flicker) and free
 * the composer, then reconcile with the stored conversation in the
 * background. The reconcile is dropped if the person has already moved on.
 */
async function finishTurn(
  conversationId: string | null,
  final: { text: string; delta: DeltaEvent["delta"] | null; error?: string },
): Promise<void> {
  const id = conversationId ?? state.activeId;
  const streaming = state.streaming;
  if (final.error) toast(final.error, "error");
  if (streaming) {
    const reply: MessageView = {
      message_id: streaming.turnId,
      role: "assistant",
      content: final.text,
      status: final.delta?.status ?? "failed",
      created_at: new Date().toISOString(),
      stats: final.delta?.stats ?? null,
      proposal: final.delta?.proposal ?? null,
    };
    const rest = state.messages.filter((m) => m.message_id !== streaming.turnId);
    setState({ streaming: null, messages: [...rest, reply] });
    resumeProposals([reply]);
  } else {
    setState({ streaming: null });
  }
  setState({ announcement: t("doneAnnouncement") });
  const epoch = turnEpoch;
  if (id && state.activeId === id) {
    try {
      const conversation = await api.getConversation(id);
      if (epoch === turnEpoch && state.activeId === id && !state.streaming && !state.sending) {
        setState({ messages: conversation.messages });
        resumeProposals(conversation.messages);
      }
    } catch {
      // Keep what is on screen.
    }
  }
  void refreshConversations();
}

function onDelta(event: DeltaEvent): void {
  const streaming = state.streaming;
  if (!streaming || streaming.turnId !== event.turn_id) return;
  const text = event.from_cursor === 0 ? event.delta.text : streaming.text + event.delta.text;
  if (event.delta.status !== "streaming") {
    void finishTurn(event.conversation_id, {
      text,
      delta: event.delta,
      error: event.delta.error ?? undefined,
    });
    return;
  }
  setState({ streaming: { turnId: streaming.turnId, text } });
}

function onStreamError(event: StreamErrorEvent): void {
  if (state.streaming?.turnId !== event.turn_id) return;
  void finishTurn(event.conversation_id, {
    text: state.streaming.text,
    delta: null,
    error: errorText(event.error),
  });
}

// ---- approvals & proposals --------------------------------------------------

function onApprovals(views: ApprovalView[]): void {
  const now = Date.now();
  setState({
    approvals: views.map((view) => ({ view, deadline: now + view.expires_in_ms })),
  });
}

export async function approve(view: ApprovalView): Promise<void> {
  try {
    // The fingerprint is the one in the view the person reviewed.
    await api.approve(view.approval_id, view.fingerprint);
  } catch (error) {
    toast(`${t("approvalFailed")} ${errorText(error)}`, "error");
  }
  await refreshApprovals();
}

export async function deny(view: ApprovalView, reason: string): Promise<void> {
  try {
    await api.deny(view.approval_id, reason);
  } catch (error) {
    toast(`${t("approvalFailed")} ${errorText(error)}`, "error");
  }
  await refreshApprovals();
}

async function refreshApprovals(): Promise<void> {
  try {
    onApprovals(await api.listApprovals());
  } catch {
    // Leave the list as it is.
  }
}

const tracked = new Set<string>();

function saveProposals(): void {
  // Merge into what is stored: other conversations' entries must survive.
  const jobs: Record<string, string> = { ...(readJson<Record<string, string>>(PROPOSALS_KEY) ?? {}) };
  for (const [id, proposal] of Object.entries(state.proposals)) {
    if (proposal.jobId) jobs[id] = proposal.jobId;
  }
  writeJson(PROPOSALS_KEY, jobs);
}

function setProposal(messageId: string, proposal: ProposalState): void {
  setState((s) => ({ proposals: { ...s.proposals, [messageId]: proposal } }));
  saveProposals();
}

async function trackJob(messageId: string, jobId: string): Promise<void> {
  if (tracked.has(jobId)) return;
  tracked.add(jobId);
  let failures = 0;
  try {
    for (;;) {
      let job;
      try {
        job = await api.getJob(jobId, 25_000);
        failures = 0;
      } catch {
        failures += 1;
        if (failures > 8) return; // the card keeps its last state
        await new Promise((resolve) => setTimeout(resolve, Math.min(30_000, 1000 * 2 ** failures)));
        continue;
      }
      if (job.status === "completed") return setProposal(messageId, { phase: "done", jobId });
      if (job.status === "failed") return setProposal(messageId, { phase: "failed", jobId });
      if (job.status === "cancelled" || job.status === "interrupted") {
        return setProposal(messageId, { phase: "cancelled", jobId });
      }
      setProposal(messageId, { phase: "waiting", jobId });
    }
  } finally {
    tracked.delete(jobId);
  }
}

/** Pick up proposals submitted earlier (the job ids are kept locally). */
function resumeProposals(messages: MessageView[]): void {
  const saved = readJson<Record<string, string>>(PROPOSALS_KEY) ?? {};
  for (const message of messages) {
    const jobId = saved[message.message_id];
    if (message.proposal && jobId && !state.proposals[message.message_id]) {
      setProposal(message.message_id, { phase: "waiting", jobId });
      void trackJob(message.message_id, jobId);
    }
  }
}

export async function submitProposal(messageId: string, text: string): Promise<void> {
  if (state.proposals[messageId]) return;
  setProposal(messageId, { phase: "submitting" });
  try {
    const job = await api.submitCopyProposal(text);
    setProposal(messageId, { phase: "waiting", jobId: job.job_id });
    setState({ drawer: true });
    void trackJob(messageId, job.job_id);
  } catch (error) {
    setState((s) => {
      const proposals = { ...s.proposals };
      delete proposals[messageId];
      return { proposals };
    });
    toast(`${t("proposalError")} ${errorText(error)}`, "error");
  }
}

// ---- core connection --------------------------------------------------------

let failStreak = 0;

function onStatus(event: StatusEvent): void {
  const wasOk = state.core === "ok";
  // One failed poll is not an outage: wait for a second before leaving "ok".
  failStreak = event.core === "ok" ? 0 : failStreak + 1;
  if (wasOk && event.core !== "ok" && failStreak < 2) return;
  setState({
    core: event.core,
    coreError: event.error,
    health: event.health ?? (event.core === "ok" ? state.health : null),
    inference: event.inference ?? (event.core === "ok" ? state.inference : null),
    inferenceError: event.inference_error,
  });
  if (event.core === "ok" && !wasOk) {
    void refreshConversations();
    void refreshApprovals();
  }
}

export async function retryCore(): Promise<void> {
  setState({ core: "connecting", coreError: null });
  try {
    await api.coreConnect();
  } catch (error) {
    const e = asDonnaError(error);
    setState({ core: e.kind === "unreachable" ? "unreachable" : "launch_failed", coreError: e });
  }
}

let started = false;

/** Subscribe to the Rust loops once. */
export async function start(): Promise<void> {
  if (started) return;
  started = true;
  document.documentElement.lang = state.lang === "pt" ? "pt-PT" : "en";
  if (!hasBackend()) {
    setState({
      core: "unreachable",
      coreError: {
        kind: "unreachable",
        message: "Tauri API not available (running outside the Donna desktop app).",
      },
    });
    return;
  }
  await subscribe({
    status: onStatus,
    approvals: onApprovals,
    delta: onDelta,
    streamError: onStreamError,
  });
}

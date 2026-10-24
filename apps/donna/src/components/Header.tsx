import { useEffect, useRef } from "preact/hooks";
import type { StringKey } from "../lib/i18n";
import { loadModel, reloadModel, setState, t, unloadModel, useStore } from "../lib/store";
import type { InferenceView } from "../lib/types";
import { BellIcon, CloseIcon, GearIcon, SidebarIcon } from "./Icons";

type Tone = "ok" | "busy" | "paused" | "idle" | "error";

interface PillInfo {
  label: string;
  tone: Tone;
}

function pillInfo(inference: InferenceView | null): PillInfo {
  if (!inference) return { label: t("stateUnknown"), tone: "idle" };
  const map: Record<InferenceView["state"], [StringKey, Tone]> = {
    ready: ["stateReady", "ok"],
    loading: ["stateLoading", "busy"],
    generating: ["stateGenerating", "busy"],
    paused_for_game: ["statePaused", "paused"],
    unloaded: ["stateUnloaded", "idle"],
    failed: ["stateFailed", "error"],
    disabled: ["stateDisabled", "idle"],
  };
  const [key, tone] = map[inference.state];
  // A slow-but-working model gets the amber dot.
  return { label: t(key), tone: tone === "ok" && inference.slow ? "paused" : tone };
}

const tokensPerSecond = (x10: number): string => (x10 / 10).toFixed(1);

export function Header() {
  const s = useStore();
  const info = pillInfo(s.inference);
  const gpu =
    s.inference && s.inference.state !== "disabled"
      ? s.inference.gpu_layers > 0
        ? t("gpuOn")
        : t("cpuOnly")
      : null;
  const pending = s.approvals.length;
  // Speed and first-token time live in the model panel; the pill stays short.
  const detail =
    s.inference && s.inference.state !== "disabled"
      ? [s.inference.model, gpu, t("contextSize", { n: s.inference.context_size })]
          .filter(Boolean)
          .join(" · ")
      : "";

  return (
    <header class="topbar">
      <button
        type="button"
        class="icon-btn sidebar-toggle"
        aria-label={t("collapseSidebar")}
        aria-pressed={s.sidebar}
        onClick={() => setState({ sidebar: !s.sidebar })}
      >
        <SidebarIcon />
      </button>
      <div class="pill-wrap">
        <button
          type="button"
          class="pill"
          data-tone={info.tone}
          aria-expanded={s.modelPanel}
          aria-haspopup="dialog"
          aria-label={`${t("modelStatus")}: ${info.label}`}
          onClick={() => setState({ modelPanel: !s.modelPanel })}
        >
          <span class="dot" aria-hidden="true" />
          <span class="pill-state">{info.label}</span>
          {detail && (
            <span class="pill-detail" title={detail}>
              {detail}
            </span>
          )}
        </button>
        {s.modelPanel && <ModelPanel />}
      </div>
      <div class="topbar-actions">
        <button
          type="button"
          class="icon-btn bell"
          aria-label={pending > 0 ? t("approvalsButtonCount", { n: pending }) : t("approvalsButton")}
          onClick={() => setState({ drawer: true })}
        >
          <BellIcon />
          {pending > 0 && <span class="badge">{pending}</span>}
        </button>
        <button
          type="button"
          class="icon-btn"
          aria-label={`${t("settings")} (Ctrl+,)`}
          aria-pressed={s.view === "settings"}
          onClick={() => setState({ view: s.view === "settings" ? "chat" : "settings" })}
        >
          <GearIcon />
        </button>
      </div>
    </header>
  );
}

function ModelPanel() {
  const s = useStore();
  const ref = useRef<HTMLDivElement>(null);
  const inference = s.inference;

  useEffect(() => {
    const close = () => setState({ modelPanel: false });
    const onDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (ref.current?.contains(target)) return;
      if ((target as Element).closest?.(".pill")) return;
      close();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        close();
        (document.querySelector(".pill") as HTMLElement | null)?.focus();
      }
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey, true);
    };
  }, []);

  const canLoad = inference && (inference.state === "unloaded" || inference.state === "failed");
  const canUnload =
    inference && (inference.state === "ready" || inference.state === "generating");
  const stats = inference?.last_stats ?? null;

  return (
    <div class="popover" role="dialog" aria-label={t("modelPanelTitle")} ref={ref}>
      <div class="popover-head">
        <h2>{t("modelPanelTitle")}</h2>
        <button
          type="button"
          class="icon-btn"
          aria-label={t("close")}
          onClick={() => setState({ modelPanel: false })}
        >
          <CloseIcon />
        </button>
      </div>
      {!inference ? (
        <p class="muted">{s.inferenceError ?? t("stateUnknown")}</p>
      ) : (
        <>
          <ModelNotice inference={inference} />
          <dl class="facts">
            <dt>{t("modelName")}</dt>
            <dd>{inference.model}</dd>
            <dt>{t("modelProfile")}</dt>
            <dd>{inference.profile === "primary" ? t("profilePrimary") : t("profileFallback")}</dd>
            <dt>{t("contextHeading")}</dt>
            <dd>{t("contextTokens", { n: inference.context_size })}</dd>
            <dt>GPU</dt>
            <dd>{inference.gpu_layers > 0 ? t("gpuOn") : t("cpuOnly")}</dd>
            {stats && (
              <>
                <dt>tok/s</dt>
                <dd>
                  {t("statsLine", {
                    tps: tokensPerSecond(stats.tokens_per_second_x10),
                    ms: stats.first_token_ms,
                  })}
                </dd>
              </>
            )}
            {inference.warmup_tokens_per_second_x10 !== null && (
              <>
                <dt>{t("warmupSpeed")}</dt>
                <dd>
                  {t("tokensPerSecond", {
                    n: tokensPerSecond(inference.warmup_tokens_per_second_x10),
                  })}
                </dd>
              </>
            )}
            {inference.load_ms !== null && (
              <>
                <dt>{t("modelLoadTime")}</dt>
                <dd>{t("loadSeconds", { n: (inference.load_ms / 1000).toFixed(1) })}</dd>
              </>
            )}
            <dt>{t("modelSha")}</dt>
            <dd class="mono sha">{inference.model_sha256}</dd>
          </dl>
          <div class="actions">
            <button type="button" class="btn btn-primary" disabled={!canLoad} onClick={() => void loadModel()}>
              {t("loadModel")}
            </button>
            <button type="button" class="btn" disabled={!canUnload} onClick={() => void unloadModel()}>
              {t("unloadModel")}
            </button>
          </div>
          <p class="muted small">{t("unloadHint")}</p>
        </>
      )}
    </div>
  );
}

/** Explains the model states that stop Donna from answering. */
export function ModelNotice({ inference }: { inference: InferenceView }) {
  const s = useStore();
  const game = s.health?.governor.process ?? null;
  if (inference.slow && (inference.state === "ready" || inference.state === "generating")) {
    const tps = tokensPerSecond(inference.warmup_tokens_per_second_x10 ?? 0);
    return (
      <div class="notice notice-paused" role="status">
        <strong>{t("slowTitle")}</strong>
        <p>{t("slowBody", { tps })}</p>
        <div class="actions">
          <button type="button" class="btn" onClick={() => void reloadModel()}>
            {t("reloadModel")}
          </button>
        </div>
      </div>
    );
  }
  switch (inference.state) {
    case "failed":
      return (
        <div class="notice notice-error" role="alert">
          <strong>{t("modelFailedTitle")}</strong>
          <p>{t("modelFailedBody")}</p>
          {inference.last_error && (
            <p class="mono small">
              <span class="muted">{t("lastError")}: </span>
              {inference.last_error}
            </p>
          )}
        </div>
      );
    case "paused_for_game":
      return (
        <div class="notice notice-paused" role="status">
          <strong>{t("pausedTitle")}</strong>
          <p>{game ? t("pausedBodyProcess", { process: game }) : t("pausedBody")}</p>
        </div>
      );
    case "loading":
      return (
        <div class="notice" role="status">
          <p>{t("loadingBody")}</p>
        </div>
      );
    case "disabled":
      return (
        <div class="notice">
          <p>{t("modelDisabledBody")}</p>
        </div>
      );
    default:
      return null;
  }
}

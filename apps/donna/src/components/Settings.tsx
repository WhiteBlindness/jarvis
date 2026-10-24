import { useEffect, useState } from "preact/hooks";
import { api } from "../lib/api";
import type { LangSetting } from "../lib/i18n";
import {
  deleteAllConversations,
  deleteConversation,
  exportConversation,
  setContextSize,
  setRetention,
  setLanguage,
  setState,
  t,
  useStore,
} from "../lib/store";
import { Dialog } from "./Dialog";
import { ArrowLeftIcon, TrashIcon } from "./Icons";
import { countAffected, needsConfirmation } from "../lib/retention";
import type { ConversationSummary } from "../lib/types";

const CONTEXT_SIZES = [4096, 8192, 16384, 32768];
const RETENTION_DAYS = [0, 7, 30, 90, 365];

export function Settings() {
  const s = useStore();
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const [pending, setPending] = useState<ConversationSummary | null>(null);
  const [retentionPrompt, setRetentionPrompt] = useState<{ days: number; count: number } | null>(null);

  // A shorter period deletes at once: count what would go and ask first.
  const chooseRetention = async (days: number) => {
    const current = s.inference?.retention_days ?? 0;
    if (!needsConfirmation(current, days)) return void setRetention(days);
    try {
      const all = await api.listConversations(null, 200);
      setRetentionPrompt({ days, count: countAffected(all, days) });
    } catch {
      // Without a count the change is not applied silently.
      setRetentionPrompt({ days, count: countAffected(s.conversations, days) });
    }
  };
  const [appVersion, setAppVersion] = useState("—");
  useEffect(() => {
    api
      .appInfo()
      .then((info) => setAppVersion(info.app_version))
      .catch(() => {});
  }, []);
  const word = t("deleteAllWord");
  const languages: [LangSetting, string][] = [
    ["pt_pt", t("langPt")],
    ["en", t("langEn")],
    ["auto", t("langAuto")],
  ];

  return (
    <section class="settings" aria-labelledby="settings-title">
      <div class="settings-inner">
        <header class="settings-head">
          <button
            type="button"
            class="icon-btn"
            aria-label={t("close")}
            onClick={() => setState({ view: "chat" })}
          >
            <ArrowLeftIcon />
          </button>
          <h1 id="settings-title" class="display">
            {t("settingsTitle")}
          </h1>
        </header>

        <section class="card">
          <h2>{t("languageHeading")}</h2>
          <p class="muted">{t("languageHelp")}</p>
          <div class="segmented" role="radiogroup" aria-label={t("languageHeading")}>
            {languages.map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={s.setting === value}
                onClick={() => setLanguage(value)}
              >
                {label}
              </button>
            ))}
          </div>
        </section>

        <section class="card">
          <h2>{t("contextHeading")}</h2>
          <p class="muted">{t("contextHelp")}</p>
          <div class="segmented" role="radiogroup" aria-label={t("contextHeading")}>
            {CONTEXT_SIZES.map((size) => (
              <button
                key={size}
                type="button"
                role="radio"
                aria-checked={s.inference?.context_size === size}
                disabled={!s.inference || s.inference.state === "disabled" || s.core !== "ok"}
                onClick={() => void setContextSize(size)}
              >
                {size.toLocaleString(s.lang === "pt" ? "pt-PT" : "en-GB")}
              </button>
            ))}
          </div>
          {s.contextError && (
            <p class="inline-error" role="alert">
              {s.contextError}
            </p>
          )}
        </section>

        <section class="card">
          <h2>{t("storageHeading")}</h2>
          <p>{t("storageBody")}</p>
          <h3 class="label">{t("retentionHeading")}</h3>
          <p class="muted">{t("retentionHelp")}</p>
          <div class="segmented" role="radiogroup" aria-label={t("retentionHeading")}>
            {RETENTION_DAYS.map((days) => (
              <button
                key={days}
                type="button"
                role="radio"
                aria-checked={s.inference?.retention_days === days}
                disabled={!s.inference || s.core !== "ok"}
                onClick={() => void chooseRetention(days)}
              >
                {days === 0 ? t("retentionKeep") : t("retentionDays", { n: days })}
              </button>
            ))}
          </div>
        </section>

        <section class="card">
          <h2>{t("conversationsHeading")}</h2>
          {s.conversations.length === 0 ? (
            <p class="muted">{t("conversationsEmpty")}</p>
          ) : (
            <ul class="conv-admin">
              {s.conversations.map((c) => (
                <li key={c.conversation_id}>
                  <span class="conv-admin-title">{c.title.trim() || t("untitled")}</span>
                  <button
                    type="button"
                    class="btn btn-ghost"
                    disabled={s.core !== "ok"}
                    onClick={() => void exportConversation(c.conversation_id)}
                  >
                    {t("exportConversation")}
                  </button>
                  <button
                    type="button"
                    class="icon-btn"
                    aria-label={`${t("deleteConversation")}: ${c.title.trim() || t("untitled")}`}
                    onClick={() => setPending(c)}
                  >
                    <TrashIcon />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section class="card">
          <h2>{t("clipboardHeading")}</h2>
          <p>{t("clipboardBody")}</p>
        </section>

        <section class="card card-danger">
          <h2>{t("dangerHeading")}</h2>
          <button
            type="button"
            class="btn btn-danger"
            disabled={s.core !== "ok"}
            onClick={() => {
              setTyped("");
              setConfirming(true);
            }}
          >
            {t("deleteAll")}
          </button>
        </section>

        <p class="muted small about">
          {t("aboutVersion", { app: appVersion, core: s.health?.core_version ?? "—" })}
        </p>
      </div>

      <Dialog
        open={retentionPrompt !== null}
        onClose={() => setRetentionPrompt(null)}
        label={t("retentionConfirmTitle")}
      >
        {retentionPrompt && (
          <div class="confirm">
            <h2>{t("retentionConfirmTitle")}</h2>
            <p>
              {retentionPrompt.count === 0
                ? t("retentionConfirmZero", { days: retentionPrompt.days })
                : t(retentionPrompt.count === 1 ? "retentionConfirmOne" : "retentionConfirmMany", {
                    n: retentionPrompt.count,
                    days: retentionPrompt.days,
                  })}
            </p>
            <div class="actions">
              <button type="button" class="btn" onClick={() => setRetentionPrompt(null)}>
                {t("cancel")}
              </button>
              <button
                type="button"
                class="btn btn-primary"
                onClick={() => {
                  const days = retentionPrompt.days;
                  setRetentionPrompt(null);
                  void setRetention(days);
                }}
              >
                {t("continueAction")}
              </button>
            </div>
          </div>
        )}
      </Dialog>

      <Dialog open={pending !== null} onClose={() => setPending(null)} label={t("deleteConversationTitle")}>
        {pending && (
          <div class="confirm">
            <h2>{t("deleteConversationTitle")}</h2>
            <p>{t("deleteConversationBody", { title: pending.title.trim() || t("untitled") })}</p>
            <div class="actions">
              <button type="button" class="btn" onClick={() => setPending(null)}>
                {t("cancel")}
              </button>
              <button
                type="button"
                class="btn btn-danger"
                onClick={() => {
                  const id = pending.conversation_id;
                  setPending(null);
                  void deleteConversation(id);
                }}
              >
                {t("delete")}
              </button>
            </div>
          </div>
        )}
      </Dialog>

      <Dialog open={confirming} onClose={() => setConfirming(false)} label={t("deleteAllTitle")}>
        <form
          class="confirm"
          onSubmit={(event) => {
            event.preventDefault();
            if (typed.trim() !== word) return;
            setConfirming(false);
            void deleteAllConversations();
          }}
        >
          <h2>{t("deleteAllTitle")}</h2>
          <p>{t("deleteAllBody")}</p>
          <label class="label" for="confirm-word">
            {t("deleteAllType", { word })}
          </label>
          <input
            id="confirm-word"
            type="text"
            autocomplete="off"
            spellcheck={false}
            value={typed}
            autoFocus
            onInput={(event) => setTyped(event.currentTarget.value)}
          />
          <div class="actions">
            <button type="button" class="btn" onClick={() => setConfirming(false)}>
              {t("cancel")}
            </button>
            <button type="submit" class="btn btn-danger" disabled={typed.trim() !== word}>
              {t("deleteAll")}
            </button>
          </div>
        </form>
      </Dialog>
    </section>
  );
}

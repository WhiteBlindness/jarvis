import { describe, expect, it } from "vitest";
import { en, pt, resolveLang, toolLabel, translate } from "./i18n";

type Key = keyof typeof pt;

describe("strings", () => {
  it("has the same keys in both languages", () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(pt).sort());
  });

  it("has no empty strings", () => {
    for (const dict of [pt, en]) {
      for (const value of Object.values(dict)) expect(value.trim()).not.toBe("");
    }
  });

  it("keeps the same placeholders in both languages", () => {
    const names = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const key of Object.keys(pt) as Key[]) {
      expect(names(en[key]), key).toEqual(names(pt[key]));
    }
  });

  it("uses the required PT-PT vocabulary", () => {
    expect(pt.proposalTitle).toBe("A Donna sugere copiar para a área de transferência:");
    expect(pt.proposalWaiting).toBe("À espera da tua aprovação");
    expect(pt.proposalAsk).toBe("Pedir aprovação");
    expect(pt.deleteAll).toBe("Apagar todas as conversas");
    expect(pt.settings).toBe("Definições");
    expect(pt.stateReady).toBe("Pronta");
    expect(pt.stateLoading).toBe("A carregar");
    expect(pt.stateGenerating).toBe("A gerar");
    expect(pt.statePaused).toBe("Em pausa — jogo a correr");
    expect(pt.stateUnloaded).toBe("Fora da memória");
    expect(pt.stateFailed).toBe("Erro");
    expect(pt.gpuOn).toBe("GPU · Vulkan");
    expect(pt.clipboardBody).toContain("área de transferência");
    expect(toolLabel("pt", "desktop.write_clipboard_text")).toBe(
      "Escrever na área de transferência",
    );
  });

  it("avoids Brazilianisms and gerund constructions in Portuguese", () => {
    const all = Object.values(pt).join("\n").toLowerCase();
    const banned = ["tela", "usuário", "configurações", "deletar", "arquivo", "clique", "baixar", "você"];
    for (const word of banned) expect(all, word).not.toContain(word);
    expect(all).not.toMatch(/\best(ou|á)\s+\w+(ando|endo|indo)\b/);
  });

  it("never uses descarregar, which means download in Portuguese", () => {
    expect(Object.values(pt).join("\n").toLowerCase()).not.toContain("descarreg");
  });

  it("explains a slow graphics card in both languages", () => {
    expect(translate("pt", "slowBody", { tps: "17.1" })).toBe(
      "A placa gráfica está lenta (~17.1 tok/s): parte do modelo ficou fora da memória de vídeo. Recarregar pode ajudar; se continuar lenta, fecha aplicações que usem a placa gráfica ou termina a sessão do Windows.",
    );
    expect(translate("en", "slowBody", { tps: "17.1" })).toContain("~17.1 tok/s");
    expect(pt.reloadModel).toBe("Recarregar modelo");
    expect(pt.retentionKeep).toBe("Manter");
    expect(pt.clipboardBody).toContain("não fica guardado");
  });

  it("warns that exported files may sync and keeps the retention confirmation plural-aware", () => {
    expect(pt.storageBody).toContain("nuvem");
    expect(en.storageBody).toContain("syncs with the cloud");
    expect(translate("pt", "retentionConfirmMany", { n: 3, days: 30 })).toBe(
      "Isto apaga já 3 conversas sem atividade há mais de 30 dias. Continuar?",
    );
    expect(translate("pt", "retentionConfirmOne", { n: 1, days: 7 })).toContain("1 conversa sem");
    expect(translate("pt", "retentionConfirmZero", { days: 7 })).toContain("nada é apagado");
    expect(translate("en", "retentionConfirmOne", { n: 1, days: 7 })).toContain("1 conversation inactive");
  });

  it("does not claim conversations are kept forever", () => {
    expect(pt.storageBody).toContain("retenção");
    expect(en.storageBody).toContain("retention");
  });

  it("falls back to the raw tool name and interpolates variables", () => {
    expect(toolLabel("en", "unknown.tool")).toBe("unknown.tool");
    expect(translate("pt", "expiresIn", { time: "1:30" })).toBe("Expira em 1:30");
  });

  it("resolves the automatic language from the system language", () => {
    expect(resolveLang("auto", "pt-PT")).toBe("pt");
    expect(resolveLang("auto", "en-US")).toBe("en");
    expect(resolveLang("pt_pt", "en-US")).toBe("pt");
    expect(resolveLang("en", "pt-PT")).toBe("en");
  });
});

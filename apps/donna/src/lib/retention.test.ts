import { describe, expect, it } from "vitest";
import { countAffected, needsConfirmation } from "./retention";

const NOW = Date.parse("2026-10-23T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW - n * 24 * 3600 * 1000).toISOString();

describe("retention count", () => {
  const list = [
    { updated_at: daysAgo(1) },
    { updated_at: daysAgo(8) },
    { updated_at: daysAgo(40) },
    { updated_at: daysAgo(100) },
    { updated_at: "not a date" },
  ];

  it("counts conversations older than the period", () => {
    expect(countAffected(list, 7, NOW)).toBe(3);
    expect(countAffected(list, 30, NOW)).toBe(2);
    expect(countAffected(list, 90, NOW)).toBe(1);
    expect(countAffected(list, 365, NOW)).toBe(0);
  });

  it("counts nothing for keep and for an empty list", () => {
    expect(countAffected(list, 0, NOW)).toBe(0);
    expect(countAffected([], 7, NOW)).toBe(0);
  });

  it("asks for confirmation only when something can be deleted at once", () => {
    expect(needsConfirmation(0, 30)).toBe(true);
    expect(needsConfirmation(90, 30)).toBe(true);
    expect(needsConfirmation(30, 90)).toBe(false);
    expect(needsConfirmation(30, 30)).toBe(false);
    expect(needsConfirmation(30, 0)).toBe(false);
    expect(needsConfirmation(0, 0)).toBe(false);
  });
});

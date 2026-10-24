const DAY_MS = 24 * 3600 * 1000;

/** How many conversations a retention period of `days` would delete right now. */
export function countAffected(
  conversations: { updated_at: string }[],
  days: number,
  now: number = Date.now(),
): number {
  if (days <= 0) return 0;
  const cutoff = now - days * DAY_MS;
  return conversations.filter((c) => {
    const updated = Date.parse(c.updated_at);
    return !Number.isNaN(updated) && updated < cutoff;
  }).length;
}

/**
 * A change needs a confirmation when it can delete something at once: any
 * period when nothing is set ("keep" is 0), or a shorter period than the
 * current one. A longer period, or "keep", deletes nothing.
 */
export function needsConfirmation(current: number, next: number): boolean {
  if (next === 0) return false;
  return current === 0 || next < current;
}

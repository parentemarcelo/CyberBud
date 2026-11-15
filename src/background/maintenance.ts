// Housekeeping (docs/SPEC.md F6): purge expired cache entries and old history
// on every background start and once a day.
import { purgeExpired, ttlMs } from '../lib/cache';
import { purgeHistory } from '../lib/history';
import { getSettings } from '../lib/settings';

export const PURGE_ALARM = 'cyberbud-purge';

export async function purge(now: number = Date.now()): Promise<{ cache: number; history: number }> {
  const s = await getSettings();
  const [cache, history] = await Promise.all([purgeExpired(ttlMs(s.cacheTtlHours), now), purgeHistory(s.historyRetentionDays, now)]);
  return { cache, history };
}

export async function ensurePurgeAlarm(): Promise<void> {
  if (!(await browser.alarms.get(PURGE_ALARM))) {
    await browser.alarms.create(PURGE_ALARM, { periodInMinutes: 24 * 60 });
  }
}

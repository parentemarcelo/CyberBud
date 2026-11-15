// Lookup history (docs/SPEC.md F6), stored locally as one list, newest first.
// Looking up the same IOC again updates its entry and moves it to the top.
// Writes are serialized; history is only written from the background page.
import { MAX_HISTORY_ENTRIES } from './constants';
import { createMutex } from './mutex';
import { IOC_TYPES, VERDICTS, type Ioc, type IocType, type LookupOrigin, type Verdict } from './types';

export const HISTORY_KEY = 'history';
const DAY_MS = 86_400_000;
const ORIGINS: readonly LookupOrigin[] = ['popup', 'context_menu', 'file'];

export interface HistoryEntry {
  value: string;
  type: IocType;
  /** Summary verdict; 'unknown' while the lookup is still running. */
  verdict: Verdict;
  /** Epoch ms of the latest lookup. */
  timestamp: number;
  origin: LookupOrigin;
}

export interface HistoryOptions {
  historyEnabled: boolean;
}

const exclusive = createMutex();

/** Add or update the entry for `ioc`. No-op (returns false) when history is off. */
export function addHistory(
  ioc: Pick<Ioc, 'value' | 'type'>,
  verdict: Verdict,
  origin: LookupOrigin,
  options: HistoryOptions,
  now: number = Date.now(),
): Promise<boolean> {
  if (!options.historyEnabled) return Promise.resolve(false);
  return exclusive(async () => {
    const entry: HistoryEntry = { value: ioc.value, type: ioc.type, verdict, timestamp: now, origin };
    const rest = (await read()).filter((e) => !(e.type === ioc.type && e.value === ioc.value));
    await write([entry, ...rest].slice(0, MAX_HISTORY_ENTRIES));
    return true;
  });
}

/** All entries, newest first. */
export async function listHistory(): Promise<HistoryEntry[]> {
  return read();
}

/** Remove entries older than `retentionDays`. Returns the count removed. */
export function purgeHistory(retentionDays: number, now: number = Date.now()): Promise<number> {
  return exclusive(async () => {
    const all = await read();
    const cutoff = now - retentionDays * DAY_MS;
    const kept = all.filter((e) => e.timestamp >= cutoff && e.timestamp <= now + DAY_MS);
    if (kept.length !== all.length) await write(kept);
    return all.length - kept.length;
  });
}

export function clearHistory(): Promise<void> {
  return exclusive(() => browser.storage.local.remove(HISTORY_KEY));
}

async function read(): Promise<HistoryEntry[]> {
  const raw = (await browser.storage.local.get(HISTORY_KEY))[HISTORY_KEY];
  if (!Array.isArray(raw)) return [];
  return raw.filter(isEntry).sort((a, b) => b.timestamp - a.timestamp);
}

function write(entries: HistoryEntry[]): Promise<void> {
  return browser.storage.local.set({ [HISTORY_KEY]: entries });
}

function isEntry(x: unknown): x is HistoryEntry {
  if (typeof x !== 'object' || x === null) return false;
  const e = x as Partial<HistoryEntry>;
  return (
    typeof e.value === 'string' &&
    (IOC_TYPES as readonly string[]).includes(e.type as string) &&
    (VERDICTS as readonly string[]).includes(e.verdict as string) &&
    typeof e.timestamp === 'number' &&
    Number.isFinite(e.timestamp) &&
    ORIGINS.includes(e.origin as LookupOrigin)
  );
}

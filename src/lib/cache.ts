// Result cache in storage.local (docs/SPEC.md F6). One storage key per entry,
// so concurrent writes for different IOCs never collide.
import type { Ioc, SourceId, SourceResult, Status } from './types';

export const CACHE_PREFIX = 'cache:';
const HOUR_MS = 3_600_000;

/** Only real answers are cached; errors and transient states never are. */
const CACHEABLE: ReadonlySet<Status> = new Set(['ok', 'not_found']);

interface CacheEntry {
  result: SourceResult;
  fetchedAt: number;
}

export function cacheKey(source: SourceId, ioc: Pick<Ioc, 'type' | 'value'>): string {
  return `${CACHE_PREFIX}${source}|${ioc.type}|${ioc.value}`;
}

export function ttlMs(hours: number): number {
  return Math.max(0, hours) * HOUR_MS;
}

/**
 * Cached result if younger than `ttl` (ms), marked `fromCache: true` and
 * carrying the caller's `ioc` (so `raw` matches the current input).
 * Expired entries are removed.
 */
export async function getCached(
  source: SourceId,
  ioc: Ioc,
  ttl: number,
  now: number = Date.now(),
): Promise<SourceResult | null> {
  if (ttl <= 0) return null;
  const key = cacheKey(source, ioc);
  const entry = (await browser.storage.local.get(key))[key];
  if (!isEntry(entry)) return null;
  // Entries "from the future" (clock moved back) are treated as expired.
  if (entry.fetchedAt > now || now - entry.fetchedAt >= ttl) {
    await browser.storage.local.remove(key);
    return null;
  }
  return { ...entry.result, ioc, fromCache: true, fetchedAt: entry.fetchedAt };
}

/** Store a result if cacheable. Returns whether it was stored. */
export async function putCached(result: SourceResult, now: number = Date.now()): Promise<boolean> {
  if (!CACHEABLE.has(result.status)) return false;
  const fetchedAt = result.fetchedAt ?? now;
  // Strip per-request fields; `raw` is replaced on read anyway.
  const { fromCache: _f, retryAt: _r, error: _e, ...rest } = result;
  const entry: CacheEntry = { result: { ...rest, fetchedAt }, fetchedAt };
  await browser.storage.local.set({ [cacheKey(result.source, result.ioc)]: entry });
  return true;
}

/** Remove one entry, e.g. before a Refresh. */
export async function invalidate(source: SourceId, ioc: Pick<Ioc, 'type' | 'value'>): Promise<void> {
  await browser.storage.local.remove(cacheKey(source, ioc));
}

/** Remove every cache entry; other storage keys are untouched. Returns the count removed. */
export async function clearCache(): Promise<number> {
  const keys = await cacheKeys();
  if (keys.length) await browser.storage.local.remove(keys);
  return keys.length;
}

/** Remove entries older than `ttl`. Returns the count removed. */
export async function purgeExpired(ttl: number, now: number = Date.now()): Promise<number> {
  const all = await browser.storage.local.get(null);
  const stale = Object.keys(all).filter((k) => {
    if (!k.startsWith(CACHE_PREFIX)) return false;
    const e = all[k];
    return !isEntry(e) || e.fetchedAt > now || now - e.fetchedAt >= ttl;
  });
  if (stale.length) await browser.storage.local.remove(stale);
  return stale.length;
}

async function cacheKeys(): Promise<string[]> {
  return Object.keys(await browser.storage.local.get(null)).filter((k) => k.startsWith(CACHE_PREFIX));
}

function isEntry(x: unknown): x is CacheEntry {
  if (typeof x !== 'object' || x === null) return false;
  const e = x as Partial<CacheEntry>;
  return typeof e.fetchedAt === 'number' && typeof e.result === 'object' && e.result !== null;
}

import { describe, expect, it, vi } from 'vitest';
import {
  CACHE_PREFIX,
  cacheKey,
  clearCache,
  getCached,
  invalidate,
  purgeExpired,
  putCached,
  ttlMs,
} from '../../src/lib/cache';
import type { Ioc, SourceResult, Status } from '../../src/lib/types';

const ioc: Ioc = { raw: 'evil[.]example', value: 'evil.example', type: 'domain' };
const HOUR = 3_600_000;
const T0 = Date.UTC(2026, 10, 15, 12, 0, 0);

const result = (status: Status = 'ok', extra: Partial<SourceResult> = {}): SourceResult => ({
  source: 'virustotal',
  ioc,
  status,
  verdict: status === 'ok' ? 'malicious' : 'unknown',
  headline: '12/94 engines',
  details: [['Registrar', 'Example']],
  link: 'https://www.virustotal.com/gui/domain/evil.example',
  fetchedAt: T0,
  ...extra,
});

describe('cache key', () => {
  it('is source|type|value', () => {
    expect(cacheKey('virustotal', ioc)).toBe(`${CACHE_PREFIX}virustotal|domain|evil.example`);
  });

  it('separates sources and types', () => {
    expect(cacheKey('urlhaus', ioc)).not.toBe(cacheKey('virustotal', ioc));
    expect(cacheKey('virustotal', { type: 'url', value: 'evil.example' })).not.toBe(cacheKey('virustotal', ioc));
  });
});

describe('TTL (SPEC F6)', () => {
  it('hit before the TTL, miss after it (fake timers)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    await putCached(result('ok', { fetchedAt: undefined }));

    vi.setSystemTime(T0 + 24 * HOUR - 1);
    const hit = await getCached('virustotal', ioc, ttlMs(24));
    expect(hit).toMatchObject({ status: 'ok', verdict: 'malicious', fromCache: true, fetchedAt: T0 });

    vi.setSystemTime(T0 + 24 * HOUR);
    expect(await getCached('virustotal', ioc, ttlMs(24))).toBeNull();
  });

  it('expired entries are removed from storage', async () => {
    await putCached(result());
    expect(await getCached('virustotal', ioc, HOUR, T0 + 2 * HOUR)).toBeNull();
    expect(await browser.storage.local.get(cacheKey('virustotal', ioc))).toEqual({});
  });

  it('TTL 0 disables the cache', async () => {
    await putCached(result());
    expect(await getCached('virustotal', ioc, 0, T0)).toBeNull();
  });

  it('entries from the future (clock moved back) are treated as expired', async () => {
    await putCached(result());
    expect(await getCached('virustotal', ioc, HOUR, T0 - 1000)).toBeNull();
  });
});

describe('what is cached', () => {
  it('stores ok and not_found', async () => {
    expect(await putCached(result('ok'))).toBe(true);
    expect(await putCached(result('not_found', { source: 'urlhaus' }))).toBe(true);
    expect(await getCached('urlhaus', ioc, HOUR, T0)).toMatchObject({ status: 'not_found' });
  });

  it.each<Status>(['error', 'rate_limited', 'queued', 'loading', 'no_key', 'disabled'])('never stores %s', async (s) => {
    expect(await putCached(result(s))).toBe(false);
    expect(await browser.storage.local.get(null)).toEqual({});
  });

  it('returns the caller ioc (raw) and drops per-request fields', async () => {
    await putCached(result('ok', { fromCache: true, retryAt: 123, error: 'x' }));
    const other: Ioc = { ...ioc, raw: 'EVIL.EXAMPLE' };
    const hit = await getCached('virustotal', other, HOUR, T0 + 1);
    expect(hit?.ioc.raw).toBe('EVIL.EXAMPLE');
    expect(hit).not.toHaveProperty('retryAt');
    expect(hit).not.toHaveProperty('error');
  });

  it('ignores corrupted entries', async () => {
    await browser.storage.local.set({ [cacheKey('virustotal', ioc)]: { nope: true } });
    expect(await getCached('virustotal', ioc, HOUR, T0)).toBeNull();
  });
});

describe('clear, invalidate, purge', () => {
  it('clearCache removes only cache entries', async () => {
    await putCached(result());
    await putCached(result('ok', { source: 'threatfox' }));
    await browser.storage.local.set({ settings: { urlMode: 'full' }, history: [] });

    expect(await clearCache()).toBe(2);
    expect(Object.keys(await browser.storage.local.get(null)).sort()).toEqual(['history', 'settings']);
    expect(await clearCache()).toBe(0);
  });

  it('invalidate removes one entry', async () => {
    await putCached(result());
    await putCached(result('ok', { source: 'threatfox' }));
    await invalidate('virustotal', ioc);
    expect(await getCached('virustotal', ioc, HOUR, T0)).toBeNull();
    expect(await getCached('threatfox', ioc, HOUR, T0)).not.toBeNull();
  });

  it('purgeExpired removes stale and corrupted entries only', async () => {
    await putCached(result('ok', { fetchedAt: T0 - 2 * HOUR }));
    await putCached(result('ok', { source: 'threatfox', fetchedAt: T0 }));
    await browser.storage.local.set({ [`${CACHE_PREFIX}bad`]: 'x', settings: {} });

    expect(await purgeExpired(HOUR, T0 + 1)).toBe(2);
    expect(Object.keys(await browser.storage.local.get(null)).sort()).toEqual([
      cacheKey('threatfox', ioc),
      'settings',
    ]);
  });
});

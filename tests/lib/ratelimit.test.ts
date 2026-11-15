import { describe, expect, it, vi } from 'vitest';
import { DAY_MS, RateLimiter, RequestQueue, WINDOW_MS } from '../../src/lib/ratelimit';

const T0 = Date.UTC(2026, 10, 15, 12, 0, 0);
const MIDNIGHT = Date.UTC(2026, 10, 16, 0, 0, 0);

describe('RateLimiter: per-minute window (SPEC F6)', () => {
  it('VirusTotal allows 4 requests, then the 5th waits about 60 s (fake timers)', () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const rl = new RateLimiter();
    for (let i = 0; i < 4; i++) expect(rl.acquire('virustotal')).toEqual({ kind: 'now' });

    expect(rl.acquire('virustotal')).toEqual({ kind: 'wait', ms: WINDOW_MS, at: T0 + WINDOW_MS });

    vi.advanceTimersByTime(45_000);
    expect(rl.check('virustotal')).toMatchObject({ kind: 'wait', ms: 15_000 });

    vi.advanceTimersByTime(15_000);
    expect(rl.acquire('virustotal')).toEqual({ kind: 'now' });
  });

  it('is a sliding window, not a fixed minute', () => {
    const rl = new RateLimiter();
    rl.acquire('virustotal', T0);
    rl.acquire('virustotal', T0 + 10_000);
    rl.acquire('virustotal', T0 + 20_000);
    rl.acquire('virustotal', T0 + 30_000);
    // The first slot frees at T0+60s, the second at T0+70s.
    expect(rl.check('virustotal', T0 + 59_999)).toMatchObject({ kind: 'wait', ms: 1 });
    expect(rl.acquire('virustotal', T0 + 60_000)).toEqual({ kind: 'now' });
    expect(rl.check('virustotal', T0 + 60_000)).toMatchObject({ kind: 'wait', at: T0 + 70_000 });
  });

  it('check() does not consume a slot', () => {
    const rl = new RateLimiter();
    for (let i = 0; i < 10; i++) expect(rl.check('virustotal', T0)).toEqual({ kind: 'now' });
    expect(rl.remainingToday('virustotal', T0)).toBe(500);
  });

  it('sources are independent; abuse.ch sources allow 60 per minute', () => {
    const rl = new RateLimiter();
    for (let i = 0; i < 4; i++) rl.acquire('virustotal', T0);
    expect(rl.check('virustotal', T0).kind).toBe('wait');
    for (let i = 0; i < 60; i++) expect(rl.acquire('urlhaus', T0).kind).toBe('now');
    expect(rl.acquire('urlhaus', T0).kind).toBe('wait');
    expect(rl.acquire('threatfox', T0).kind).toBe('now');
  });
});

describe('RateLimiter: daily quota', () => {
  it('VirusTotal daily cap is reached at 500', () => {
    const rl = new RateLimiter();
    let t = T0 - 10 * 3_600_000; // 02:00 UTC, leaves room for 125 minutes of requests
    for (let i = 0; i < 500; i++) {
      const d = rl.acquire('virustotal', t);
      if (d.kind === 'wait') {
        t = d.at;
        expect(rl.acquire('virustotal', t).kind).toBe('now');
      }
    }
    expect(rl.remainingToday('virustotal', t)).toBe(0);
    expect(rl.acquire('virustotal', t + WINDOW_MS)).toEqual({ kind: 'quota', resetAt: MIDNIGHT });
  });

  it('the counter resets across UTC midnight', () => {
    const rl = new RateLimiter({ ...limitsWith({ perMinute: 100, perDay: 3 }) });
    const late = MIDNIGHT - 1000;
    for (let i = 0; i < 3; i++) rl.acquire('virustotal', late);
    expect(rl.check('virustotal', late)).toEqual({ kind: 'quota', resetAt: MIDNIGHT });
    expect(rl.check('virustotal', MIDNIGHT - 1).kind).toBe('quota');
    expect(rl.acquire('virustotal', MIDNIGHT)).toEqual({ kind: 'now' });
    expect(rl.remainingToday('virustotal', MIDNIGHT)).toBe(2);
  });

  it('sources without a daily limit have no quota', () => {
    const rl = new RateLimiter();
    expect(rl.remainingToday('urlhaus', T0)).toBeUndefined();
  });
});

describe('RateLimiter: Retry-After penalty', () => {
  it('blocks the source until the penalty expires', () => {
    const rl = new RateLimiter();
    rl.penalize('abuseipdb', 30_000, T0);
    expect(rl.check('abuseipdb', T0)).toEqual({ kind: 'wait', ms: 30_000, at: T0 + 30_000 });
    expect(rl.check('abuseipdb', T0 + 30_000)).toEqual({ kind: 'now' });
  });

  it('a shorter penalty never shortens an existing one; negative is ignored', () => {
    const rl = new RateLimiter();
    rl.penalize('abuseipdb', 60_000, T0);
    rl.penalize('abuseipdb', 5_000, T0);
    rl.penalize('abuseipdb', -1, T0);
    expect(rl.check('abuseipdb', T0)).toMatchObject({ at: T0 + 60_000 });
  });

  it('caps absurd penalties at one day', () => {
    const rl = new RateLimiter();
    rl.penalize('abuseipdb', 365 * DAY_MS, T0);
    expect(rl.check('abuseipdb', T0)).toMatchObject({ at: T0 + DAY_MS });
  });
});

describe('RateLimiter: clock moved backwards', () => {
  it('ignores timestamps from the future instead of blocking', () => {
    const rl = new RateLimiter();
    for (let i = 0; i < 4; i++) rl.acquire('virustotal', T0);
    expect(rl.check('virustotal', T0 - 5 * 60_000)).toEqual({ kind: 'now' });
  });
});

describe('RateLimiter: serialize/restore', () => {
  it('restored limiter behaves identically', () => {
    const rl = new RateLimiter();
    for (let i = 0; i < 4; i++) rl.acquire('virustotal', T0);
    rl.acquire('abuseipdb', T0);
    rl.penalize('urlhaus', 10_000, T0);

    const json = JSON.parse(JSON.stringify(rl.serialize()));
    const copy = RateLimiter.restore(json);
    expect(copy.serialize()).toEqual(rl.serialize());
    for (const s of ['virustotal', 'abuseipdb', 'urlhaus', 'threatfox'] as const) {
      expect(copy.check(s, T0 + 1)).toEqual(rl.check(s, T0 + 1));
    }
    expect(copy.remainingToday('abuseipdb', T0)).toBe(999);
  });

  it('serialize returns a copy, not live state', () => {
    const rl = new RateLimiter();
    const snap = rl.serialize();
    rl.acquire('virustotal', T0);
    expect(snap.sources).toEqual({});
  });

  it.each([null, 'x', { v: 2, sources: {} }, { v: 1, sources: { nope: {} } }, { v: 1, sources: { virustotal: { recent: 'x' } } }])(
    'invalid state %j → fresh limiter',
    (bad) => {
      expect(RateLimiter.restore(bad).serialize()).toEqual({ v: 1, sources: {} });
    },
  );
});

describe('RequestQueue', () => {
  it('drains ready jobs FIFO and keeps the rest queued', () => {
    const rl = new RateLimiter();
    const q = new RequestQueue<string>();
    for (let i = 1; i <= 6; i++) q.enqueue('virustotal', `vt${i}`, T0);
    q.enqueue('urlhaus', 'uh1', T0);

    const { ready, exhausted } = q.drain(rl, T0);
    expect(ready.map((j) => j.payload)).toEqual(['vt1', 'vt2', 'vt3', 'vt4', 'uh1']);
    expect(exhausted).toEqual([]);
    expect(q.list().map((j) => j.payload)).toEqual(['vt5', 'vt6']);

    expect(q.nextWakeAt(rl, T0)).toBe(T0 + WINDOW_MS);
    expect(q.drain(rl, T0 + 30_000).ready).toEqual([]);
    expect(q.drain(rl, T0 + WINDOW_MS).ready.map((j) => j.payload)).toEqual(['vt5', 'vt6']);
    expect(q.size).toBe(0);
    expect(q.nextWakeAt(rl, T0)).toBeNull();
  });

  it('returns jobs over the daily quota as exhausted', () => {
    const rl = new RateLimiter(limitsWith({ perMinute: 10, perDay: 2 }));
    const q = new RequestQueue<number>();
    for (let i = 0; i < 3; i++) q.enqueue('virustotal', i, T0);
    const { ready, exhausted } = q.drain(rl, T0);
    expect(ready.map((j) => j.payload)).toEqual([0, 1]);
    expect(exhausted.map((j) => j.payload)).toEqual([2]);
    expect(q.size).toBe(0);
  });

  it('estimates start time from queue position', () => {
    const rl = new RateLimiter();
    const q = new RequestQueue<number>();
    const jobs = Array.from({ length: 10 }, (_, i) => q.enqueue('virustotal', i, T0));
    q.drain(rl, T0); // first 4 run
    expect(q.estimateStart(jobs[4]!.id, rl, T0)).toBe(T0 + WINDOW_MS);
    expect(q.estimateStart(jobs[7]!.id, rl, T0)).toBe(T0 + WINDOW_MS);
    expect(q.estimateStart(jobs[8]!.id, rl, T0)).toBe(T0 + 2 * WINDOW_MS);
    expect(q.estimateStart('missing', rl, T0)).toBeNull();
  });

  it('remove() cancels matching jobs', () => {
    const q = new RequestQueue<string>();
    q.enqueue('virustotal', 'a', T0);
    q.enqueue('urlhaus', 'b', T0);
    expect(q.remove((j) => j.source === 'virustotal').map((j) => j.payload)).toEqual(['a']);
    expect(q.list().map((j) => j.payload)).toEqual(['b']);
  });

  it('serialize/restore round-trips through JSON (storage.session)', async () => {
    const rl = new RateLimiter();
    const q = new RequestQueue<{ ioc: string }>();
    for (let i = 0; i < 6; i++) q.enqueue('virustotal', { ioc: `x${i}` }, T0);
    q.drain(rl, T0);

    await browser.storage.session.set({ queue: q.serialize(), limiter: rl.serialize() });
    const stored = await browser.storage.session.get(['queue', 'limiter']);
    const q2 = RequestQueue.restore<{ ioc: string }>(stored.queue);
    const rl2 = RateLimiter.restore(stored.limiter);

    expect(q2.serialize()).toEqual(q.serialize());
    expect(q2.nextWakeAt(rl2, T0)).toBe(T0 + WINDOW_MS);
    expect(q2.drain(rl2, T0 + WINDOW_MS).ready.map((j) => j.payload.ioc)).toEqual(['x4', 'x5']);
  });

  it('invalid queue state → empty queue', () => {
    expect(RequestQueue.restore({ v: 1, jobs: [{ id: 1 }] }).size).toBe(0);
    expect(RequestQueue.restore(undefined).size).toBe(0);
  });
});

function limitsWith(vt: { perMinute: number; perDay?: number }) {
  return {
    virustotal: vt,
    abuseipdb: { perMinute: 60, perDay: 1000 },
    urlhaus: { perMinute: 60 },
    malwarebazaar: { perMinute: 60 },
    threatfox: { perMinute: 60 },
  };
}

import { describe, expect, it, vi } from 'vitest';
import { Engine } from '../../src/background/engine';
import { putCached } from '../../src/lib/cache';
import { listHistory } from '../../src/lib/history';
import { errorResult, result } from '../../src/lib/sources/common';
import type { Ioc, IocReport } from '../../src/lib/types';
import { fakeAdapter, makeEngine, statusOf } from '../helpers/engine';

const T0 = Date.UTC(2026, 10, 15, 12, 0, 0);
const dom = (value: string): Ioc => ({ raw: value, value, type: 'domain' });

function useClock() {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
}

describe('lookup basics', () => {
  it('parses, emits parsed + reports, and runs every source', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const uh = fakeAdapter('urlhaus', (ioc) => result('urlhaus', ioc, { status: 'ok', verdict: 'malicious', headline: 'listed' }));
    const h = await makeEngine([vt.adapter, uh.adapter]);

    const items = await h.engine.lookup('evil[.]example', 'popup');
    expect(items).toEqual([{ kind: 'ioc', ioc: { raw: 'evil[.]example', value: 'evil.example', type: 'domain' } }]);
    expect(h.messages[0]).toEqual({ type: 'parsed', items });

    const report = h.engine.getReport(dom('evil.example'))!;
    expect(report.results.map((r) => [r.source, r.status, r.verdict])).toEqual([
      ['virustotal', 'ok', 'clean'],
      ['urlhaus', 'ok', 'malicious'],
    ]);
    expect(report.summary).toEqual({ verdict: 'malicious', flagged: 1, total: 2, pending: 0 });
    // First report shows both sources loading.
    const first = h.messages.find((m) => m.type === 'report')!;
    expect(first.type === 'report' && first.report.results.map((r) => r.status)).toEqual(['loading', 'loading']);
  });

  it('passes the right API key to each adapter', async () => {
    const vt = fakeAdapter('virustotal');
    const tf = fakeAdapter('threatfox');
    const h = await makeEngine([vt.adapter, tf.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup.mock.calls[0]![1]).toBe('vt-secret-key-123');
    expect(tf.lookup.mock.calls[0]![1]).toBe('ac-secret-key-123');
  });

  it('private and unsupported items are never sent', async () => {
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    const items = await h.engine.lookup('10.0.0.1 foo', 'popup');
    expect(items.map((i) => i.kind)).toEqual(['private', 'unsupported']);
    expect(vt.lookup).not.toHaveBeenCalled();
  });

  it('missing keys / disabled sources give placeholders and no calls', async () => {
    const vt = fakeAdapter('virustotal');
    const uh = fakeAdapter('urlhaus');
    const h = await makeEngine([vt.adapter, uh.adapter], {
      settings: { keys: { vt: '', abuseipdb: '', abusech: 'k' }, enabledSources: { virustotal: true, abuseipdb: true, urlhaus: false, malwarebazaar: true, threatfox: true } },
    });
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup).not.toHaveBeenCalled();
    expect(uh.lookup).not.toHaveBeenCalled();
    expect(h.engine.getReport(dom('evil.example'))!.results.map((r) => r.status)).toEqual(['no_key', 'disabled']);
  });
});

describe('cache (SPEC F6)', () => {
  it('a cache hit means the adapter is not called', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    await putCached(result('virustotal', dom('evil.example'), { status: 'ok', verdict: 'malicious', headline: 'cached', fetchedAt: T0 - 1000 }));
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup).not.toHaveBeenCalled();
    expect(h.engine.getReport(dom('evil.example'))!.results[0]).toMatchObject({ fromCache: true, verdict: 'malicious', headline: 'cached' });
  });

  it('results are cached; a second lookup does not call the adapter', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup).toHaveBeenCalledTimes(1);
  });

  it('errors are not cached', async () => {
    const vt = fakeAdapter('virustotal', (ioc) => errorResult('virustotal', ioc, 'Network error'));
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup).toHaveBeenCalledTimes(2);
  });

  it('refresh bypasses the cache, and only re-runs the given source', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const uh = fakeAdapter('urlhaus');
    const h = await makeEngine([vt.adapter, uh.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    await h.engine.refresh(dom('evil.example'), 'virustotal');
    expect(vt.lookup).toHaveBeenCalledTimes(2);
    expect(uh.lookup).toHaveBeenCalledTimes(1);
    await h.engine.refresh(dom('evil.example'));
    expect(vt.lookup).toHaveBeenCalledTimes(3);
    expect(uh.lookup).toHaveBeenCalledTimes(2);
  });
});

describe('rate limits and queue (SPEC F6)', () => {
  it('the 5th VirusTotal call reports queued, then ok after the window', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('a.example b.example c.example d.example e.example', 'popup');

    expect(vt.lookup).toHaveBeenCalledTimes(4);
    const fifth = h.engine.getReport(dom('e.example'))!;
    expect(fifth.results[0]).toMatchObject({ status: 'queued', retryAt: T0 + 60_000 });
    expect(fifth.summary.pending).toBe(1);
    expect(h.alarm).toHaveBeenLastCalledWith(T0 + 60_000);

    await vi.advanceTimersByTimeAsync(59_999);
    expect(statusOf(h, dom('e.example'), 'virustotal')).toBe('queued');
    await vi.advanceTimersByTimeAsync(1);
    expect(statusOf(h, dom('e.example'), 'virustotal')).toBe('ok');
    expect(vt.lookup).toHaveBeenCalledTimes(5);

    const statuses = h.messages.flatMap((m) =>
      m.type === 'report' && m.report.ioc.value === 'e.example' ? [m.report.results[0]!.status] : [],
    );
    expect(statuses).toEqual(['loading', 'queued', 'ok']);
    expect(h.alarm).toHaveBeenLastCalledWith(null);
  });

  it('new lookups wait behind queued jobs (FIFO)', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('a.example b.example c.example d.example e.example', 'popup');
    await vi.advanceTimersByTimeAsync(30_000);
    await h.engine.lookup('f.example', 'popup');
    expect(statusOf(h, dom('f.example'), 'virustotal')).toBe('queued');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(vt.lookup.mock.calls.slice(4).map((c) => c[0].value)).toEqual(['e.example', 'f.example']);
  });

  it('a server 429 re-queues with Retry-After and succeeds later', async () => {
    useClock();
    let calls = 0;
    const ab = fakeAdapter('abuseipdb', (ioc) =>
      ++calls === 1
        ? result('abuseipdb', ioc, { status: 'rate_limited', retryAt: Date.now() + 10_000, headline: 'x' })
        : result('abuseipdb', ioc, { status: 'ok', verdict: 'clean', headline: 'ok' }),
    );
    const h = await makeEngine([ab.adapter]);
    await h.engine.lookup('8.8.8.8', 'popup');
    const ip = { type: 'ipv4' as const, value: '8.8.8.8' };
    expect(statusOf(h, ip, 'abuseipdb')).toBe('queued');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(statusOf(h, ip, 'abuseipdb')).toBe('ok');
  });

  it('gives up after 3 attempts of 429', async () => {
    useClock();
    const ab = fakeAdapter('abuseipdb', (ioc) => result('abuseipdb', ioc, { status: 'rate_limited', headline: 'x' }));
    const h = await makeEngine([ab.adapter]);
    await h.engine.lookup('8.8.8.8', 'popup');
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(ab.lookup).toHaveBeenCalledTimes(3);
    expect(statusOf(h, { type: 'ipv4', value: '8.8.8.8' }, 'abuseipdb')).toBe('rate_limited');
  });

  it('daily quota → rate_limited "Daily quota reached"', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter], {
      initialState: {
        v: 1,
        queue: { v: 1, jobs: [] },
        limiter: { v: 1, sources: { virustotal: { recent: [], day: Math.floor(T0 / 86_400_000), dayCount: 500, blockedUntil: 0 } } },
        reports: [],
        items: [],
      },
    });
    await h.engine.lookup('evil.example', 'popup');
    expect(vt.lookup).not.toHaveBeenCalled();
    expect(h.engine.getReport(dom('evil.example'))!.results[0]).toMatchObject({
      status: 'rate_limited',
      headline: 'Daily quota reached',
      retryAt: Date.UTC(2026, 10, 16),
    });
  });
});

describe('failures are isolated', () => {
  it('one failing adapter does not affect the others', async () => {
    const vt = fakeAdapter('virustotal', () => {
      throw new Error('boom');
    });
    const uh = fakeAdapter('urlhaus', (ioc) => result('urlhaus', ioc, { status: 'ok', verdict: 'malicious', headline: 'x' }));
    const tf = fakeAdapter('threatfox', (ioc) => errorResult('threatfox', ioc, 'Network error'));
    const h = await makeEngine([vt.adapter, uh.adapter, tf.adapter]);
    await h.engine.lookup('evil.example', 'popup');
    const r = h.engine.getReport(dom('evil.example'))!;
    expect(r.results.map((x) => [x.source, x.status])).toEqual([
      ['virustotal', 'error'],
      ['urlhaus', 'ok'],
      ['threatfox', 'error'],
    ]);
    expect(r.results[0]!.error).toBe('Unexpected error');
    expect(r.summary).toEqual({ verdict: 'malicious', flagged: 1, total: 1, pending: 0 });
  });

  it('a throwing listener does not break the engine', async () => {
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    h.engine.subscribe(() => {
      throw new Error('closed port');
    });
    await expect(h.engine.lookup('evil.example', 'popup')).resolves.toHaveLength(1);
  });
});

describe('history (SPEC F6)', () => {
  it('one entry per IOC with the final verdict', async () => {
    useClock();
    const vt = fakeAdapter('virustotal', (ioc) =>
      result('virustotal', ioc, { status: 'ok', verdict: ioc.value.startsWith('bad') ? 'malicious' : 'clean', headline: '' }),
    );
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('bad.example good.example bad.example', 'context_menu');
    const hist = await listHistory();
    expect(hist.map((e) => [e.value, e.verdict, e.origin]).sort()).toEqual([
      ['bad.example', 'malicious', 'context_menu'],
      ['good.example', 'clean', 'context_menu'],
    ]);
  });

  it('a queued IOC is recorded and updated when it completes', async () => {
    useClock();
    const vt = fakeAdapter('virustotal', (ioc) => result('virustotal', ioc, { status: 'ok', verdict: 'malicious', headline: '' }));
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('a.example b.example c.example d.example e.example', 'popup');
    expect((await listHistory()).find((e) => e.value === 'e.example')?.verdict).toBe('unknown');
    await vi.advanceTimersByTimeAsync(60_000);
    expect((await listHistory()).find((e) => e.value === 'e.example')?.verdict).toBe('malicious');
    expect(await listHistory()).toHaveLength(5);
  });

  it('nothing is written when history is off', async () => {
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter], { settings: { historyEnabled: false } });
    await h.engine.lookup('evil.example', 'popup');
    expect(await listHistory()).toEqual([]);
  });
});

describe('duplicates and file hashes', () => {
  it('does not start an IOC twice while it is still running', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const vt = fakeAdapter('virustotal', async (ioc) => {
      await gate;
      return result('virustotal', ioc, { status: 'ok', verdict: 'clean', headline: '' });
    });
    const h = await makeEngine([vt.adapter]);
    const first = h.engine.lookup('evil.example', 'popup');
    await vi.waitFor(() => expect(vt.lookup).toHaveBeenCalledTimes(1));
    await h.engine.lookup('evil.example', 'popup');
    release();
    await first;
    expect(vt.lookup).toHaveBeenCalledTimes(1);
  });

  it('lookupHash looks up the SHA-256 with origin "file"', async () => {
    const mb = fakeAdapter('malwarebazaar');
    const h = await makeEngine([mb.adapter]);
    const sha = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
    await h.engine.lookupHash(sha);
    expect(mb.lookup.mock.calls[0]![0]).toEqual({ raw: sha.toLowerCase(), value: sha.toLowerCase(), type: 'sha256' });
    expect((await listHistory())[0]).toMatchObject({ type: 'sha256', origin: 'file' });
    expect(h.engine.getState().items).toHaveLength(1);
  });
});

describe('persistence (storage.session)', () => {
  it('state never contains an API key', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('a.example b.example c.example d.example e.example', 'popup');
    await h.engine.flush();
    const json = JSON.stringify(h.saved);
    expect(h.saved.length).toBeGreaterThan(0);
    expect(json).not.toContain('vt-secret-key-123');
    expect(json).not.toContain('secret');
  });

  it('a restarted engine resumes queued jobs from saved state', async () => {
    useClock();
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    await h.engine.lookup('a.example b.example c.example d.example e.example f.example', 'popup');
    await h.engine.flush();
    const state = h.saved.at(-1)!;
    expect(state.queue.jobs.map((j) => j.payload.ioc.value)).toEqual(['e.example', 'f.example']);

    // Simulate the event page being suspended and restarted.
    vi.clearAllTimers();
    const vt2 = fakeAdapter('virustotal');
    const h2 = await makeEngine([vt2.adapter], { initialState: JSON.parse(JSON.stringify(state)) });
    expect(h2.engine.getState().items).toHaveLength(6);
    expect(statusOf(h2, dom('e.example'), 'virustotal')).toBe('queued');

    await vi.advanceTimersByTimeAsync(60_000);
    expect(vt2.lookup.mock.calls.map((c) => c[0].value)).toEqual(['e.example', 'f.example']);
    expect(h2.engine.getState().reports.every((r: IocReport) => r.summary.pending === 0)).toBe(true);
  });

  it('requests in flight when the page stopped are re-queued on restore', async () => {
    useClock();
    const ioc = dom('evil.example');
    const loading = result('virustotal', ioc, { status: 'loading', headline: '' });
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter], {
      initialState: {
        v: 1,
        queue: { v: 1, jobs: [] },
        limiter: { v: 1, sources: {} },
        reports: [{ ioc, results: [loading], summary: { verdict: 'unknown', flagged: 0, total: 0, pending: 1 } }],
        items: [{ kind: 'ioc', ioc }],
      },
    });
    expect(statusOf(h, ioc, 'virustotal')).toBe('queued');
    await vi.advanceTimersByTimeAsync(0);
    expect(statusOf(h, ioc, 'virustotal')).toBe('ok');
  });

  it('invalid saved state starts empty', async () => {
    for (const bad of [undefined, null, 'x', { v: 2 }]) {
      const h = await makeEngine([fakeAdapter('virustotal').adapter], { initialState: bad });
      expect(h.engine.getState()).toEqual({ items: [], reports: [] });
    }
  });

  it('getState returns the current view in input order', async () => {
    const h = await makeEngine([fakeAdapter('virustotal').adapter]);
    await h.engine.lookup('b.example 10.0.0.1 a.example', 'popup');
    const st = h.engine.getState();
    expect(st.items.map((i) => i.kind)).toEqual(['ioc', 'private', 'ioc']);
    expect(st.reports.map((r) => r.ioc.value)).toEqual(['b.example', 'a.example']);
  });
});

it('Engine.create uses defaults without throwing (fakeBrowser)', async () => {
  const e = await Engine.create();
  expect(e.getState()).toEqual({ items: [], reports: [] });
});

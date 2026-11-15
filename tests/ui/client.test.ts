import { describe, expect, it, vi } from 'vitest';
import type { IocReport } from '../../src/lib/types';
import { fakeClient } from '../helpers/port';

const ioc = { raw: 'x', value: 'evil.example', type: 'domain' as const };
const report = (pending: number): IocReport => ({ ioc, results: [], summary: { verdict: 'unknown', flagged: 0, total: 0, pending } });

describe('LookupClient', () => {
  it('queues messages until connected, then sends them', () => {
    const f = fakeClient();
    f.client.send({ type: 'getState' });
    expect(f.sent).toEqual([]);
    f.client.connect();
    expect(f.sent).toEqual([{ type: 'getState' }]);
  });

  it('applies state, parsed and report messages', () => {
    const f = fakeClient();
    f.client.connect();
    const states: unknown[] = [];
    f.client.subscribe((s) => states.push(s));
    f.push({ type: 'state', items: [{ kind: 'ioc', ioc }], reports: [report(1)] });
    expect(f.client.state.connected).toBe(true);
    expect(f.client.state.reports['domain|evil.example']!.summary.pending).toBe(1);
    f.push({ type: 'report', report: report(0) });
    expect(f.client.currentReports()[0]!.report!.summary.pending).toBe(0);
    f.push({ type: 'parsed', items: [] });
    expect(f.client.state.items).toEqual([]);
    expect(states).toHaveLength(3);
  });

  it('shows background errors and clears them on the next result', () => {
    const f = fakeClient();
    f.client.connect();
    f.push({ type: 'error', message: 'Invalid request' });
    expect(f.client.state.error).toBe('Invalid request');
    f.push({ type: 'parsed', items: [] });
    expect(f.client.state.error).toBeUndefined();
  });

  it('reconnects when the background restarts', () => {
    vi.useFakeTimers();
    const f = fakeClient();
    f.client.connect();
    f.drop();
    expect(f.client.state.connected).toBe(false);
    vi.advanceTimersByTime(300);
    expect(f.connects()).toBe(2);
  });

  it('does not reconnect after close()', () => {
    vi.useFakeTimers();
    const f = fakeClient();
    f.client.connect();
    f.client.close();
    f.drop();
    vi.advanceTimersByTime(5000);
    expect(f.connects()).toBe(1);
  });
});

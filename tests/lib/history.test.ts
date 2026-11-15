import { describe, expect, it, vi } from 'vitest';
import { MAX_HISTORY_ENTRIES } from '../../src/lib/constants';
import { HISTORY_KEY, addHistory, clearHistory, listHistory, purgeHistory } from '../../src/lib/history';
import type { Ioc } from '../../src/lib/types';

const ON = { historyEnabled: true };
const OFF = { historyEnabled: false };
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 10, 15, 12, 0, 0);
const d = (value: string): Ioc => ({ raw: value, value, type: 'domain' });

describe('add and list', () => {
  it('adds entries and lists them newest first', async () => {
    await addHistory(d('a.example'), 'clean', 'popup', ON, T0);
    await addHistory(d('b.example'), 'malicious', 'context_menu', ON, T0 + 1000);
    await addHistory({ value: 'e3b0', type: 'sha256' }, 'unknown', 'file', ON, T0 + 2000);
    expect(await listHistory()).toEqual([
      { value: 'e3b0', type: 'sha256', verdict: 'unknown', timestamp: T0 + 2000, origin: 'file' },
      { value: 'b.example', type: 'domain', verdict: 'malicious', timestamp: T0 + 1000, origin: 'context_menu' },
      { value: 'a.example', type: 'domain', verdict: 'clean', timestamp: T0, origin: 'popup' },
    ]);
  });

  it('uses Date.now() by default (fake timers)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    await addHistory(d('a.example'), 'clean', 'popup', ON);
    expect((await listHistory())[0]?.timestamp).toBe(T0);
  });

  it('a repeat lookup updates the entry and moves it to the top', async () => {
    await addHistory(d('a.example'), 'unknown', 'popup', ON, T0);
    await addHistory(d('b.example'), 'clean', 'popup', ON, T0 + 1);
    await addHistory(d('a.example'), 'malicious', 'context_menu', ON, T0 + 2);
    const list = await listHistory();
    expect(list).toHaveLength(2);
    expect(list[0]).toMatchObject({ value: 'a.example', verdict: 'malicious', origin: 'context_menu' });
  });

  it('same value with a different type is a separate entry', async () => {
    await addHistory({ value: '1.2.3.4', type: 'ipv4' }, 'clean', 'popup', ON, T0);
    await addHistory({ value: '1.2.3.4', type: 'domain' }, 'clean', 'popup', ON, T0);
    expect(await listHistory()).toHaveLength(2);
  });

  it('concurrent adds are all kept', async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => addHistory(d(`h${i}.example`), 'clean', 'popup', ON, T0 + i)));
    expect(await listHistory()).toHaveLength(20);
  });

  it(`keeps at most ${MAX_HISTORY_ENTRIES} entries, dropping the oldest`, async () => {
    const entries = Array.from({ length: MAX_HISTORY_ENTRIES }, (_, i) => ({
      value: `h${i}.example`,
      type: 'domain',
      verdict: 'clean',
      timestamp: T0 + i,
      origin: 'popup',
    }));
    await browser.storage.local.set({ [HISTORY_KEY]: entries });
    await addHistory(d('new.example'), 'clean', 'popup', ON, T0 + MAX_HISTORY_ENTRIES);
    const list = await listHistory();
    expect(list).toHaveLength(MAX_HISTORY_ENTRIES);
    expect(list[0]?.value).toBe('new.example');
    expect(list.some((e) => e.value === 'h0.example')).toBe(false);
  });
});

describe('history off', () => {
  it('nothing is written', async () => {
    expect(await addHistory(d('a.example'), 'clean', 'popup', OFF, T0)).toBe(false);
    expect(await listHistory()).toEqual([]);
    expect(await browser.storage.local.get(null)).toEqual({});
  });
});

describe('purge (retention)', () => {
  it('removes entries older than 7 days (fake timers)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    await addHistory(d('old.example'), 'clean', 'popup', ON, T0 - 7 * DAY - 1);
    await addHistory(d('edge.example'), 'clean', 'popup', ON, T0 - 7 * DAY);
    await addHistory(d('new.example'), 'clean', 'popup', ON, T0 - DAY);

    expect(await purgeHistory(7)).toBe(1);
    expect((await listHistory()).map((e) => e.value)).toEqual(['new.example', 'edge.example']);
  });

  it('respects a custom retention', async () => {
    await addHistory(d('a.example'), 'clean', 'popup', ON, T0 - 2 * DAY);
    expect(await purgeHistory(1, T0)).toBe(1);
    expect(await listHistory()).toEqual([]);
  });

  it('drops entries dated in the far future (clock moved back)', async () => {
    await addHistory(d('future.example'), 'clean', 'popup', ON, T0 + 10 * DAY);
    expect(await purgeHistory(7, T0)).toBe(1);
  });

  it('nothing to purge → 0, storage untouched', async () => {
    await addHistory(d('a.example'), 'clean', 'popup', ON, T0);
    expect(await purgeHistory(7, T0)).toBe(0);
  });
});

describe('clear and robustness', () => {
  it('clearHistory removes everything and only history', async () => {
    await addHistory(d('a.example'), 'clean', 'popup', ON, T0);
    await browser.storage.local.set({ settings: {} });
    await clearHistory();
    expect(await listHistory()).toEqual([]);
    expect(Object.keys(await browser.storage.local.get(null))).toEqual(['settings']);
  });

  it('skips corrupted entries', async () => {
    await browser.storage.local.set({
      [HISTORY_KEY]: [
        { value: 'ok.example', type: 'domain', verdict: 'clean', timestamp: T0, origin: 'popup' },
        { value: 'x', type: 'email', verdict: 'clean', timestamp: T0, origin: 'popup' },
        { value: 'y', type: 'domain', verdict: 'maybe', timestamp: T0, origin: 'popup' },
        'garbage',
        null,
      ],
    });
    expect((await listHistory()).map((e) => e.value)).toEqual(['ok.example']);
  });

  it('a non-array stored value reads as empty', async () => {
    await browser.storage.local.set({ [HISTORY_KEY]: { not: 'an array' } });
    expect(await listHistory()).toEqual([]);
  });
});

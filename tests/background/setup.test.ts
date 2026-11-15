import { describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { DRAIN_ALARM, type Engine } from '../../src/background/engine';
import { PURGE_ALARM, purge } from '../../src/background/maintenance';
import { setupBackground } from '../../src/background/setup';
import { putCached } from '../../src/lib/cache';
import { addHistory, listHistory } from '../../src/lib/history';
import { result } from '../../src/lib/sources/common';

const T0 = Date.UTC(2026, 10, 15, 12, 0, 0);
const DAY = 86_400_000;

function stubConnect() {
  // fakeBrowser implements neither runtime ports nor context menus.
  vi.spyOn(browser.contextMenus.onClicked, 'addListener').mockImplementation(() => undefined);
  vi.spyOn(browser.downloads.onChanged, 'addListener').mockImplementation(() => undefined);
  vi.spyOn(browser.notifications.onClicked, 'addListener').mockImplementation(() => undefined);
  return vi.spyOn(browser.runtime.onConnect, 'addListener').mockImplementation(() => undefined);
}

describe('setupBackground', () => {
  it('registers a port listener and a daily purge alarm', async () => {
    const connect = stubConnect();
    const drain = vi.fn(async () => undefined);
    setupBackground(async () => ({ drain }) as unknown as Engine);
    expect(connect).toHaveBeenCalledTimes(1);
    await vi.waitFor(async () => expect(await browser.alarms.get(PURGE_ALARM)).toMatchObject({ periodInMinutes: 1440 }));
  });

  it('registers the context menu click handler and creates the menu on install', async () => {
    stubConnect();
    const onClicked = vi.mocked(browser.contextMenus.onClicked.addListener);
    const create = vi.spyOn(browser.contextMenus, 'create').mockImplementation(() => 'id');
    vi.spyOn(browser.contextMenus, 'removeAll').mockResolvedValue(undefined);
    setupBackground(async () => ({ drain: vi.fn() }) as unknown as Engine);
    expect(onClicked).toHaveBeenCalledTimes(1);
    await fakeBrowser.runtime.onInstalled.trigger({ reason: 'install', temporary: false } as Parameters<typeof fakeBrowser.runtime.onInstalled.trigger>[0]);
    await vi.waitFor(() =>
      expect(create).toHaveBeenCalledWith({ id: 'cyberbud-check', title: 'Check reputation', contexts: ['selection', 'link', 'page'] }),
    );
  });

  it('registers the download and notification listeners', () => {
    stubConnect();
    setupBackground(async () => ({ drain: vi.fn() }) as unknown as Engine);
    expect(browser.downloads.onChanged.addListener).toHaveBeenCalledTimes(1);
    expect(browser.notifications.onClicked.addListener).toHaveBeenCalledTimes(1);
  });

  it('the drain alarm wakes the engine', async () => {
    stubConnect();
    const drain = vi.fn(async () => undefined);
    setupBackground(async () => ({ drain }) as unknown as Engine);
    const alarm = { name: DRAIN_ALARM, scheduledTime: Date.now() } as Parameters<typeof fakeBrowser.alarms.onAlarm.trigger>[0];
    await fakeBrowser.alarms.onAlarm.trigger(alarm);
    await vi.waitFor(() => expect(drain).toHaveBeenCalledTimes(1));
  });
});

describe('purge (SPEC F6: on startup and daily)', () => {
  it('removes expired cache entries and old history', async () => {
    const ioc = { raw: 'a.example', value: 'a.example', type: 'domain' as const };
    await putCached(result('virustotal', ioc, { status: 'ok', verdict: 'clean', headline: '', fetchedAt: T0 - 2 * DAY }));
    await putCached(result('urlhaus', ioc, { status: 'ok', verdict: 'clean', headline: '', fetchedAt: T0 - 1000 }));
    await addHistory(ioc, 'clean', 'popup', { historyEnabled: true }, T0 - 8 * DAY);
    await addHistory({ value: 'b.example', type: 'domain' }, 'clean', 'popup', { historyEnabled: true }, T0 - DAY);

    expect(await purge(T0)).toEqual({ cache: 1, history: 1 });
    expect((await listHistory()).map((e) => e.value)).toEqual(['b.example']);
  });
});

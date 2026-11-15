// Background wiring. All listeners are registered synchronously at startup,
// as MV3 event pages require (events that wake the page must find them).
import { DRAIN_ALARM, Engine, defaultDeps } from './engine';
import { PURGE_ALARM, ensurePurgeAlarm, purge } from './maintenance';
import { attachPort, type PortLike } from './messaging';

export function setupBackground(createEngine: () => Promise<Engine> = () => Engine.create(defaultDeps())): {
  engine: Promise<Engine>;
} {
  const engine = createEngine();

  browser.runtime.onConnect.addListener((port) => {
    attachPort(port as unknown as PortLike, engine, browser.runtime.id);
  });

  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === DRAIN_ALARM) void engine.then((e) => e.drain());
    else if (alarm.name === PURGE_ALARM) void purge().catch(() => undefined);
  });

  void purge().catch(() => undefined);
  void ensurePurgeAlarm().catch(() => undefined);
  return { engine };
}

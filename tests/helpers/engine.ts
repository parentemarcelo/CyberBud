import { vi } from 'vitest';
import { Engine, type EngineDeps, type EngineState } from '../../src/background/engine';
import { RATE_LIMITS } from '../../src/lib/constants';
import { defaultSettings, type Settings } from '../../src/lib/settings';
import { result } from '../../src/lib/sources/common';
import type { SourcePlan } from '../../src/lib/sources/registry';
import type { Ioc, KeyId, ResponseMessage, SourceAdapter, SourceId, SourceResult } from '../../src/lib/types';

const KEY_OF: Record<SourceId, KeyId> = {
  virustotal: 'vt',
  abuseipdb: 'abuseipdb',
  urlhaus: 'abusech',
  malwarebazaar: 'abusech',
  threatfox: 'abusech',
};

export type LookupImpl = (ioc: Ioc, apiKey: string) => Promise<SourceResult> | SourceResult;

export function fakeAdapter(id: SourceId, impl?: LookupImpl) {
  const lookup = vi.fn(async (ioc: Ioc, apiKey: string) =>
    impl ? impl(ioc, apiKey) : result(id, ioc, { status: 'ok', verdict: 'clean', headline: `${id} ok` }),
  );
  const adapter: SourceAdapter = {
    id,
    name: id,
    keyId: KEY_OF[id],
    limits: RATE_LIMITS[id],
    supports: () => true,
    lookup,
    testKey: vi.fn(async () => 'ok' as const),
  };
  return { adapter, lookup };
}

export interface Harness {
  engine: Engine;
  messages: ResponseMessage[];
  saved: EngineState[];
  settings: Settings;
  alarm: ReturnType<typeof vi.fn>;
  deps: EngineDeps;
}

/** Engine with the given fake adapters, all keys set, in-memory session state. */
export async function makeEngine(
  adapters: SourceAdapter[],
  opts: { settings?: Partial<Settings>; initialState?: unknown; saved?: EngineState[] } = {},
): Promise<Harness> {
  const settings: Settings = {
    ...defaultSettings(),
    keys: { vt: 'vt-secret-key-123', abuseipdb: 'ab-secret-key-123', abusech: 'ac-secret-key-123' },
    ...opts.settings,
  };
  const saved = opts.saved ?? [];
  const alarm = vi.fn(async () => undefined);
  const deps: EngineDeps = {
    getSettings: async () => settings,
    adaptersFor: (_ioc, s): SourcePlan => ({
      runnable: adapters
        .filter((a) => s.enabledSources[a.id] && s.keys[a.keyId] !== '')
        .map((adapter) => ({ adapter, apiKey: s.keys[adapter.keyId] })),
      placeholders: adapters
        .filter((a) => !s.enabledSources[a.id] || s.keys[a.keyId] === '')
        .map((a) => result(a.id, _ioc, { status: s.enabledSources[a.id] ? 'no_key' : 'disabled', headline: '' })),
    }),
    keyTestAdapter: (keyId) => adapters.find((a) => a.keyId === keyId) ?? adapters[0]!,
    now: () => Date.now(),
    loadState: async () => opts.initialState,
    saveState: async (st) => {
      saved.push(structuredClone(st));
    },
    scheduleAlarm: alarm,
  };
  const engine = await Engine.create(deps);
  const messages: ResponseMessage[] = [];
  engine.subscribe((m) => messages.push(m));
  return { engine, messages, saved, settings, alarm, deps };
}

export const statusOf = (h: Harness, ioc: Pick<Ioc, 'type' | 'value'>, source: SourceId) =>
  h.engine.getReport(ioc)?.results.find((r) => r.source === source)?.status;

// User settings (docs/SPEC.md F5), stored in storage.local (never sync).
// Reads always go through normalize(), so stored data from older versions,
// partial writes or manual edits can never produce an invalid Settings.
import { DEFAULT_RISKY_EXTENSIONS } from './constants';
import { createMutex } from './mutex';
import {
  DOWNLOAD_PROMPT_MODES,
  KEY_IDS,
  SOURCE_IDS,
  URL_PRIVACY_MODES,
  type DownloadPromptMode,
  type KeyId,
  type SourceId,
  type UrlPrivacyMode,
} from './types';

export const SETTINGS_KEY = 'settings';

export interface Settings {
  /** API keys by slot. Empty string = not set. */
  keys: Record<KeyId, string>;
  enabledSources: Record<SourceId, boolean>;
  urlMode: UrlPrivacyMode;
  downloadPrompt: DownloadPromptMode;
  /** Lowercase, no dot. */
  riskyExtensions: string[];
  /** 0 disables the cache. */
  cacheTtlHours: number;
  historyEnabled: boolean;
  historyRetentionDays: number;
}

export type SettingsPatch = Partial<Omit<Settings, 'keys' | 'enabledSources'>> & {
  keys?: Partial<Settings['keys']>;
  enabledSources?: Partial<Settings['enabledSources']>;
};

export const CACHE_TTL_HOURS_MAX = 24 * 30;
export const HISTORY_RETENTION_DAYS_MIN = 1;
export const HISTORY_RETENTION_DAYS_MAX = 365;

export function defaultSettings(): Settings {
  return {
    keys: { vt: '', abuseipdb: '', abusech: '' },
    enabledSources: { virustotal: true, abuseipdb: true, urlhaus: true, malwarebazaar: true, threatfox: true },
    urlMode: 'strip',
    downloadPrompt: 'risky',
    riskyExtensions: [...DEFAULT_RISKY_EXTENSIONS],
    cacheTtlHours: 24,
    historyEnabled: true,
    historyRetentionDays: 7,
  };
}

/** Build a valid Settings from anything: unknown or invalid fields fall back to defaults. */
export function normalize(stored: unknown): Settings {
  const d = defaultSettings();
  const s = isRecord(stored) ? stored : {};
  const keys = isRecord(s.keys) ? s.keys : {};
  const enabled = isRecord(s.enabledSources) ? s.enabledSources : {};

  return {
    keys: Object.fromEntries(
      KEY_IDS.map((k) => [k, typeof keys[k] === 'string' ? (keys[k] as string).trim() : d.keys[k]]),
    ) as Settings['keys'],
    enabledSources: Object.fromEntries(
      SOURCE_IDS.map((id) => [id, typeof enabled[id] === 'boolean' ? enabled[id] : d.enabledSources[id]]),
    ) as Settings['enabledSources'],
    urlMode: oneOf(s.urlMode, URL_PRIVACY_MODES, d.urlMode),
    downloadPrompt: oneOf(s.downloadPrompt, DOWNLOAD_PROMPT_MODES, d.downloadPrompt),
    riskyExtensions: Array.isArray(s.riskyExtensions)
      ? cleanExtensions(s.riskyExtensions.filter((x): x is string => typeof x === 'string'))
      : d.riskyExtensions,
    cacheTtlHours: intInRange(s.cacheTtlHours, 0, CACHE_TTL_HOURS_MAX, d.cacheTtlHours),
    historyEnabled: typeof s.historyEnabled === 'boolean' ? s.historyEnabled : d.historyEnabled,
    historyRetentionDays: intInRange(
      s.historyRetentionDays,
      HISTORY_RETENTION_DAYS_MIN,
      HISTORY_RETENTION_DAYS_MAX,
      d.historyRetentionDays,
    ),
  };
}

export async function getSettings(): Promise<Settings> {
  const stored = await browser.storage.local.get(SETTINGS_KEY);
  return normalize(stored[SETTINGS_KEY]);
}

const exclusive = createMutex();

/** Merge a partial update (keys and enabledSources merge per field) and persist. */
export function updateSettings(patch: SettingsPatch): Promise<Settings> {
  return exclusive(async () => {
    const current = await getSettings();
    const next = normalize({
      ...current,
      ...patch,
      keys: { ...current.keys, ...patch.keys },
      enabledSources: { ...current.enabledSources, ...patch.enabledSources },
    });
    await browser.storage.local.set({ [SETTINGS_KEY]: next });
    return next;
  });
}

/** Restore defaults. API keys are kept unless `includeKeys` is true. */
export function resetSettings({ includeKeys = false } = {}): Promise<Settings> {
  return exclusive(async () => {
    const current = await getSettings();
    const next = defaultSettings();
    if (!includeKeys) next.keys = current.keys;
    await browser.storage.local.set({ [SETTINGS_KEY]: next });
    return next;
  });
}

/** Calls `listener` with the new settings whenever they change in any extension context. */
export function subscribeSettings(listener: (settings: Settings) => void): () => void {
  const handler = (changes: Record<string, { newValue?: unknown }>, area: string) => {
    if (area === 'local' && SETTINGS_KEY in changes) listener(normalize(changes[SETTINGS_KEY]!.newValue));
  };
  browser.storage.onChanged.addListener(handler);
  return () => browser.storage.onChanged.removeListener(handler);
}

/** Parse the comma/space separated "risky extensions" text field. */
export function parseExtensionList(text: string): string[] {
  return cleanExtensions(text.split(/[\s,;]+/));
}

function cleanExtensions(list: readonly string[]): string[] {
  const out = new Set<string>();
  for (const raw of list) {
    const ext = raw.trim().toLowerCase().replace(/^\.+/, '');
    if (/^[a-z0-9]{1,16}$/.test(ext)) out.add(ext);
  }
  return [...out];
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function oneOf<T extends string>(x: unknown, allowed: readonly T[], fallback: T): T {
  return typeof x === 'string' && (allowed as readonly string[]).includes(x) ? (x as T) : fallback;
}

function intInRange(x: unknown, min: number, max: number, fallback: number): number {
  if (typeof x !== 'number' || !Number.isFinite(x)) return fallback;
  return Math.min(max, Math.max(min, Math.round(x)));
}

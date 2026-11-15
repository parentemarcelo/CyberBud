import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_RISKY_EXTENSIONS } from '../../src/lib/constants';
import {
  SETTINGS_KEY,
  defaultSettings,
  getSettings,
  normalize,
  parseExtensionList,
  resetSettings,
  subscribeSettings,
  updateSettings,
} from '../../src/lib/settings';

describe('defaults (SPEC F5)', () => {
  it('first run returns the SPEC defaults', async () => {
    const s = await getSettings();
    expect(s).toEqual({
      keys: { vt: '', abuseipdb: '', abusech: '' },
      enabledSources: { virustotal: true, abuseipdb: true, urlhaus: true, malwarebazaar: true, threatfox: true },
      urlMode: 'strip',
      downloadPrompt: 'risky',
      riskyExtensions: [...DEFAULT_RISKY_EXTENSIONS],
      cacheTtlHours: 24,
      historyEnabled: true,
      historyRetentionDays: 7,
    });
  });

  it('defaultSettings returns a fresh object each time', () => {
    const a = defaultSettings();
    a.riskyExtensions.push('xyz');
    a.keys.vt = 'changed';
    expect(defaultSettings().riskyExtensions).not.toContain('xyz');
    expect(defaultSettings().keys.vt).toBe('');
  });
});

describe('persistence', () => {
  it('values persist in storage.local, never storage.sync', async () => {
    await updateSettings({ urlMode: 'full', keys: { vt: 'k1' } });
    expect((await getSettings()).urlMode).toBe('full');
    const raw = await browser.storage.local.get(SETTINGS_KEY);
    expect(raw[SETTINGS_KEY]).toMatchObject({ urlMode: 'full', keys: { vt: 'k1' } });
    expect(await browser.storage.sync.get(null)).toEqual({});
  });

  it('keys and enabledSources merge per field', async () => {
    await updateSettings({ keys: { vt: 'vt-key' }, enabledSources: { urlhaus: false } });
    await updateSettings({ keys: { abusech: 'ac-key' }, enabledSources: { threatfox: false } });
    const s = await getSettings();
    expect(s.keys).toEqual({ vt: 'vt-key', abuseipdb: '', abusech: 'ac-key' });
    expect(s.enabledSources).toMatchObject({ virustotal: true, urlhaus: false, threatfox: false });
  });

  it('trims API keys', async () => {
    expect((await updateSettings({ keys: { vt: '  abc \n' } })).keys.vt).toBe('abc');
  });

  it('concurrent updates do not lose writes', async () => {
    await Promise.all([
      updateSettings({ keys: { vt: 'a' } }),
      updateSettings({ keys: { abuseipdb: 'b' } }),
      updateSettings({ keys: { abusech: 'c' } }),
      updateSettings({ urlMode: 'domain' }),
    ]);
    const s = await getSettings();
    expect(s.keys).toEqual({ vt: 'a', abuseipdb: 'b', abusech: 'c' });
    expect(s.urlMode).toBe('domain');
  });

  it('resetSettings keeps keys unless asked', async () => {
    await updateSettings({ keys: { vt: 'keep' }, urlMode: 'full' });
    let s = await resetSettings();
    expect(s.urlMode).toBe('strip');
    expect(s.keys.vt).toBe('keep');
    s = await resetSettings({ includeKeys: true });
    expect(s.keys.vt).toBe('');
  });
});

describe('migration-safe normalize', () => {
  it('fills missing fields from defaults', async () => {
    await browser.storage.local.set({ [SETTINGS_KEY]: { urlMode: 'full' } });
    const s = await getSettings();
    expect(s.urlMode).toBe('full');
    expect(s.cacheTtlHours).toBe(24);
    expect(s.keys).toEqual({ vt: '', abuseipdb: '', abusech: '' });
  });

  it.each([null, undefined, 'garbage', 42, [], { keys: 'x', enabledSources: [1] }])(
    'invalid stored value %j → defaults',
    (stored) => {
      expect(normalize(stored)).toEqual(defaultSettings());
    },
  );

  it('rejects invalid enum values and wrong types per field', () => {
    const s = normalize({
      urlMode: 'everything',
      downloadPrompt: 'sometimes',
      historyEnabled: 'yes',
      keys: { vt: 123, abuseipdb: 'ok' },
      enabledSources: { virustotal: 'no', urlhaus: false },
      unknownField: true,
    });
    expect(s.urlMode).toBe('strip');
    expect(s.downloadPrompt).toBe('risky');
    expect(s.historyEnabled).toBe(true);
    expect(s.keys).toEqual({ vt: '', abuseipdb: 'ok', abusech: '' });
    expect(s.enabledSources.virustotal).toBe(true);
    expect(s.enabledSources.urlhaus).toBe(false);
    expect(s).not.toHaveProperty('unknownField');
  });

  it('clamps numbers into range and rounds them', () => {
    expect(normalize({ cacheTtlHours: -5 }).cacheTtlHours).toBe(0);
    expect(normalize({ cacheTtlHours: 1e9 }).cacheTtlHours).toBe(720);
    expect(normalize({ cacheTtlHours: 2.6 }).cacheTtlHours).toBe(3);
    expect(normalize({ cacheTtlHours: Number.NaN }).cacheTtlHours).toBe(24);
    expect(normalize({ historyRetentionDays: 0 }).historyRetentionDays).toBe(1);
    expect(normalize({ historyRetentionDays: 5000 }).historyRetentionDays).toBe(365);
    expect(normalize({ historyRetentionDays: '7' }).historyRetentionDays).toBe(7);
  });

  it('cleans the risky extension list', () => {
    expect(normalize({ riskyExtensions: ['.EXE', 'exe', 'zip', 'bad ext', 42, '', '7z'] }).riskyExtensions).toEqual([
      'exe',
      'zip',
      '7z',
    ]);
    expect(normalize({ riskyExtensions: [] }).riskyExtensions).toEqual([]);
  });
});

describe('subscribeSettings', () => {
  it('fires with normalized settings on change, and stops after unsubscribe', async () => {
    const listener = vi.fn();
    const unsubscribe = subscribeSettings(listener);
    await updateSettings({ urlMode: 'domain' });
    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener.mock.lastCall?.[0]).toMatchObject({ urlMode: 'domain', cacheTtlHours: 24 });

    unsubscribe();
    await updateSettings({ urlMode: 'full' });
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('ignores changes to other keys and other areas', async () => {
    const listener = vi.fn();
    subscribeSettings(listener);
    await browser.storage.local.set({ other: 1 });
    await browser.storage.session.set({ [SETTINGS_KEY]: {} });
    expect(listener).not.toHaveBeenCalled();
  });
});

describe('parseExtensionList', () => {
  it('accepts commas, spaces, dots and mixed case', () => {
    expect(parseExtensionList('.EXE, msi;  zip\n.7z, exe, , ')).toEqual(['exe', 'msi', 'zip', '7z']);
  });
});

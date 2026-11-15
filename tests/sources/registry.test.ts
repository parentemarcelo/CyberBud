import { afterEach, describe, expect, it, vi } from 'vitest';
import { HOST_PERMISSIONS } from '../../wxt.config';
import { defaultSettings, type Settings } from '../../src/lib/settings';
import { ADAPTERS, SOURCE_API_ORIGINS, adaptersFor } from '../../src/lib/sources/registry';
import { IOC_TYPES, SOURCE_IDS, type Ioc, type IocType, type SourceId } from '../../src/lib/types';
import { jsonResponse, mockFetch } from '../helpers/fetch';

afterEach(() => vi.unstubAllGlobals());

const ioc = (type: IocType): Ioc => ({ raw: 'x', value: 'x', type });
const withKeys = (): Settings => ({ ...defaultSettings(), keys: { vt: 'vt-key', abuseipdb: 'ab-key', abusech: 'ac-key' } });
const ids = (s: Settings, type: IocType) => adaptersFor(ioc(type), s).runnable.map((r) => r.adapter.id);

describe('type → sources matrix (all keys set, all enabled)', () => {
  it.each<[IocType, SourceId[]]>([
    ['ipv4', ['virustotal', 'abuseipdb', 'urlhaus', 'threatfox']],
    ['ipv6', ['virustotal', 'abuseipdb', 'threatfox']],
    ['domain', ['virustotal', 'urlhaus', 'threatfox']],
    ['url', ['virustotal', 'urlhaus', 'threatfox']],
    ['sha256', ['virustotal', 'malwarebazaar', 'threatfox']],
    ['md5', ['virustotal', 'malwarebazaar', 'threatfox']],
    ['sha1', ['virustotal', 'malwarebazaar', 'threatfox']],
  ])('%s → %j', (type, expected) => {
    expect(ids(withKeys(), type)).toEqual(expected);
    expect(adaptersFor(ioc(type), withKeys()).placeholders).toEqual([]);
  });

  it('every IOC type has at least one source', () => {
    for (const t of IOC_TYPES) expect(ids(withKeys(), t).length).toBeGreaterThan(0);
  });
});

describe('placeholders', () => {
  it('a missing key gives a no_key result', () => {
    const s = withKeys();
    s.keys.abuseipdb = '';
    const plan = adaptersFor(ioc('ipv4'), s);
    expect(plan.runnable.map((r) => r.adapter.id)).toEqual(['virustotal', 'urlhaus', 'threatfox']);
    expect(plan.placeholders).toEqual([
      expect.objectContaining({ source: 'abuseipdb', status: 'no_key', verdict: 'unknown', headline: 'No API key set' }),
    ]);
  });

  it('one missing abuse.ch key affects all three abuse.ch sources', () => {
    const s = withKeys();
    s.keys.abusech = '  ';
    const plan = adaptersFor(ioc('sha256'), s);
    expect(plan.runnable.map((r) => r.adapter.id)).toEqual(['virustotal']);
    expect(plan.placeholders.map((p) => [p.source, p.status])).toEqual([
      ['malwarebazaar', 'no_key'],
      ['threatfox', 'no_key'],
    ]);
  });

  it('a disabled source gives a disabled result, even without a key', () => {
    const s = withKeys();
    s.enabledSources.virustotal = false;
    s.keys.vt = '';
    expect(adaptersFor(ioc('domain'), s).placeholders).toEqual([
      expect.objectContaining({ source: 'virustotal', status: 'disabled' }),
    ]);
  });

  it('first run (no keys) → only no_key placeholders', () => {
    const plan = adaptersFor(ioc('ipv4'), defaultSettings());
    expect(plan.runnable).toEqual([]);
    expect(plan.placeholders.map((p) => p.status)).toEqual(['no_key', 'no_key', 'no_key', 'no_key']);
  });

  it('unsupported sources are omitted, not placeholders', () => {
    const plan = adaptersFor(ioc('sha1'), defaultSettings());
    expect(plan.placeholders.map((p) => p.source)).not.toContain('abuseipdb');
    expect(plan.placeholders.map((p) => p.source)).toEqual(['virustotal', 'malwarebazaar', 'threatfox']);
  });

  it('passes the trimmed key for the right slot', () => {
    const s = withKeys();
    s.keys.abusech = ' ac-key ';
    const plan = adaptersFor(ioc('url'), s);
    expect(plan.runnable.map((r) => [r.adapter.id, r.apiKey])).toEqual([
      ['virustotal', 'vt-key'],
      ['urlhaus', 'ac-key'],
      ['threatfox', 'ac-key'],
    ]);
  });
});

describe('registry integrity', () => {
  it('has one adapter per SourceId with matching id', () => {
    expect(Object.keys(ADAPTERS).sort()).toEqual([...SOURCE_IDS].sort());
    for (const id of SOURCE_IDS) expect(ADAPTERS[id].id).toBe(id);
  });

  it('API origins match the manifest host_permissions (SPEC §9 S1)', () => {
    expect(SOURCE_API_ORIGINS.map((o) => `${o}/*`).sort()).toEqual([...HOST_PERMISSIONS].sort());
  });

  it('every request any adapter makes goes to a declared origin, over https', async () => {
    const { calls } = mockFetch(() => jsonResponse({}, 404));
    const samples: Ioc[] = [
      { raw: '', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'sha256' },
      { raw: '', value: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5' },
      { raw: '', value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', type: 'sha1' },
      { raw: '', value: 'evil.example', type: 'domain' },
      { raw: '', value: '1.2.3.4', type: 'ipv4' },
      { raw: '', value: '2001:db8::1', type: 'ipv6' },
      { raw: '', value: 'http://evil.example/x', type: 'url' },
    ];
    const signal = new AbortController().signal;
    for (const adapter of Object.values(ADAPTERS)) {
      for (const s of samples) if (adapter.supports(s.type)) await adapter.lookup(s, 'k-0123', signal);
      await adapter.testKey('k-0123', signal);
    }
    expect(calls.length).toBeGreaterThan(20);
    for (const c of calls) {
      const u = new URL(c.url);
      expect(u.protocol).toBe('https:');
      expect(SOURCE_API_ORIGINS).toContain(u.origin);
    }
  });
});

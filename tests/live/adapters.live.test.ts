// Live checks of every adapter against the real APIs (PLAN steps 13-17 "Manual").
// Uses your keys from docs/KEYS.md or env (see keys.ts); skips sources without a key.
// Only public, well-known IOCs are sent to VirusTotal (VT may add queried IOCs to its dataset).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { requestJson } from '../../src/lib/http';
import { ADAPTERS } from '../../src/lib/sources/registry';
import type { Ioc, IocType, SourceId, SourceResult } from '../../src/lib/types';
import { loadKeys } from './keys';

const keys = loadKeys();
const allKeys = Object.values(keys).filter((k): k is string => !!k);
const signal = () => new AbortController().signal;
const ioc = (type: IocType, value: string): Ioc => ({ raw: value, value, type });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const table: string[] = [];

async function look(source: SourceId, i: Ioc, key: string): Promise<SourceResult> {
  const r = await ADAPTERS[source].lookup(i, key, signal());
  const json = JSON.stringify(r);
  for (const k of allKeys) expect(json, 'API key leaked into a result').not.toContain(k);
  table.push(
    [source.padEnd(13), i.type.padEnd(6), r.status.padEnd(9), r.verdict.padEnd(10), r.headline.slice(0, 45).padEnd(45), r.link ?? '-'].join(' | '),
  );
  return r;
}

afterAll(() => {
  console.log(`\nLIVE RESULTS\n${table.join('\n')}`);
});

// IOCs currently listed on abuse.ch, discovered with read-only feed queries.
const live: { domain?: string; ipPort?: string; url?: string; tfMd5?: string; tfSha1?: string; tfSha256?: string; sample?: { sha256: string; sha1: string; md5: string }; uhUrl?: string; uhHost?: string } = {};

beforeAll(async () => {
  if (!keys.abusech) return;
  const k = keys.abusech;
  const tf = await requestJson({
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: { 'Auth-Key': k, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    secrets: [k],
  });
  const iocs = tf.kind === 'ok' && Array.isArray((tf.json as { data?: unknown }).data) ? ((tf.json as { data: Array<Record<string, unknown>> }).data) : [];
  live.domain = iocs.find((e) => e.ioc_type === 'domain')?.ioc as string | undefined;
  live.ipPort = iocs.find((e) => e.ioc_type === 'ip:port' && /^\d+\.\d+\.\d+\.\d+:\d+$/.test(String(e.ioc)))?.ioc as string | undefined;
  live.url = iocs.find((e) => e.ioc_type === 'url')?.ioc as string | undefined;
  live.tfMd5 = iocs.find((e) => e.ioc_type === 'md5_hash')?.ioc as string | undefined;
  live.tfSha1 = iocs.find((e) => e.ioc_type === 'sha1_hash')?.ioc as string | undefined;
  live.tfSha256 = iocs.find((e) => e.ioc_type === 'sha256_hash')?.ioc as string | undefined;

  const mb = await requestJson({
    url: 'https://mb-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: { 'Auth-Key': k },
    body: new URLSearchParams({ query: 'get_recent', selector: 'time' }),
    secrets: [k],
  });
  const s = mb.kind === 'ok' ? (mb.json as { data?: Array<Record<string, string>> }).data?.[0] : undefined;
  if (s) live.sample = { sha256: s.sha256_hash!, sha1: s.sha1_hash!, md5: s.md5_hash! };

  const uh = await requestJson({ url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/3/', headers: { 'Auth-Key': k }, secrets: [k] });
  const u = uh.kind === 'ok' ? (uh.json as { urls?: Array<Record<string, string>> }).urls?.[0] : undefined;
  if (u) {
    live.uhUrl = u.url;
    live.uhHost = u.host;
  }
  console.log('DISCOVERED', JSON.stringify({ ...live, sample: live.sample ? 'yes' : 'no' }));
});

describe.skipIf(!keys.abusech)('abuse.ch (live)', () => {
  const k = () => keys.abusech!;

  it('testKey: one key works for all three services', async () => {
    for (const id of ['urlhaus', 'malwarebazaar', 'threatfox'] as const) {
      expect(await ADAPTERS[id].testKey(k(), signal()), id).toBe('ok');
    }
  });

  it('testKey: a wrong key is reported as invalid', async () => {
    for (const id of ['urlhaus', 'malwarebazaar', 'threatfox'] as const) {
      expect(await ADAPTERS[id].testKey('invalid-key-000000000000000000000000', signal()), id).toBe('invalid');
    }
  });

  it('URLhaus: a listed URL and its host are malicious; an unlisted host is not found', async () => {
    expect(live.uhUrl, 'no recent URLhaus URL discovered').toBeTruthy();
    const url = await look('urlhaus', ioc('url', live.uhUrl!), k());
    expect(url).toMatchObject({ status: 'ok', verdict: 'malicious' });
    expect(url.link).toMatch(/^https:\/\/urlhaus\.abuse\.ch\/url\/\d+\/$/);

    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(live.uhHost!);
    const host = await look('urlhaus', ioc(isIp ? 'ipv4' : 'domain', live.uhHost!), k());
    expect(host).toMatchObject({ status: 'ok', verdict: 'malicious' });
    expect(host.link).toMatch(/^https:\/\/urlhaus\.abuse\.ch\/host\//);

    expect((await look('urlhaus', ioc('domain', 'no-such-host-cyberbud.example'), k())).status).toBe('not_found');
  });

  it('MalwareBazaar: a recent sample is found by SHA-256, SHA-1 and MD5', async () => {
    expect(live.sample, 'no recent MalwareBazaar sample discovered').toBeTruthy();
    for (const [type, value] of [['sha256', live.sample!.sha256], ['sha1', live.sample!.sha1], ['md5', live.sample!.md5]] as const) {
      const r = await look('malwarebazaar', ioc(type, value), k());
      expect(r, type).toMatchObject({ status: 'ok', verdict: 'malicious', link: `https://bazaar.abuse.ch/sample/${live.sample!.sha256}/` });
    }
    expect((await look('malwarebazaar', ioc('sha256', '0'.repeat(64)), k())).status).toBe('not_found');
  });

  it('ThreatFox: listed domain, IP (from ip:port), URL and hash are malicious', async () => {
    expect(live.domain && live.ipPort, 'no recent ThreatFox IOCs discovered').toBeTruthy();
    const d = await look('threatfox', ioc('domain', live.domain!), k());
    expect(d).toMatchObject({ status: 'ok', verdict: 'malicious' });
    expect(d.link).toMatch(/^https:\/\/threatfox\.abuse\.ch\/ioc\/\d+\/$/);

    const ip = live.ipPort!.split(':')[0]!;
    expect(await look('threatfox', ioc('ipv4', ip), k())).toMatchObject({ status: 'ok', verdict: 'malicious' });

    if (live.url) expect((await look('threatfox', ioc('url', live.url), k())).verdict).toBe('malicious');
    for (const [type, value] of [['md5', live.tfMd5], ['sha1', live.tfSha1], ['sha256', live.tfSha256]] as const) {
      if (value) expect((await look('threatfox', ioc(type, value), k())).verdict, type).toBe('malicious');
    }

    expect((await look('threatfox', ioc('domain', 'no-such-host-cyberbud.example'), k())).status).toBe('not_found');
    expect((await look('threatfox', ioc('md5', '0'.repeat(32)), k())).status).toBe('not_found');
  });
});

describe.skipIf(!keys.abuseipdb)('AbuseIPDB (live)', () => {
  const k = () => keys.abuseipdb!;

  it('testKey ok, wrong key invalid', async () => {
    expect(await ADAPTERS.abuseipdb.testKey(k(), signal())).toBe('ok');
    expect(await ADAPTERS.abuseipdb.testKey('invalid-key-000000000000000000000000', signal())).toBe('invalid');
  });

  it('checks a public resolver and a currently listed C2 IP', async () => {
    const dns = await look('abuseipdb', ioc('ipv4', '8.8.8.8'), k());
    expect(dns.status).toBe('ok');
    expect(dns.link).toBe('https://www.abuseipdb.com/check/8.8.8.8');
    expect(dns.details.map((d) => d[0])).toContain('ISP');

    if (live.ipPort) expect((await look('abuseipdb', ioc('ipv4', live.ipPort.split(':')[0]!), k())).status).toBe('ok');
    expect((await look('abuseipdb', ioc('ipv6', '2001:4860:4860::8888'), k())).status).toBe('ok');
  });
});

describe.skipIf(!keys.vt)('VirusTotal (live, public IOCs only)', () => {
  const k = () => keys.vt!;
  const EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

  it('testKey, one lookup per type, respecting 4 requests/minute', async () => {
    expect(await ADAPTERS.virustotal.testKey(k(), signal())).toBe('ok');

    const file = await look('virustotal', ioc('sha256', EICAR), k());
    expect(file).toMatchObject({ status: 'ok', verdict: 'malicious', link: `https://www.virustotal.com/gui/file/${EICAR}` });

    const dom = await look('virustotal', ioc('domain', 'google.com'), k());
    expect(dom.status).toBe('ok');
    expect(['clean', 'unknown', 'suspicious']).toContain(dom.verdict);

    const ip = await look('virustotal', ioc('ipv4', '8.8.8.8'), k());
    expect(ip.status).toBe('ok');
    expect(ip.details.map((d) => d[0])).toContain('AS owner');

    await sleep(61_000); // 5th request in this test: wait for the window
    const url = await look('virustotal', ioc('url', 'https://www.google.com/'), k());
    expect(['ok', 'not_found']).toContain(url.status);
    if (url.status === 'ok') expect(url.link).toMatch(/^https:\/\/www\.virustotal\.com\/gui\/url\/[0-9a-f]{64}$/);
  }, 180_000);
});

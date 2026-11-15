import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseVt, virustotal, vtEndpoint, vtHeadline, vtLink, vtUrlId, vtVerdict } from '../../src/lib/sources/virustotal';
import type { Ioc } from '../../src/lib/types';
import { jsonResponse, mockFetch } from '../helpers/fetch';
import { fixture } from '../helpers/fixtures';

const KEY = 'vt-test-key-0123456789';
const signal = new AbortController().signal;
const SHA = '3f6fa13af90cf967f0b5f5d07f413f9d1f39d2fa366f09ff760fcd3fd8bf6fbf';
const fileIoc: Ioc = { raw: SHA, value: SHA, type: 'sha256' };
const domainIoc: Ioc = { raw: 'foo.fooapis.com', value: 'foo.fooapis.com', type: 'domain' };
const ipIoc: Ioc = { raw: '81.169.145.1', value: '81.169.145.1', type: 'ipv4' };
const urlIoc: Ioc = { raw: 'u', value: 'http://www.somedomain.com/this/is/my/url', type: 'url' };

afterEach(() => vi.unstubAllGlobals());

describe('URL identifier', () => {
  it('matches the docs example (unpadded URL-safe base64)', () => {
    // Python: base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    expect(vtUrlId('http://www.somedomain.com/this/is/my/url')).toBe('aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA');
  });

  it('uses - and _ instead of + and /, and encodes UTF-8', () => {
    expect(vtUrlId('https://a.example/?>>>???')).not.toMatch(/[+/=]/);
    expect(vtUrlId('https://xn--bcher-kva.de/ü')).toBe(Buffer.from('https://xn--bcher-kva.de/ü').toString('base64url'));
  });
});

describe('endpoints', () => {
  it.each<[Ioc, string]>([
    [fileIoc, `https://www.virustotal.com/api/v3/files/${SHA}`],
    [domainIoc, 'https://www.virustotal.com/api/v3/domains/foo.fooapis.com'],
    [ipIoc, 'https://www.virustotal.com/api/v3/ip_addresses/81.169.145.1'],
    [{ raw: '', value: '2001:db8::1', type: 'ipv6' }, 'https://www.virustotal.com/api/v3/ip_addresses/2001%3Adb8%3A%3A1'],
    [urlIoc, 'https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA'],
  ])('%j', (ioc, url) => {
    expect(vtEndpoint(ioc)).toBe(url);
  });
});

describe('verdict rules (SPEC F3)', () => {
  const s = (malicious: number, suspicious = 0, harmless = 0, undetected = 0) => ({ malicious, suspicious, harmless, undetected });
  it.each([
    [s(3), 'malicious'],
    [s(12, 0, 50, 20), 'malicious'],
    [s(2, 0, 60), 'suspicious'],
    [s(1, 1, 60), 'suspicious'],
    [s(0, 2, 60), 'suspicious'],
    [s(2, 5, 60), 'suspicious'], // many "suspicious" engines never make it malicious
    [s(1, 0, 91), 'clean'], // single detection is noise (e.g. google.com, 8.8.8.8)
    [s(0, 1, 91), 'clean'],
    [s(0, 0, 60, 30), 'clean'],
    [s(0, 0, 0, 0), 'unknown'],
  ] as const)('%j → %s', (stats, verdict) => {
    expect(vtVerdict(stats)).toBe(verdict);
  });

  it('the headline always shows the raw detections', () => {
    expect(vtHeadline(s(1, 0, 91))).toBe('1/92 engines');
    expect(vtHeadline(s(0, 1, 91))).toBe('0/92 engines · 1 suspicious');
    expect(vtHeadline(s(12, 0, 50, 20))).toBe('12/82 engines');
  });
});

describe('fixtures → SourceResult', () => {
  it('malicious file', () => {
    const r = parseVt(fileIoc, fixture('virustotal', 'file-malicious'));
    expect(r).toMatchObject({
      source: 'virustotal',
      status: 'ok',
      verdict: 'malicious',
      headline: '3/5 engines',
      link: `https://www.virustotal.com/gui/file/${SHA}`,
    });
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['Name', 'o4oz44Z4E444.exe'],
        ['Type', 'Win32 EXE'],
        ['Size', '365.5 KB'],
        ['Last analysis', '2020-06-14 13:33 UTC'],
      ]),
    );
  });

  it('clean domain', () => {
    const r = parseVt(domainIoc, fixture('virustotal', 'domain-clean'));
    expect(r).toMatchObject({ status: 'ok', verdict: 'clean', headline: '0/3 engines', link: 'https://www.virustotal.com/gui/domain/foo.fooapis.com' });
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['Registrar', 'MarkMonitor Inc.'],
        ['Categories', 'known infection source, bot networks. parked domain'],
      ]),
    );
  });

  it('suspicious URL links to the GUI by the returned id', () => {
    const r = parseVt(urlIoc, fixture('virustotal', 'url-suspicious'));
    expect(r).toMatchObject({ status: 'ok', verdict: 'suspicious', headline: '1/92 engines · 1 suspicious' });
    expect(r.link).toBe('https://www.virustotal.com/gui/url/1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31');
    expect(r.details).toEqual(expect.arrayContaining([['Final URL', 'http://www.somedomain.com/landing']]));
  });

  it('clean IP', () => {
    const r = parseVt(ipIoc, fixture('virustotal', 'ip-clean'));
    expect(r).toMatchObject({ verdict: 'clean', link: 'https://www.virustotal.com/gui/ip-address/81.169.145.1' });
    expect(r.details).toEqual(expect.arrayContaining([['AS owner', 'Example Hosting GmbH'], ['Country', 'DE']]));
  });

  it('object without analysis stats → ok, unknown, "Not analysed yet"', () => {
    expect(parseVt(domainIoc, { data: { id: 'x', attributes: {} } })).toMatchObject({
      status: 'ok',
      verdict: 'unknown',
      headline: 'Not analysed yet',
    });
  });

  it('malformed body → error "Unexpected response"', () => {
    for (const bad of [null, {}, { data: [] }, { data: { attributes: 'x' } }]) {
      expect(parseVt(fileIoc, bad)).toMatchObject({ status: 'error', error: 'Unexpected response' });
    }
  });
});

describe('lookup (mocked fetch)', () => {
  it('sends a GET with x-apikey and parses the response', async () => {
    const { calls } = mockFetch(() => jsonResponse(fixture('virustotal', 'file-malicious')));
    const r = await virustotal.lookup(fileIoc, KEY, signal);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: 'GET', url: `https://www.virustotal.com/api/v3/files/${SHA}` });
    expect(calls[0]!.headers['x-apikey']).toBe(KEY);
    expect(r.verdict).toBe('malicious');
  });

  it('404 hash → not_found with a GUI link', async () => {
    mockFetch(() => jsonResponse(fixture('virustotal', 'not-found'), 404));
    const r = await virustotal.lookup(fileIoc, KEY, signal);
    expect(r).toMatchObject({ status: 'not_found', verdict: 'unknown', headline: 'Not in VirusTotal' });
    expect(r.link).toBe(`https://www.virustotal.com/gui/file/${SHA}`);
  });

  it('404 URL → search link', async () => {
    mockFetch(() => jsonResponse(fixture('virustotal', 'not-found'), 404));
    const r = await virustotal.lookup(urlIoc, KEY, signal);
    expect(r.link).toBe('https://www.virustotal.com/gui/search/http%253A%252F%252Fwww.somedomain.com%252Fthis%252Fis%252Fmy%252Furl');
  });

  it('401 → error without the key; 429 → rate_limited', async () => {
    mockFetch(() => jsonResponse(fixture('virustotal', 'wrong-credentials'), 401));
    const r = await virustotal.lookup(fileIoc, KEY, signal);
    expect(r).toMatchObject({ status: 'error', error: 'Invalid or unauthorized key' });
    expect(JSON.stringify(r)).not.toContain(KEY);

    mockFetch(() => jsonResponse({ error: { code: 'QuotaExceededError' } }, 429));
    expect((await virustotal.lookup(fileIoc, KEY, signal)).status).toBe('rate_limited');
  });

  it('only calls read-only GET endpoints (SPEC §9 S2)', async () => {
    const { calls } = mockFetch(() => jsonResponse(fixture('virustotal', 'domain-clean')));
    for (const ioc of [fileIoc, domainIoc, ipIoc, urlIoc]) await virustotal.lookup(ioc, KEY, signal);
    await virustotal.testKey(KEY, signal);
    expect(calls.every((c) => c.method === 'GET' && c.body === undefined)).toBe(true);
  });
});

describe('testKey', () => {
  it.each([
    [200, 'ok'],
    [404, 'ok'],
    [401, 'invalid'],
    [403, 'invalid'],
    [429, 'error'],
    [500, 'error'],
  ] as const)('HTTP %i → %s', async (status, expected) => {
    mockFetch(() => jsonResponse(fixture('virustotal', 'ip-clean'), status));
    expect(await virustotal.testKey(KEY, signal)).toBe(expected);
  });
});

describe('supports and links', () => {
  it('supports every IOC type', () => {
    for (const t of ['md5', 'sha1', 'sha256', 'domain', 'ipv4', 'ipv6', 'url'] as const) expect(virustotal.supports(t)).toBe(true);
  });

  it('links are https on www.virustotal.com', () => {
    for (const ioc of [fileIoc, domainIoc, ipIoc, urlIoc]) {
      const u = new URL(vtLink(ioc)!);
      expect(u.protocol).toBe('https:');
      expect(u.hostname).toBe('www.virustotal.com');
    }
  });
});

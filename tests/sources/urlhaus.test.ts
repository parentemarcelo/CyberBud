import { afterEach, describe, expect, it, vi } from 'vitest';
import { classifyQueryStatus } from '../../src/lib/sources/abusech';
import { urlhaus } from '../../src/lib/sources/urlhaus';
import type { Ioc } from '../../src/lib/types';
import { jsonResponse, mockFetch } from '../helpers/fetch';
import { fixture } from '../helpers/fixtures';

const KEY = 'abusech-test-key-0123456789';
const signal = new AbortController().signal;
const urlIoc: Ioc = { raw: '', value: 'http://evil.example/bins/payload.exe', type: 'url' };
const hostIoc: Ioc = { raw: '', value: 'evil.example', type: 'domain' };

afterEach(() => vi.unstubAllGlobals());

describe('requests', () => {
  it('URL → POST /v1/url/ form url=…, Auth-Key header', async () => {
    const { calls } = mockFetch(() => jsonResponse(fixture('urlhaus', 'url-found')));
    await urlhaus.lookup(urlIoc, KEY, signal);
    expect(calls[0]).toMatchObject({ method: 'POST', url: 'https://urlhaus-api.abuse.ch/v1/url/' });
    expect(calls[0]!.headers['auth-key']).toBe(KEY);
    expect(new URLSearchParams(calls[0]!.body).get('url')).toBe(urlIoc.value);
  });

  it.each<Ioc>([hostIoc, { raw: '', value: '1.2.3.4', type: 'ipv4' }])('$type → POST /v1/host/ form host=…', async (ioc) => {
    const { calls } = mockFetch(() => jsonResponse(fixture('urlhaus', 'host-found')));
    await urlhaus.lookup(ioc, KEY, signal);
    expect(calls[0]!.url).toBe('https://urlhaus-api.abuse.ch/v1/host/');
    expect(new URLSearchParams(calls[0]!.body).get('host')).toBe(ioc.value);
  });
});

describe('fixtures → SourceResult', () => {
  it('URL found → malicious with details and reference link', async () => {
    mockFetch(() => jsonResponse(fixture('urlhaus', 'url-found')));
    const r = await urlhaus.lookup(urlIoc, KEY, signal);
    expect(r).toMatchObject({
      source: 'urlhaus',
      status: 'ok',
      verdict: 'malicious',
      headline: 'malware download · online',
      link: 'https://urlhaus.abuse.ch/url/105821/',
    });
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['Status', 'online'],
        ['Added', '2026-11-10 07:41 UTC'],
        ['Tags', 'elf, mirai'],
        ['Payloads', '1'],
        ['Blocklists', 'spamhaus_dbl: abused_legit_malware'],
      ]),
    );
  });

  it('host found → malicious with URL counts', async () => {
    mockFetch(() => jsonResponse(fixture('urlhaus', 'host-found')));
    const r = await urlhaus.lookup(hostIoc, KEY, signal);
    expect(r).toMatchObject({
      status: 'ok',
      verdict: 'malicious',
      headline: '3 malicious URLs · 2 online',
      link: 'https://urlhaus.abuse.ch/host/evil.example/',
    });
    expect(r.details).toEqual(expect.arrayContaining([['Blocklists', 'surbl: listed'], ['Tags', 'exe, AgentTesla']]));
  });

  it('no_results → not_found / unknown (never clean)', async () => {
    mockFetch(() => jsonResponse(fixture('urlhaus', 'no-results')));
    const r = await urlhaus.lookup(hostIoc, KEY, signal);
    expect(r).toMatchObject({ status: 'not_found', verdict: 'unknown', headline: 'Not listed in URLhaus' });
    expect(r.link).toBe('https://urlhaus.abuse.ch/host/evil.example/');
  });

  it('invalid_url → error naming the status', async () => {
    mockFetch(() => jsonResponse(fixture('urlhaus', 'invalid-url')));
    expect(await urlhaus.lookup(urlIoc, KEY, signal)).toMatchObject({
      status: 'error',
      error: 'URLhaus rejected the request (invalid_url)',
    });
  });

  it('ignores a reference link pointing elsewhere', async () => {
    mockFetch(() => jsonResponse({ ...(fixture('urlhaus', 'url-found') as object), urlhaus_reference: 'https://evil.example/' }));
    expect((await urlhaus.lookup(urlIoc, KEY, signal)).link).toBe('https://urlhaus.abuse.ch/url/105821/');
  });
});

describe('auth failures (undocumented by abuse.ch: handled both ways)', () => {
  it.each([401, 403])('HTTP %i → invalid key error, no key in output', async (status) => {
    mockFetch(() => jsonResponse({ query_status: 'unknown_auth_key' }, status));
    const r = await urlhaus.lookup(urlIoc, KEY, signal);
    expect(r).toMatchObject({ status: 'error', error: 'Invalid or unauthorized key' });
    expect(JSON.stringify(r)).not.toContain(KEY);
  });

  it('HTTP 200 with a key-related query_status → invalid key', async () => {
    mockFetch(() => jsonResponse({ query_status: 'unknown_auth_key' }));
    expect(await urlhaus.lookup(urlIoc, KEY, signal)).toMatchObject({ error: 'Invalid or unauthorized key' });
  });

  it('testKey', async () => {
    mockFetch(() => jsonResponse({ query_status: 'no_results' }));
    expect(await urlhaus.testKey(KEY, signal)).toBe('ok');
    mockFetch(() => jsonResponse({ query_status: 'unknown_auth_key' }));
    expect(await urlhaus.testKey(KEY, signal)).toBe('invalid');
    mockFetch(() => jsonResponse({}, 401));
    expect(await urlhaus.testKey(KEY, signal)).toBe('invalid');
    mockFetch(() => new Response('down', { status: 503 }));
    expect(await urlhaus.testKey(KEY, signal)).toBe('error');
  });
});

describe('classifyQueryStatus', () => {
  it.each([
    ['ok', 'ok'],
    ['no_results', 'not_found'],
    ['no_result', 'not_found'],
    ['hash_not_found', 'not_found'],
    ['unknown_auth_key', 'invalid_key'],
    ['no_api_key', 'invalid_key'],
    ['invalid_url', 'rejected'],
    ['illegal_hash', 'rejected'],
    [undefined, 'rejected'],
    [42, 'rejected'],
  ])('%s → %s', (status, kind) => {
    expect(classifyQueryStatus(status)).toBe(kind);
  });
});

describe('supports', () => {
  it('URL, domain and IPv4 only', () => {
    expect(['url', 'domain', 'ipv4'].every((t) => urlhaus.supports(t as 'url'))).toBe(true);
    for (const t of ['ipv6', 'md5', 'sha1', 'sha256'] as const) expect(urlhaus.supports(t)).toBe(false);
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { matchesIoc, threatfox, threatfoxBody } from '../../src/lib/sources/threatfox';
import type { Ioc } from '../../src/lib/types';
import { jsonResponse, mockFetch } from '../helpers/fetch';
import { fixture } from '../helpers/fixtures';

const KEY = 'abusech-test-key-0123456789';
const signal = new AbortController().signal;
const domain: Ioc = { raw: '', value: 'evil.example', type: 'domain' };
const ip: Ioc = { raw: '', value: '1.2.3.4', type: 'ipv4' };
const md5: Ioc = { raw: '', value: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5' };

afterEach(() => vi.unstubAllGlobals());

describe('request body per type', () => {
  it.each<[Ioc, Record<string, unknown>]>([
    [domain, { query: 'search_ioc', search_term: 'evil.example', exact_match: true }],
    [{ raw: '', value: 'http://evil.example/gate.php', type: 'url' }, { query: 'search_ioc', search_term: 'http://evil.example/gate.php', exact_match: true }],
    [ip, { query: 'search_ioc', search_term: '1.2.3.4', exact_match: false }],
    [{ raw: '', value: '2001:db8::1', type: 'ipv6' }, { query: 'search_ioc', search_term: '2001:db8::1', exact_match: false }],
    [md5, { query: 'search_hash', hash: md5.value }],
    [{ raw: '', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'sha256' }, { query: 'search_hash', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }],
  ])('$type', async (ioc, body) => {
    expect(threatfoxBody(ioc)).toEqual(body);
    const { calls } = mockFetch(() => jsonResponse(fixture('threatfox', 'no-result')));
    await threatfox.lookup(ioc, KEY, signal);
    expect(calls[0]).toMatchObject({ method: 'POST', url: 'https://threatfox-api.abuse.ch/api/v1/' });
    expect(calls[0]!.headers['content-type']).toBe('application/json');
    expect(calls[0]!.headers['auth-key']).toBe(KEY);
    expect(JSON.parse(calls[0]!.body!)).toEqual(body);
  });
});

describe('fixtures → SourceResult', () => {
  it('domain found → malicious with malware and confidence', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'ioc-found-domain')));
    const r = await threatfox.lookup(domain, KEY, signal);
    expect(r).toMatchObject({
      source: 'threatfox',
      status: 'ok',
      verdict: 'malicious',
      link: 'https://threatfox.abuse.ch/ioc/41/',
    });
    expect(r.headline).toContain('QakBot');
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['Malware', 'QakBot'],
        ['Confidence', '75%'],
        ['Tags', 'QakBot, c2'],
        ['First seen', '2026-11-01 12:00 UTC'],
      ]),
    );
  });

  it('IP: keeps only ip / ip:port matches and shows the most confident one', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'ioc-found-ip-port')));
    const r = await threatfox.lookup(ip, KEY, signal);
    expect(r).toMatchObject({ verdict: 'malicious', link: 'https://threatfox.abuse.ch/ioc/102/' });
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['IOC', '1.2.3.4:443'],
        ['Confidence', '90%'],
        ['Matching entries', '2'],
      ]),
    );
  });

  it('IP: wildcard hits that are a different IP → not_found', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'ioc-found-ip-port')));
    expect((await threatfox.lookup({ raw: '', value: '2.3.4.4', type: 'ipv4' }, KEY, signal)).status).toBe('not_found');
  });

  it('hash found (search_hash) → malicious', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'hash-found')));
    expect(await threatfox.lookup(md5, KEY, signal)).toMatchObject({ verdict: 'malicious', link: 'https://threatfox.abuse.ch/ioc/500/' });
  });

  it('no_result (data is a message string) → not_found / unknown', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'no-result')));
    expect(await threatfox.lookup(domain, KEY, signal)).toMatchObject({
      status: 'not_found',
      verdict: 'unknown',
      headline: 'Not in ThreatFox',
    });
  });

  it('illegal_search_term → error', async () => {
    mockFetch(() => jsonResponse({ query_status: 'illegal_search_term', data: 'x' }));
    expect(await threatfox.lookup(domain, KEY, signal)).toMatchObject({
      status: 'error',
      error: 'ThreatFox rejected the request (illegal_search_term)',
    });
  });
});

describe('matchesIoc', () => {
  it.each([
    [ip, '1.2.3.4', true],
    [ip, '1.2.3.4:443', true],
    [ip, '11.2.3.4:443', false],
    [ip, '1.2.3.45:80', false],
    [{ raw: '', value: '2001:db8::1', type: 'ipv6' } as Ioc, '[2001:db8::1]:443', true],
    [domain, 'EVIL.EXAMPLE', true],
    [domain, 'sub.evil.example', false],
    [{ raw: '', value: 'http://evil.example/', type: 'url' } as Ioc, 'http://evil.example', true],
    [ip, null, false],
  ] as const)('%j vs %s → %s', (ioc, entry, expected) => {
    expect(matchesIoc(ioc, entry)).toBe(expected);
  });
});

describe('testKey and supports', () => {
  it('testKey', async () => {
    mockFetch(() => jsonResponse(fixture('threatfox', 'no-result')));
    expect(await threatfox.testKey(KEY, signal)).toBe('ok');
    mockFetch(() => jsonResponse({}, 403));
    expect(await threatfox.testKey(KEY, signal)).toBe('invalid');
  });

  it('no SHA-1 (not supported by search_hash)', () => {
    for (const t of ['url', 'domain', 'ipv4', 'ipv6', 'md5', 'sha256'] as const) expect(threatfox.supports(t)).toBe(true);
    expect(threatfox.supports('sha1')).toBe(false);
  });
});

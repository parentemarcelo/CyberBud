import { afterEach, describe, expect, it, vi } from 'vitest';
import { abuseipdb, abuseIpdbVerdict, parseAbuseIpdb } from '../../src/lib/sources/abuseipdb';
import type { Ioc } from '../../src/lib/types';
import { jsonResponse, mockFetch } from '../helpers/fetch';
import { fixture } from '../helpers/fixtures';

const KEY = 'abuseipdb-test-key-0123456789';
const signal = new AbortController().signal;
const ip = (value: string): Ioc => ({ raw: value, value, type: 'ipv4' });

afterEach(() => vi.unstubAllGlobals());

describe('fixtures → verdict (SPEC F3)', () => {
  it.each([
    ['score-0-no-reports', 'unknown', 'No reports'],
    ['score-10-reports', 'clean', '10% confidence · 2 reports'],
    ['score-50', 'suspicious', '50% confidence · 14 reports'],
    ['score-100', 'malicious', '100% confidence · 1 report'],
    ['whitelisted', 'clean', 'No reports'],
  ])('%s → %s', (name, verdict, headline) => {
    const r = parseAbuseIpdb(ip('1.2.3.4'), fixture('abuseipdb', name));
    expect(r).toMatchObject({ source: 'abuseipdb', status: 'ok', verdict, headline });
  });

  it('details for a reported IP', () => {
    const r = parseAbuseIpdb(ip('118.25.6.39'), fixture('abuseipdb', 'score-100'));
    expect(r.details).toEqual(
      expect.arrayContaining([
        ['Abuse confidence', '100%'],
        ['Reports (last 90 days)', '1'],
        ['Last reported', '2018-12-20 20:55 UTC'],
        ['ISP', 'Tencent Cloud Computing (Beijing) Co. Ltd'],
        ['Country', 'China'],
      ]),
    );
    expect(r.link).toBe('https://www.abuseipdb.com/check/118.25.6.39');
  });

  it('whitelisted is shown; null whitelist is not', () => {
    expect(parseAbuseIpdb(ip('8.8.8.8'), fixture('abuseipdb', 'whitelisted')).details).toContainEqual(['Whitelisted', 'Yes']);
    expect(parseAbuseIpdb(ip('1.2.3.4'), fixture('abuseipdb', 'score-0-no-reports')).details.map((d) => d[0])).not.toContain(
      'Whitelisted',
    );
  });

  it('threshold edges', () => {
    const v = (abuseConfidenceScore: number, totalReports = 5, isWhitelisted: boolean | null = false) =>
      abuseIpdbVerdict({ abuseConfidenceScore, totalReports, isWhitelisted });
    expect(v(75)).toBe('malicious');
    expect(v(74)).toBe('suspicious');
    expect(v(25)).toBe('suspicious');
    expect(v(24)).toBe('clean');
    expect(v(0, 0)).toBe('unknown');
    expect(v(0, 0, true)).toBe('clean');
    expect(v(90, 3, true)).toBe('malicious'); // the score wins over the whitelist
  });

  it('malformed body → error', () => {
    for (const bad of [null, {}, { data: {} }, { data: { abuseConfidenceScore: '5', totalReports: 1 } }]) {
      expect(parseAbuseIpdb(ip('1.2.3.4'), bad)).toMatchObject({ status: 'error', error: 'Unexpected response' });
    }
  });
});

describe('lookup (mocked fetch)', () => {
  it('GET /check with Key header, url-encoded IP and maxAgeInDays=90', async () => {
    const { calls } = mockFetch(() => jsonResponse(fixture('abuseipdb', 'score-50')));
    await abuseipdb.lookup({ raw: '', value: '2001:db8::1', type: 'ipv6' }, KEY, signal);
    expect(calls[0]!.method).toBe('GET');
    expect(calls[0]!.url).toBe('https://api.abuseipdb.com/api/v2/check?ipAddress=2001%3Adb8%3A%3A1&maxAgeInDays=90');
    expect(calls[0]!.headers.key).toBe(KEY);
    expect(calls[0]!.headers.accept).toBe('application/json');
  });

  it('429 with Retry-After → rate_limited with retryAt', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(Date.UTC(2026, 10, 15, 12));
    mockFetch(() => jsonResponse(fixture('abuseipdb', 'rate-limited'), 429, { 'Retry-After': '29241' }));
    const r = await abuseipdb.lookup(ip('1.2.3.4'), KEY, signal);
    expect(r).toMatchObject({ status: 'rate_limited', retryAt: Date.UTC(2026, 10, 15, 12) + 29_241_000 });
  });

  it('401 → error without the key', async () => {
    mockFetch(() => jsonResponse({ errors: [{ detail: `bad key ${KEY}`, status: 401 }] }, 401));
    const r = await abuseipdb.lookup(ip('1.2.3.4'), KEY, signal);
    expect(r).toMatchObject({ status: 'error', error: 'Invalid or unauthorized key' });
    expect(JSON.stringify(r)).not.toContain(KEY);
  });

  it('422 → error', async () => {
    mockFetch(() => jsonResponse({ errors: [{ detail: 'x', status: 422 }] }, 422));
    expect((await abuseipdb.lookup(ip('1.2.3.4'), KEY, signal)).status).toBe('error');
  });
});

describe('testKey and supports', () => {
  it.each([
    [200, 'ok'],
    [401, 'invalid'],
    [429, 'error'],
  ] as const)('HTTP %i → %s', async (status, expected) => {
    mockFetch(() => jsonResponse(fixture('abuseipdb', 'whitelisted'), status));
    expect(await abuseipdb.testKey(KEY, signal)).toBe(expected);
  });

  it('supports IPs only', () => {
    expect(['ipv4', 'ipv6'].every((t) => abuseipdb.supports(t as 'ipv4'))).toBe(true);
    for (const t of ['domain', 'url', 'md5', 'sha1', 'sha256'] as const) expect(abuseipdb.supports(t)).toBe(false);
  });
});

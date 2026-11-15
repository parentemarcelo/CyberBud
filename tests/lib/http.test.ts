import { afterEach, describe, expect, it, vi } from 'vitest';
import { MESSAGES, parseRetryAfter, redact, requestJson } from '../../src/lib/http';
import { hangingFetch, jsonResponse, mockFetch } from '../helpers/fetch';

const KEY = 'sk-test-0123456789abcdef';
const req = { url: 'https://api.example.test/x', headers: { Key: KEY }, secrets: [KEY] };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('status mapping (SPEC §8)', () => {
  it('200 with JSON → ok', async () => {
    mockFetch(() => jsonResponse({ a: 1 }));
    expect(await requestJson(req)).toEqual({ kind: 'ok', status: 200, json: { a: 1 } });
  });

  it('404 → not_found (body kept when JSON)', async () => {
    mockFetch(() => jsonResponse({ error: { code: 'NotFoundError' } }, 404));
    expect(await requestJson(req)).toEqual({ kind: 'not_found', status: 404, json: { error: { code: 'NotFoundError' } } });
    mockFetch(() => new Response('', { status: 404 }));
    expect(await requestJson(req)).toEqual({ kind: 'not_found', status: 404 });
  });

  it.each([401, 403])('%i → unauthorized "Invalid or unauthorized key"', async (status) => {
    mockFetch(() => jsonResponse({ error: { message: `bad key ${KEY}` } }, status));
    expect(await requestJson(req)).toEqual({ kind: 'unauthorized', status, message: MESSAGES.unauthorized });
  });

  it('429 with Retry-After seconds → rate_limited with retryAfterMs', async () => {
    mockFetch(() => jsonResponse({ errors: [] }, 429, { 'Retry-After': '30' }));
    expect(await requestJson(req)).toEqual({ kind: 'rate_limited', status: 429, retryAfterMs: 30_000, json: { errors: [] } });
  });

  it('429 without Retry-After → rate_limited without retryAfterMs', async () => {
    mockFetch(() => new Response('', { status: 429 }));
    expect(await requestJson(req)).toEqual({ kind: 'rate_limited', status: 429 });
  });

  it.each([500, 502, 503, 504])('%i → error "Source unavailable"', async (status) => {
    mockFetch(() => new Response('oops', { status }));
    expect(await requestJson(req)).toEqual({ kind: 'error', status, message: `Source unavailable (HTTP ${status})` });
  });

  it.each([400, 422])('%i → error "Request rejected"', async (status) => {
    mockFetch(() => jsonResponse({ errors: [{ detail: 'x' }] }, status));
    expect(await requestJson(req)).toEqual({ kind: 'error', status, message: `Request rejected (HTTP ${status})` });
  });

  it('200 with invalid JSON → error "Unexpected response"', async () => {
    mockFetch(() => new Response('<html>not json</html>', { status: 200 }));
    expect(await requestJson(req)).toEqual({ kind: 'error', status: 200, message: MESSAGES.badJson });
  });

  it('200 with empty body → error "Unexpected response"', async () => {
    mockFetch(() => new Response('', { status: 200 }));
    expect(await requestJson(req)).toMatchObject({ kind: 'error', message: MESSAGES.badJson });
  });

  it('network failure → error "Network error"', async () => {
    mockFetch(() => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });
    expect(await requestJson(req)).toMatchObject({ kind: 'error', message: expect.stringContaining(MESSAGES.network) });
  });
});

describe('timeout and cancellation', () => {
  it('times out after 15 s (fake timers)', async () => {
    vi.useFakeTimers();
    hangingFetch();
    const p = requestJson(req);
    await vi.advanceTimersByTimeAsync(14_999);
    let settled = false;
    void p.then(() => (settled = true));
    await Promise.resolve();
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await p).toEqual({ kind: 'error', message: MESSAGES.timeout });
  });

  it('caller abort → "Cancelled"', async () => {
    hangingFetch();
    const ctl = new AbortController();
    const p = requestJson({ ...req, signal: ctl.signal });
    ctl.abort();
    expect(await p).toEqual({ kind: 'error', message: MESSAGES.cancelled });
  });

  it('an already-aborted signal is honoured', async () => {
    mockFetch(() => jsonResponse({}));
    const ctl = new AbortController();
    ctl.abort();
    expect(await requestJson({ ...req, signal: ctl.signal })).toEqual({ kind: 'error', message: MESSAGES.cancelled });
  });
});

describe('request options', () => {
  it('sends method, headers and body, omits credentials, never follows redirects', async () => {
    const { fn } = mockFetch(() => jsonResponse({}));
    await requestJson({ ...req, method: 'POST', body: new URLSearchParams({ q: '1' }) });
    const init = fn.mock.calls[0]![1]!;
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('omit');
    expect(init.redirect).toBe('error');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(String(init.body)).toBe('q=1');
  });
});

describe('key redaction (SPEC §9 S5)', () => {
  it('no outcome message ever contains the key', async () => {
    const responses: Array<() => Response> = [
      () => jsonResponse({ msg: KEY }, 401),
      () => jsonResponse({ msg: KEY }, 403),
      () => new Response(KEY, { status: 500 }),
      () => new Response(KEY, { status: 422 }),
      () => new Response(`not json ${KEY}`, { status: 200 }),
      () => {
        throw new TypeError(`Invalid header value ${KEY}`);
      },
    ];
    for (const r of responses) {
      mockFetch(r);
      const out = await requestJson(req);
      expect(JSON.stringify(out)).not.toContain(KEY);
    }
  });

  it('redact replaces every occurrence and ignores very short secrets', () => {
    expect(redact(`a ${KEY} b ${KEY}`, [KEY])).toBe('a [redacted] b [redacted]');
    expect(redact('abc', ['ab'])).toBe('abc');
  });
});

describe('parseRetryAfter', () => {
  it('parses seconds and HTTP dates', () => {
    const now = Date.UTC(2026, 10, 15, 12, 0, 0);
    expect(parseRetryAfter('120', now)).toBe(120_000);
    expect(parseRetryAfter('Sun, 15 Nov 2026 12:01:00 GMT', now)).toBe(60_000);
    expect(parseRetryAfter('Sun, 15 Nov 2026 11:00:00 GMT', now)).toBe(0);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('soon')).toBeUndefined();
  });
});

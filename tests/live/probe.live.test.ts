// Exploratory probe of real API behaviour that the docs leave open.
// Prints response *shapes* (status codes, query_status, field names), never keys.
import { describe, it } from 'vitest';
import { requestJson } from '../../src/lib/http';
import { loadKeys } from './keys';

const keys = loadKeys();
const signal = () => new AbortController().signal;
const shape = (x: unknown): unknown =>
  Array.isArray(x) ? (x.length ? [shape(x[0]), `…${x.length}`] : []) : x && typeof x === 'object'
    ? Object.fromEntries(Object.entries(x).map(([k, v]) => [k, typeof v === 'object' && v !== null ? shape(v) : typeof v]))
    : typeof x;

const abusech = (url: string, body: Record<string, unknown> | Record<string, string>, key: string, json = false) =>
  requestJson({
    url,
    method: 'POST',
    headers: { 'Auth-Key': key, Accept: 'application/json', ...(json && { 'Content-Type': 'application/json' }) },
    body: json ? JSON.stringify(body) : new URLSearchParams(body as Record<string, string>),
    secrets: [key],
    signal: signal(),
  });

describe.skipIf(!keys.abusech)('abuse.ch probe', () => {
  it('invalid key behaviour', async () => {
    const bad = 'invalid-key-000000000000000000000000';
    for (const [name, url, body, json] of [
      ['urlhaus', 'https://urlhaus-api.abuse.ch/v1/host/', { host: 'example.com' }, false],
      ['mb', 'https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }, false],
      ['tf', 'https://threatfox-api.abuse.ch/api/v1/', { query: 'search_hash', hash: 'd41d8cd98f00b204e9800998ecf8427e' }, true],
    ] as const) {
      const out = await abusech(url, body, bad, json);
      console.log('INVALID-KEY', name, JSON.stringify(out));
    }
  });

  it('not-found and success shapes', async () => {
    const k = keys.abusech!;
    const probes: Array<[string, string, Record<string, unknown>, boolean]> = [
      ['mb-notfound', 'https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash: '0'.repeat(64) }, false],
      ['tf-notfound-hash', 'https://threatfox-api.abuse.ch/api/v1/', { query: 'search_hash', hash: '0'.repeat(32) }, true],
      ['tf-notfound-ioc', 'https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: 'no-such-host-cyberbud.example', exact_match: true }, true],
      ['uh-notfound-host', 'https://urlhaus-api.abuse.ch/v1/host/', { host: 'no-such-host-cyberbud.example' }, false],
      ['uh-host-ipv6', 'https://urlhaus-api.abuse.ch/v1/host/', { host: '2001:db8::1' }, false],
      ['tf-recent', 'https://threatfox-api.abuse.ch/api/v1/', { query: 'get_iocs', days: 1 }, true],
      ['mb-recent', 'https://mb-api.abuse.ch/api/v1/', { query: 'get_recent', selector: 'time' }, false],
    ];
    for (const [name, url, body, json] of probes) {
      const out = await abusech(url, body, k, json);
      const j = out.kind === 'ok' ? (out.json as Record<string, unknown>) : undefined;
      console.log('PROBE', name, out.kind, 'status' in out ? out.status : '', j ? JSON.stringify(j.query_status) : '', j ? JSON.stringify(shape(j)).slice(0, 900) : JSON.stringify(out));
    }
  });
});

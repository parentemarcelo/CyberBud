import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  HASH_TYPES,
  IOC_TYPES,
  KEY_IDS,
  SOURCE_IDS,
  STATUSES,
  VERDICTS,
  type IocType,
  type ParseResult,
  type SourceId,
  type SourceResult,
  type Status,
  type Verdict,
} from '../src/lib/types';

// Runtime tuples must match SPEC §8. Type-level checks run under `npm run compile`.
describe('type tuples (SPEC §8)', () => {
  it('IOC types', () => {
    expect(IOC_TYPES).toEqual(['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);
    for (const h of HASH_TYPES) expect(IOC_TYPES).toContain(h);
    expectTypeOf<(typeof IOC_TYPES)[number]>().toEqualTypeOf<IocType>();
  });

  it('sources and key slots', () => {
    expect(SOURCE_IDS).toEqual(['virustotal', 'abuseipdb', 'urlhaus', 'malwarebazaar', 'threatfox']);
    expect(KEY_IDS).toEqual(['vt', 'abuseipdb', 'abusech']);
    expectTypeOf<(typeof SOURCE_IDS)[number]>().toEqualTypeOf<SourceId>();
  });

  it('verdicts and statuses', () => {
    expect([...VERDICTS].sort()).toEqual(['clean', 'malicious', 'suspicious', 'unknown']);
    expect([...STATUSES].sort()).toEqual(
      ['disabled', 'error', 'loading', 'no_key', 'not_found', 'ok', 'queued', 'rate_limited'],
    );
    expectTypeOf<(typeof VERDICTS)[number]>().toEqualTypeOf<Verdict>();
    expectTypeOf<(typeof STATUSES)[number]>().toEqualTypeOf<Status>();
  });

  it('ParseResult is a discriminated union on kind', () => {
    expectTypeOf<ParseResult['kind']>().toEqualTypeOf<'ioc' | 'private' | 'unsupported' | 'skipped'>();
  });

  it('a minimal SourceResult type-checks', () => {
    const r: SourceResult = {
      source: 'virustotal',
      ioc: { raw: 'example[.]com', value: 'example.com', type: 'domain' },
      status: 'ok',
      verdict: 'clean',
      headline: '0/94 engines',
      details: [['Registrar', 'Example Inc.']],
    };
    expect(r.details[0]?.[0]).toBe('Registrar');
  });
});

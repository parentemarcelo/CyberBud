import { describe, expect, it } from 'vitest';
import { applyUrlMode, parseInput, splitTokens } from '../../src/lib/ioc/parse';
import type { ParseResult } from '../../src/lib/types';

const iocs = (results: ParseResult[]) =>
  results.flatMap((r) => (r.kind === 'ioc' ? [`${r.ioc.type}:${r.ioc.value}`] : []));

describe('acceptance criterion 1 (parser level)', () => {
  it('defanged URL with token is refanged and stripped in default mode', () => {
    const [r] = parseInput('hxxps://evil[.]example/path?token=abc', 'strip');
    expect(r).toEqual({
      kind: 'ioc',
      ioc: { raw: 'hxxps://evil[.]example/path?token=abc', type: 'url', value: 'https://evil.example/path' },
    });
  });
});

describe('acceptance criterion 3 (parser level)', () => {
  it('private IP is labelled and not returned as an IOC', () => {
    expect(parseInput('10.0.0.5', 'strip')).toEqual([{ kind: 'private', raw: '10.0.0.5', value: '10.0.0.5' }]);
  });

  it('URLs and domains pointing at private hosts are private too', () => {
    const kinds = parseInput('http://192.168.1.1/admin http://localhost:8080/x app.localhost http://[::1]/', 'full').map(
      (r) => r.kind,
    );
    expect(kinds).toEqual(['private', 'private', 'private', 'private']);
  });

  it('private IPv6 is private', () => {
    expect(parseInput('fe80::1', 'strip')[0]?.kind).toBe('private');
  });
});

describe('splitting', () => {
  it('splits on whitespace, commas, semicolons and newlines', () => {
    const r = parseInput('8.8.8.8, 1.1.1.1;example.com\nexample.org\t9.9.9.9', 'strip');
    expect(iocs(r)).toEqual([
      'ipv4:8.8.8.8',
      'ipv4:1.1.1.1',
      'domain:example.com',
      'domain:example.org',
      'ipv4:9.9.9.9',
    ]);
  });

  it('does not split a URL on commas/semicolons in its path or query', () => {
    expect(splitTokens('https://example.com/a,b;c?x=1,2')).toEqual(['https://example.com/a,b;c?x=1,2']);
  });

  it('splits URLs that are joined by a comma', () => {
    expect(splitTokens('https://a.example/x,https://b.example/y')).toEqual([
      'https://a.example/x',
      'https://b.example/y',
    ]);
    expect(splitTokens('hxxp://a[.]example/x;hxxps[:]//b[.]example')).toEqual([
      'hxxp://a[.]example/x',
      'hxxps[:]//b[.]example',
    ]);
  });

  it('keeps spaced defangs in one token', () => {
    expect(parseInput('evil[ . ]example . com', 'strip')).toEqual([
      { kind: 'ioc', ioc: { raw: 'evil[.]example[.]com', type: 'domain', value: 'evil.example.com' } },
    ]);
  });

  it('ignores empty input and punctuation-only tokens', () => {
    expect(parseInput('', 'strip')).toEqual([]);
    expect(parseInput('  , ; "" \n ', 'strip')).toEqual([]);
  });
});

describe('mixed input', () => {
  it('detects each type and reports unsupported tokens', () => {
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const r = parseInput(`8[.]8[.]8[.]8 evil[.]example ${sha} user@example.com "hxxp://bad[.]example/x"`, 'strip');
    expect(r).toEqual([
      { kind: 'ioc', ioc: { raw: '8[.]8[.]8[.]8', type: 'ipv4', value: '8.8.8.8' } },
      { kind: 'ioc', ioc: { raw: 'evil[.]example', type: 'domain', value: 'evil.example' } },
      { kind: 'ioc', ioc: { raw: sha, type: 'sha256', value: sha } },
      { kind: 'unsupported', raw: 'user@example.com' },
      { kind: 'ioc', ioc: { raw: '"hxxp://bad[.]example/x"', type: 'url', value: 'http://bad.example/x' } },
    ]);
  });
});

describe('deduplication', () => {
  it('removes duplicates after normalization, keeping the first raw form', () => {
    const r = parseInput('EXAMPLE.com example[.]com example.com. "example.com"', 'strip');
    expect(r).toEqual([{ kind: 'ioc', ioc: { raw: 'EXAMPLE.com', type: 'domain', value: 'example.com' } }]);
  });

  it('URLs differing only by query string collapse in strip mode but not in full mode', () => {
    const text = 'https://a.example/p?x=1 https://a.example/p?x=2';
    expect(iocs(parseInput(text, 'strip'))).toEqual(['url:https://a.example/p']);
    expect(iocs(parseInput(text, 'full'))).toHaveLength(2);
  });

  it('dedupes private and unsupported entries too', () => {
    expect(parseInput('10.0.0.1 10.0.0.1 foo foo', 'strip')).toHaveLength(2);
  });
});

describe('batch cap (MAX_BATCH_SIZE = 20)', () => {
  const ips = Array.from({ length: 25 }, (_, i) => `8.8.8.${i + 1}`);

  it('returns 20 IOCs and reports the rest as skipped', () => {
    const r = parseInput(ips.join(' '), 'strip');
    expect(r.filter((x) => x.kind === 'ioc')).toHaveLength(20);
    expect(r[20]).toEqual({ kind: 'skipped', raw: '8.8.8.21' });
    expect(r.filter((x) => x.kind === 'skipped')).toHaveLength(5);
  });

  it('private, unsupported and duplicate tokens do not count toward the cap', () => {
    const text = ['10.0.0.1', 'foo', ...ips.slice(0, 20), ips[0], '8.8.4.4'].join(' ');
    const r = parseInput(text, 'strip');
    expect(r.filter((x) => x.kind === 'ioc')).toHaveLength(20);
    expect(r.filter((x) => x.kind === 'skipped')).toEqual([{ kind: 'skipped', raw: '8.8.4.4' }]);
  });
});

describe('URL privacy modes', () => {
  const url = 'https://user:pw@Evil.Example:8443/p/a?token=secret#frag';

  it('full: keeps query, drops fragment and credentials', () => {
    expect(iocs(parseInput(url, 'full'))).toEqual(['url:https://evil.example:8443/p/a?token=secret']);
  });

  it('strip: drops query and fragment', () => {
    expect(iocs(parseInput(url, 'strip'))).toEqual(['url:https://evil.example:8443/p/a']);
  });

  it('domain: turns the URL into a domain IOC', () => {
    expect(iocs(parseInput(url, 'domain'))).toEqual(['domain:evil.example']);
  });

  it('domain: an IP host becomes an IP IOC', () => {
    expect(iocs(parseInput('http://1.2.3.4/x hxxp://[2606:4700::1111]/y', 'domain'))).toEqual([
      'ipv4:1.2.3.4',
      'ipv6:2606:4700::1111',
    ]);
  });

  it('domain: a private IP host is still caught', () => {
    expect(parseInput('http://10.0.0.1/x', 'domain')).toEqual([
      { kind: 'private', raw: 'http://10.0.0.1/x', value: '10.0.0.1' },
    ]);
  });

  it('the fragment is never sent, in any mode', () => {
    for (const mode of ['full', 'strip', 'domain'] as const) {
      for (const r of parseInput('https://example.com/x?y=1#secret-fragment', mode)) {
        expect(JSON.stringify(r.kind === 'ioc' ? r.ioc.value : '')).not.toContain('secret-fragment');
      }
    }
  });

  it('modes only affect URLs', () => {
    for (const mode of ['full', 'strip', 'domain'] as const) {
      expect(iocs(parseInput('example.com 8.8.8.8', mode))).toEqual(['domain:example.com', 'ipv4:8.8.8.8']);
    }
  });

  it('applyUrlMode keeps raw', () => {
    const ioc = { raw: 'RAW', type: 'url' as const, value: 'https://a.example/x?q=1#f' };
    expect(applyUrlMode(ioc, 'strip')).toEqual({ raw: 'RAW', type: 'url', value: 'https://a.example/x' });
  });
});

import { describe, expect, it } from 'vitest';
import { isPrivateHost, isPrivateIp } from '../../src/lib/ioc/private';
import { parseInput } from '../../src/lib/ioc/parse';
import { URL_PRIVACY_MODES } from '../../src/lib/types';

// Deterministic PRNG so failures are reproducible.
function rng(seed: number) {
  return () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
}

const PIECES = [
  'http', 'hxxps', '://', '[.]', '[:]', '(dot)', '.', ':', '/', '?', '#', '@', '[at]', '%', ',', ';', ' ', '\n',
  'example', 'com', 'xn--p1ai', 'bücher', '10', '192', '168', '255', '256', '0', '::', 'ffff', 'fe80', '1',
  '"', "'", '(', ')', '<', '>', '[', ']', 'user:pw', 'localhost', 'e3b0c44298fc1c149afbf4c8996fb924', '-', '_',
];

describe('parseInput robustness', () => {
  const rand = rng(42);
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
  const maybe = (p: number, s: string) => (rand() < p ? s : '');

  const HOSTS = [
    'evil.example', 'Sub.Evil.Example', 'bücher.de', 'xn--p1ai.xn--p1ai', 'my_site.example.com', '8.8.8.8',
    '10.0.0.1', '192.168.1.1', '127.0.0.1', '[2606:4700::1111]', '[::1]', '[fe80::1]', 'localhost', 'app.localhost',
    '0x7f.1', '1.2.3', 'intranet',
  ];

  // A realistic URL with random parts, then randomly defanged and wrapped.
  const structured = () => {
    let u =
      pick(['http://', 'https://', 'ftp://', 'HTTPS://', '']) +
      maybe(0.2, 'user:pw@') +
      pick(HOSTS) +
      maybe(0.2, ':8443') +
      maybe(0.7, '/p/a,b(c)') +
      maybe(0.5, '?token=secret&x=1') +
      maybe(0.5, '#frag');
    if (rand() < 0.5) u = u.replace(/\./g, pick(['[.]', '(.)', '[dot]', '{.}']));
    if (rand() < 0.3) u = u.replace(/^http/i, 'hxxp');
    if (rand() < 0.2) u = u.replace('://', '[://]');
    return pick(['', '"', '<', '(']) + u + pick(['', '"', '>', ')', '.', ',']);
  };
  const noise = () =>
    Array.from({ length: 1 + Math.floor(rand() * 12) }, () => pick(PIECES)).join('');

  const inputs = Array.from({ length: 3000 }, () =>
    Array.from({ length: 1 + Math.floor(rand() * 3) }, () => (rand() < 0.7 ? structured() : noise())).join(
      pick([' ', ', ', '\n', ';']),
    ),
  );

  it('never throws and upholds the privacy invariants', () => {
    for (const mode of URL_PRIVACY_MODES) {
      for (const input of inputs) {
        const results = parseInput(input, mode);
        for (const r of results) {
          if (r.kind !== 'ioc') continue;
          const { type, value } = r.ioc;
          if (type === 'url') {
            const u = new URL(value);
            expect(u.hash, input).toBe('');
            expect(u.username + u.password, input).toBe('');
            expect(isPrivateHost(u.hostname), input).toBe(false);
            if (mode === 'strip') expect(u.search, input).toBe('');
          }
          if (type === 'ipv4' || type === 'ipv6') expect(isPrivateIp(value), input).toBe(false);
          if (mode === 'domain') expect(type, input).not.toBe('url');
        }
      }
    }
  });

  it('the generated inputs exercise every outcome', () => {
    const seen = new Set<string>();
    for (const input of inputs) {
      for (const r of parseInput(input, 'full')) seen.add(r.kind === 'ioc' ? r.ioc.type : r.kind);
    }
    for (const k of ['url', 'domain', 'ipv4', 'private', 'unsupported']) expect(seen).toContain(k);
  });

  it('handles a large paste quickly', () => {
    const big = Array.from({ length: 20_000 }, (_, i) => `host${i}[.]example[.]com`).join('\n');
    const start = performance.now();
    const r = parseInput(big, 'strip');
    expect(performance.now() - start).toBeLessThan(2000);
    expect(r.filter((x) => x.kind === 'ioc')).toHaveLength(20);
  });
});

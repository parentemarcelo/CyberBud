import { describe, expect, it } from 'vitest';
import { detect } from '../../src/lib/ioc/detect';
import type { IocType } from '../../src/lib/types';

type Case = [input: string, type: IocType, value: string];

const MD5 = 'd41d8cd98f00b204e9800998ecf8427e';
const SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
const SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('detect: hashes', () => {
  it.each<Case>([
    [MD5, 'md5', MD5],
    [SHA1, 'sha1', SHA1],
    [SHA256, 'sha256', SHA256],
    [SHA256.toUpperCase(), 'sha256', SHA256],
    [MD5.toUpperCase(), 'md5', MD5],
  ])('%s → %s', (input, type, value) => {
    expect(detect(input)).toEqual({ raw: input, type, value });
  });

  it.each([
    ['64 chars, not hex', 'g'.repeat(64)],
    ['hex, wrong length 31', MD5.slice(0, 31)],
    ['hex, length 33', `${MD5}a`],
    ['hex, length 63', SHA256.slice(0, 63)],
  ])('%s → unsupported', (_label, input) => {
    expect(detect(input)).toBeNull();
  });
});

describe('detect: IPv4', () => {
  it.each<Case>([
    ['8.8.8.8', 'ipv4', '8.8.8.8'],
    ['0.0.0.0', 'ipv4', '0.0.0.0'],
    ['255.255.255.255', 'ipv4', '255.255.255.255'],
    ['10.0.0.5', 'ipv4', '10.0.0.5'],
  ])('%s → %s', (input, type, value) => {
    expect(detect(input)).toEqual({ raw: input, type, value });
  });

  it.each([
    ['octet over 255', '1.2.3.256'],
    ['leading zero', '01.2.3.4'],
    ['leading zero in last octet', '1.2.3.04'],
    ['three octets', '1.2.3'],
    ['five octets', '1.2.3.4.5'],
    ['CIDR range', '10.0.0.0/8'],
    ['negative', '1.2.3.-4'],
  ])('%s (%s) → unsupported', (_label, input) => {
    expect(detect(input)).toBeNull();
  });
});

describe('detect: IPv6', () => {
  it.each<Case>([
    ['2001:db8::1', 'ipv6', '2001:db8::1'],
    ['2001:0DB8:0000:0000:0000:0000:0000:0001', 'ipv6', '2001:db8::1'],
    ['[2001:db8::1]', 'ipv6', '2001:db8::1'],
    ['::1', 'ipv6', '::1'],
    ['fe80::', 'ipv6', 'fe80::'],
    ['::ffff:1.2.3.4', 'ipv6', '::ffff:102:304'],
  ])('%s → %s', (input, type, value) => {
    expect(detect(input)).toEqual({ raw: input, type, value });
  });

  it.each([
    ['too many groups', '1:2:3:4:5:6:7:8:9'],
    ['two "::"', '1::2::3'],
    ['non-hex group', '2001:db8::xyz'],
    ['zone id', 'fe80::1%eth0'],
  ])('%s (%s) → unsupported', (_label, input) => {
    expect(detect(input)).toBeNull();
  });
});

describe('detect: URLs', () => {
  it.each<Case>([
    ['https://example.com', 'url', 'https://example.com/'],
    ['HTTPS://EXAMPLE.COM', 'url', 'https://example.com/'],
    ['http://example.com/Path?Q=1#frag', 'url', 'http://example.com/Path?Q=1#frag'],
    ['ftp://files.example.org/a.zip', 'url', 'ftp://files.example.org/a.zip'],
    ['example.com/path', 'url', 'http://example.com/path'],
    ['example.com:8080/path', 'url', 'http://example.com:8080/path'],
    ['https://bücher.de/x', 'url', 'https://xn--bcher-kva.de/x'],
    ['http://1.2.3.4/payload.exe', 'url', 'http://1.2.3.4/payload.exe'],
    ['http://[2001:db8::1]/x', 'url', 'http://[2001:db8::1]/x'],
    ['1.2.3.4/admin', 'url', 'http://1.2.3.4/admin'],
    ['https://en.wikipedia.org/wiki/Foo_(bar)', 'url', 'https://en.wikipedia.org/wiki/Foo_(bar)'],
  ])('%s → %s', (input, type, value) => {
    expect(detect(input)).toEqual({ raw: input, type, value });
  });

  it('removes embedded credentials', () => {
    expect(detect('https://user:secret@example.com/x')?.value).toBe('https://example.com/x');
  });

  it.each([
    ['javascript scheme', 'javascript:alert(1)'],
    ['file scheme', 'file:///etc/passwd'],
    ['mailto scheme', 'mailto:user@example.com'],
    ['single-label host', 'http://intranet/x'],
    ['invalid host', 'http://exa$mple.com/x'],
    ['scheme only', 'https://'],
  ])('%s (%s) → unsupported', (_label, input) => {
    expect(detect(input)).toBeNull();
  });
});

describe('detect: domains', () => {
  it.each<Case>([
    ['example.com', 'domain', 'example.com'],
    ['EXAMPLE.COM', 'domain', 'example.com'],
    ['sub.example.co.uk', 'domain', 'sub.example.co.uk'],
    ['xn--bcher-kva.de', 'domain', 'xn--bcher-kva.de'],
    ['bücher.de', 'domain', 'xn--bcher-kva.de'],
    ['example.xn--p1ai', 'domain', 'example.xn--p1ai'],
    ['a-b.example', 'domain', 'a-b.example'],
    ['foo.localhost', 'domain', 'foo.localhost'],
    ['my_site.example.com', 'domain', 'my_site.example.com'],
  ])('%s → %s', (input, type, value) => {
    expect(detect(input)).toEqual({ raw: input, type, value });
  });

  it.each([
    ['single label', 'example'],
    ['email', 'user@example.com'],
    ['numeric TLD', 'example.123'],
    ['label starts with hyphen', '-bad.example.com'],
    ['label ends with hyphen', 'bad-.example.com'],
    ['empty label', 'example..com'],
    ['underscore in TLD', 'example.c_om'],
    ['dollar sign', 'exa$mple.com'],
    ['label over 63 chars', `${'a'.repeat(64)}.com`],
    ['one-letter TLD', 'example.c'],
    ['empty', ''],
    ['whitespace', '   '],
    ['plain word', 'hello'],
  ])('%s (%s) → unsupported', (_label, input) => {
    expect(detect(input)).toBeNull();
  });
});

describe('detect: raw is preserved', () => {
  it('keeps the original token as raw', () => {
    expect(detect('EXAMPLE.COM')?.raw).toBe('EXAMPLE.COM');
  });
});

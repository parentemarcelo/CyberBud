import { describe, expect, it } from 'vitest';
import { isPrivateHost, isPrivateIp, parseIpv6, privateRange } from '../../src/lib/ioc/private';

// For each range: the first and last address are private, and the addresses
// just outside it are public (when that neighbour isn't itself reserved).
describe('IPv4 range boundaries (SPEC F1)', () => {
  it.each([
    // [below (public or null), first, last, above (public or null)]
    ['0.0.0.0/8', null, '0.0.0.0', '0.255.255.255', '1.0.0.0'],
    ['10.0.0.0/8', '9.255.255.255', '10.0.0.0', '10.255.255.255', '11.0.0.0'],
    ['100.64.0.0/10', '100.63.255.255', '100.64.0.0', '100.127.255.255', '100.128.0.0'],
    ['127.0.0.0/8', '126.255.255.255', '127.0.0.0', '127.255.255.255', '128.0.0.0'],
    ['169.254.0.0/16', '169.253.255.255', '169.254.0.0', '169.254.255.255', '169.255.0.0'],
    ['172.16.0.0/12', '172.15.255.255', '172.16.0.0', '172.31.255.255', '172.32.0.0'],
    ['192.0.0.0/24', '191.255.255.255', '192.0.0.0', '192.0.0.255', '192.0.1.0'],
    ['192.0.2.0/24', '192.0.1.255', '192.0.2.0', '192.0.2.255', '192.0.3.0'],
    ['192.168.0.0/16', '192.167.255.255', '192.168.0.0', '192.168.255.255', '192.169.0.0'],
    ['198.18.0.0/15', '198.17.255.255', '198.18.0.0', '198.19.255.255', '198.20.0.0'],
    ['198.51.100.0/24', '198.51.99.255', '198.51.100.0', '198.51.100.255', '198.51.101.0'],
    ['203.0.113.0/24', '203.0.112.255', '203.0.113.0', '203.0.113.255', '203.0.114.0'],
    ['224.0.0.0/4 + 240.0.0.0/4', '223.255.255.255', '224.0.0.0', '255.255.255.255', null],
  ])('%s', (_range, below, first, last, above) => {
    expect(isPrivateIp(first!)).toBe(true);
    expect(isPrivateIp(last!)).toBe(true);
    if (below) expect(isPrivateIp(below)).toBe(false);
    if (above) expect(isPrivateIp(above)).toBe(false);
  });

  it('public addresses are not private', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '185.199.108.153']) {
      expect(isPrivateIp(ip)).toBe(false);
    }
  });

  it('labels the matching range', () => {
    expect(privateRange('10.0.0.5')).toBe('Private (RFC 1918)');
    expect(privateRange('127.0.0.1')).toBe('Loopback');
    expect(privateRange('100.100.1.1')).toBe('Carrier-grade NAT (RFC 6598)');
    expect(privateRange('8.8.8.8')).toBeNull();
  });
});

describe('IPv6 ranges', () => {
  it.each([
    ['::', 'Unspecified'],
    ['::1', 'Loopback'],
    ['fc00::', 'Unique local'],
    ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'Unique local'],
    ['fe80::', 'Link-local'],
    ['febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'Link-local'],
    ['fec0::1', 'Site-local (deprecated)'],
    ['ff02::1', 'Multicast'],
    ['2001:db8::', 'Documentation'],
    ['::ffff:127.0.0.1', 'Loopback'],
    ['2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'Documentation'],
    ['100::1', 'Discard-only'],
    ['::2', 'Reserved (IETF)'],
    ['ff::1', 'Reserved (IETF)'],
  ])('%s → %s', (ip, label) => {
    expect(privateRange(ip)).toBe(label);
  });

  it.each([
    ['fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'just below fc00::/7'],
    ['fe00::', 'just above fc00::/7'],
    ['2001:db9::', 'just above 2001:db8::/32'],
    ['2001:db7:ffff:ffff:ffff:ffff:ffff:ffff', 'just below 2001:db8::/32'],
    ['2606:4700:4700::1111', 'Cloudflare DNS'],
    ['2001:4860:4860::8888', 'Google DNS'],
  ])('%s is public (%s)', (ip) => {
    expect(isPrivateIp(ip)).toBe(false);
  });

  it('checks the IPv4 inside IPv4-mapped and NAT64 addresses', () => {
    expect(isPrivateIp('::ffff:10.0.0.1')).toBe(true);
    expect(isPrivateIp('::ffff:a00:1')).toBe(true); // same, hex form
    expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false);
    expect(isPrivateIp('64:ff9b::192.168.1.1')).toBe(true);
    expect(isPrivateIp('64:ff9b::8.8.8.8')).toBe(false);
  });
});

describe('parseIpv6', () => {
  it('expands compressed forms', () => {
    expect(Array.from(parseIpv6('::1')!)).toEqual([...Array<number>(15).fill(0), 1]);
    expect(Array.from(parseIpv6('2001:db8::1')!.slice(0, 4))).toEqual([0x20, 0x01, 0x0d, 0xb8]);
  });

  it('rejects malformed input', () => {
    for (const s of ['1::2::3', '1:2:3:4:5:6:7:8:9', '12345::', 'gggg::', '1.2.3.4', '::ffff:1.2.3', '']) {
      expect(parseIpv6(s)).toBeNull();
    }
  });

  it('accepts a full 8-group address and the IPv4 tail form', () => {
    expect(parseIpv6('1:2:3:4:5:6:7:8')).not.toBeNull();
    expect(parseIpv6('1:2:3:4:5:6:1.2.3.4')).not.toBeNull();
  });
});

describe('isPrivateHost (URL hosts)', () => {
  it.each([
    ['localhost', true],
    ['LOCALHOST', true],
    ['app.localhost', true],
    ['10.1.2.3', true],
    ['[::1]', true],
    ['[fe80::1]', true],
    ['example.com', false],
    ['8.8.8.8', false],
    ['[2606:4700:4700::1111]', false],
    ['localhost.example.com', false],
  ])('%s → %s', (host, expected) => {
    expect(isPrivateHost(host)).toBe(expected);
  });
});

describe('garbage input', () => {
  it('is never private', () => {
    for (const s of ['', 'example.com', '999.1.1.1', 'not-an-ip']) {
      expect(isPrivateIp(s)).toBe(false);
    }
  });
});

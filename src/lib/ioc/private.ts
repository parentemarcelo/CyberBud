// Private/reserved address filter (docs/SPEC.md F1 "Rules", §9 S6).
// Matching addresses are shown to the user but never sent to any source.

interface Cidr {
  bytes: Uint8Array;
  bits: number;
  label: string;
}

const IPV4_RANGES: readonly Cidr[] = [
  ['0.0.0.0/8', '"This" network'],
  ['10.0.0.0/8', 'Private (RFC 1918)'],
  ['100.64.0.0/10', 'Carrier-grade NAT (RFC 6598)'],
  ['127.0.0.0/8', 'Loopback'],
  ['169.254.0.0/16', 'Link-local'],
  ['172.16.0.0/12', 'Private (RFC 1918)'],
  ['192.0.0.0/24', 'IETF protocol assignments'],
  ['192.0.2.0/24', 'Documentation (TEST-NET-1)'],
  ['192.168.0.0/16', 'Private (RFC 1918)'],
  ['198.18.0.0/15', 'Benchmarking'],
  ['198.51.100.0/24', 'Documentation (TEST-NET-2)'],
  ['203.0.113.0/24', 'Documentation (TEST-NET-3)'],
  ['224.0.0.0/4', 'Multicast'],
  ['240.0.0.0/4', 'Reserved (incl. broadcast)'],
].map(([cidr, label]) => toCidr(cidr!, label!, parseIpv4));

const IPV6_RANGES: readonly Cidr[] = [
  ['::/128', 'Unspecified'],
  ['::1/128', 'Loopback'],
  ['::/8', 'Reserved (IETF)'],
  ['100::/64', 'Discard-only'],
  ['2001:db8::/32', 'Documentation'],
  ['fc00::/7', 'Unique local'],
  ['fe80::/10', 'Link-local'],
  ['fec0::/10', 'Site-local (deprecated)'],
  ['ff00::/8', 'Multicast'],
].map(([cidr, label]) => toCidr(cidr!, label!, parseIpv6));

/** IPv6 prefixes that embed an IPv4 address in their last 32 bits. */
const IPV4_EMBEDDING: readonly Cidr[] = [
  ['::ffff:0:0/96', 'IPv4-mapped'],
  ['64:ff9b::/96', 'NAT64'],
].map(([cidr, label]) => toCidr(cidr!, label!, parseIpv6));

/**
 * Returns the reserved-range label (e.g. "Loopback") when `ip` must not be
 * sent, or null when it is a public address. Unparseable input returns null.
 */
export function privateRange(ip: string): string | null {
  const v4 = parseIpv4(ip);
  if (v4) return match(v4, IPV4_RANGES);

  const v6 = parseIpv6(ip);
  if (!v6) return null;
  // Checked first: ::ffff:10.0.0.1 is as private as 10.0.0.1, and
  // ::ffff:8.8.8.8 is as public as 8.8.8.8 even though it sits inside ::/8.
  if (match(v6, IPV4_EMBEDDING)) return match(v6.slice(12), IPV4_RANGES);
  return match(v6, IPV6_RANGES);
}

export function isPrivateIp(ip: string): boolean {
  return privateRange(ip) !== null;
}

/**
 * True for URL/host names that point at the local machine or a reserved
 * address: `localhost`, `*.localhost`, private IPv4, `[private IPv6]`.
 */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const ip = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  return isPrivateIp(ip);
}

// ---------- parsing ----------

export function parseIpv4(s: string): Uint8Array | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i]!;
    if (!/^(?:0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

export function parseIpv6(s: string): Uint8Array | null {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(':')) return null;

  // Optional dotted IPv4 tail, e.g. ::ffff:1.2.3.4
  let tail: Uint8Array | null = null;
  let head = s;
  const lastColon = s.lastIndexOf(':');
  if (s.slice(lastColon + 1).includes('.')) {
    tail = parseIpv4(s.slice(lastColon + 1));
    if (!tail) return null;
    head = s.slice(0, lastColon + 1);
    // "::" before the tail must stay a "::"; a single ":" separator is dropped.
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }

  const groupsNeeded = tail ? 6 : 8;
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const toGroups = (x: string) => (x === '' ? [] : x.split(':'));
  const left = toGroups(halves[0]!);
  const right = halves.length === 2 ? toGroups(halves[1]!) : [];
  const missing = groupsNeeded - left.length - right.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

  const groups = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...right];
  const out = new Uint8Array(16);
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i]!;
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  }
  if (tail) out.set(tail, 12);
  return out;
}

// ---------- CIDR helpers ----------

function toCidr(cidr: string, label: string, parse: (s: string) => Uint8Array | null): Cidr {
  const [addr, bits] = cidr.split('/');
  const bytes = parse(addr!);
  if (!bytes) throw new Error(`Bad CIDR constant: ${cidr}`);
  return { bytes, bits: Number(bits), label };
}

function match(addr: Uint8Array, ranges: readonly Cidr[]): string | null {
  for (const r of ranges) {
    if (r.bytes.length === addr.length && inPrefix(addr, r.bytes, r.bits)) return r.label;
  }
  return null;
}

function inPrefix(addr: Uint8Array, prefix: Uint8Array, bits: number): boolean {
  const full = bits >> 3;
  for (let i = 0; i < full; i++) if (addr[i] !== prefix[i]) return false;
  const rest = bits & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (addr[full]! & mask) === (prefix[full]! & mask);
}

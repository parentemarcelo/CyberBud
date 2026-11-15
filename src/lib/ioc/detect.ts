// IOC type detection and normalization (docs/SPEC.md F1 "Detection").
// Input is one already refanged and cleaned token. First match wins:
// hash → IPv4 → IPv6 → URL → domain → unsupported.
import type { Ioc, IocType } from '../types';

const HEX = /^[0-9a-f]+$/i;
const HASH_BY_LENGTH: Readonly<Record<number, IocType>> = { 32: 'md5', 40: 'sha1', 64: 'sha256' };

/** Four octets 0–255, no leading zeros ("01" is rejected). */
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);

/** IPv4 with a CIDR suffix, e.g. 10.0.0.0/8: a range, not a URL. */
const IPV4_CIDR = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;

const SCHEME_URL = /^(?:https?|ftp):\/\//i;
const ANY_SCHEME = /^[a-z][a-z0-9+.-]*:/i;

/** host[:port]/… without a scheme, e.g. example.com/path. */
const SCHEMELESS_URL = /^([^/?#@\s]+?)(?::\d{1,5})?\//;

/** Characters that can never appear in a bare domain token. */
const NOT_DOMAIN = /[/:@?#\s\\%]/;

// Underscores are not valid in hostnames but occur in real malicious hosts,
// so they are allowed in every label except the TLD.
const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/** Detect and normalize one token. Returns null when unsupported. */
export function detect(token: string): Ioc | null {
  const raw = token;
  const t = token.trim();
  if (t === '') return null;

  const hashType = HEX.test(t) ? HASH_BY_LENGTH[t.length] : undefined;
  if (hashType) return { raw, value: t.toLowerCase(), type: hashType };

  if (IPV4.test(t)) return { raw, value: t, type: 'ipv4' };

  const v6 = normalizeIpv6(t);
  if (v6) return { raw, value: v6, type: 'ipv6' };

  if (IPV4_CIDR.test(t)) return null;

  const url = normalizeUrl(t);
  if (url) return { raw, value: url, type: 'url' };

  const domain = normalizeDomain(t);
  if (domain) return { raw, value: domain, type: 'domain' };

  return null;
}

/** Compressed lowercase IPv6, or null. Accepts the bracketed form `[2001:db8::1]`. */
export function normalizeIpv6(token: string): string | null {
  const t = token.startsWith('[') && token.endsWith(']') ? token.slice(1, -1) : token;
  if (!t.includes(':') || !/^[0-9a-f:.]+$/i.test(t)) return null;
  try {
    const host = new URL(`http://[${t}]/`).hostname; // "[2001:db8::1]"
    return host.slice(1, -1);
  } catch {
    return null;
  }
}

/** Valid hostname → lowercase punycode, or null (SPEC F1 "domain" rule). */
export function normalizeDomain(token: string): string | null {
  if (NOT_DOMAIN.test(token) || token.length > 253) return null;
  let host: string;
  try {
    host = new URL(`http://${token}/`).hostname;
  } catch {
    return null;
  }
  return isValidHostname(host) ? host : null;
}

/** Checks an already-lowercased ASCII (punycode) hostname. */
export function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => LABEL.test(l))) return false;
  return TLD.test(labels.at(-1)!);
}

/**
 * Normalized URL (`URL.href`: lowercase punycode host, credentials removed),
 * or null. Accepts http/https/ftp, or a scheme-less `host/path` which gets
 * `http://` prepended. The host must be a valid domain, IPv4 or IPv6.
 */
export function normalizeUrl(token: string): string | null {
  let candidate: string;
  if (SCHEME_URL.test(token)) {
    candidate = token;
  } else if (ANY_SCHEME.test(token) && !SCHEMELESS_URL.test(token)) {
    return null; // other schemes (javascript:, file:, mailto:…) are unsupported
  } else if (SCHEMELESS_URL.test(token)) {
    candidate = `http://${token}`;
  } else {
    return null;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }
  if (!isValidUrlHost(url.hostname)) return null;
  // Never send credentials embedded in a URL (SPEC §9).
  url.username = '';
  url.password = '';
  return url.href;
}

/** URL hostnames: domain, IPv4, or bracketed IPv6. `localhost` is accepted so it can be flagged private. */
function isValidUrlHost(host: string): boolean {
  if (host.startsWith('[')) return true; // URL already validated the IPv6 literal
  if (IPV4.test(host)) return true;
  if (host === 'localhost') return true;
  return isValidHostname(host);
}

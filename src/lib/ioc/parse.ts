// Batch input parsing (docs/SPEC.md F1): split → refang → clean → detect →
// URL privacy mode → private filter → dedupe → batch cap.
import { MAX_BATCH_SIZE } from '../constants';
import type { Ioc, ParseResult, UrlPrivacyMode } from '../types';
import { detect, normalizeIpv6 } from './detect';
import { isPrivateHost, isPrivateIp } from './private';
import { cleanToken, refang, tightenDefangs } from './refang';

/** A token that starts like a URL (real or defanged scheme). */
const URLISH = /^\s*(?:[a-z][a-z0-9+.-]*:\/\/|h[xt]{2}ps?\[|fxp\[)|\//i;
/** In URL-like chunks, only split on , or ; when another URL follows. */
const URL_SEPARATOR = /[,;](?=[a-z][a-z0-9+.-]*:\/\/|(?:hxxps?|fxp)\[)/i;

/**
 * Parse free text into one result per distinct token, in input order.
 * At most MAX_BATCH_SIZE IOCs are returned as `ioc`; later ones are `skipped`.
 */
export function parseInput(text: string, urlMode: UrlPrivacyMode): ParseResult[] {
  const results: ParseResult[] = [];
  const seen = new Set<string>();
  let iocCount = 0;

  for (const token of splitTokens(text)) {
    const cleaned = cleanToken(refang(token));
    if (cleaned === '') continue;

    const detected = detect(cleaned);
    const item = detected ? classify({ ...detected, raw: token }, urlMode) : unsupported(token);

    const key = dedupeKey(item);
    if (seen.has(key)) continue;
    seen.add(key);

    if (item.kind === 'ioc') {
      if (iocCount >= MAX_BATCH_SIZE) {
        results.push({ kind: 'skipped', raw: token });
        continue;
      }
      iocCount++;
    }
    results.push(item);
  }
  return results;
}

/** Split on whitespace, commas and semicolons without breaking URLs or spaced defangs. */
export function splitTokens(text: string): string[] {
  const tokens: string[] = [];
  for (const chunk of tightenDefangs(text).split(/\s+/)) {
    if (chunk === '') continue;
    const parts = URLISH.test(chunk) ? chunk.split(URL_SEPARATOR) : chunk.split(/[,;]+/);
    for (const p of parts) if (p !== '') tokens.push(p);
  }
  return tokens;
}

/** Apply the URL privacy mode, then the private-address filter. */
function classify(ioc: Ioc, urlMode: UrlPrivacyMode): ParseResult {
  const shaped = ioc.type === 'url' ? applyUrlMode(ioc, urlMode) : ioc;

  if ((shaped.type === 'ipv4' || shaped.type === 'ipv6') && isPrivateIp(shaped.value)) {
    return { kind: 'private', raw: ioc.raw, value: shaped.value };
  }
  if (shaped.type === 'url' && isPrivateHost(new URL(shaped.value).hostname)) {
    return { kind: 'private', raw: ioc.raw, value: shaped.value };
  }
  if (shaped.type === 'domain' && isPrivateHost(shaped.value)) {
    return { kind: 'private', raw: ioc.raw, value: shaped.value };
  }
  return { kind: 'ioc', ioc: shaped };
}

/**
 * full   → URL as detected, minus fragment
 * strip  → also without query string
 * domain → only the host, as a domain/IPv4/IPv6 IOC
 */
export function applyUrlMode(ioc: Ioc, mode: UrlPrivacyMode): Ioc {
  const url = new URL(ioc.value);
  url.hash = '';

  if (mode === 'domain') {
    const host = url.hostname;
    if (host.startsWith('[')) {
      return { raw: ioc.raw, value: normalizeIpv6(host) ?? host.slice(1, -1), type: 'ipv6' };
    }
    const asHost = detect(host);
    if (asHost && (asHost.type === 'ipv4' || asHost.type === 'domain')) {
      return { raw: ioc.raw, value: asHost.value, type: asHost.type };
    }
    // e.g. "localhost": keep as a URL host so the private filter catches it.
    return { raw: ioc.raw, value: `${url.protocol}//${host}/`, type: 'url' };
  }

  if (mode === 'strip') url.search = '';
  return { raw: ioc.raw, value: url.href, type: 'url' };
}

function unsupported(raw: string): ParseResult {
  return { kind: 'unsupported', raw };
}

function dedupeKey(item: ParseResult): string {
  switch (item.kind) {
    case 'ioc':
      return `ioc|${item.ioc.type}|${item.ioc.value}`;
    case 'private':
      return `private|${item.value}`;
    case 'unsupported':
    case 'skipped':
      return `${item.kind}|${item.raw}`;
  }
}

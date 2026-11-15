// ThreatFox adapter (docs/SPEC.md F3). JSON POST to /api/v1/.
// Docs: https://threatfox.abuse.ch/api/ (checked 2026-11-15).
// - search_ioc for URLs/domains (exact_match) and IPs (wildcard, then filtered
//   to `ip` or `ip:port`, because ThreatFox stores most IP IOCs as ip:port)
// - search_hash for MD5/SHA-256 (SHA-1 is not supported by ThreatFox)
// - IOCs older than 6 months are expired and not returned
// Blocklist semantics: found = malicious, not found = unknown.
import { RATE_LIMITS } from '../constants';
import type { Ioc, IocType, KeyTestResult, SourceAdapter, SourceResult } from '../types';
import { abuseChKeyTest, handleAbuseCh, postAbuseCh } from './abusech';
import { isRecord, notFound, num, result, rows, safeLink, str, tagList, textDate } from './common';

const API = 'https://threatfox-api.abuse.ch/api/v1/';
const WEB_HOST = 'threatfox.abuse.ch';
const SUPPORTED: ReadonlySet<IocType> = new Set(['url', 'domain', 'ipv4', 'ipv6', 'md5', 'sha256']);

export function threatfoxBody(ioc: Pick<Ioc, 'type' | 'value'>): Record<string, unknown> {
  switch (ioc.type) {
    case 'md5':
    case 'sha256':
      return { query: 'search_hash', hash: ioc.value };
    case 'ipv4':
    case 'ipv6':
      return { query: 'search_ioc', search_term: ioc.value, exact_match: false };
    default:
      return { query: 'search_ioc', search_term: ioc.value, exact_match: true };
  }
}

/** Keep only entries that really are this IOC (wildcard IP search can return 11.2.3.45 for 1.2.3.4). */
export function matchesIoc(ioc: Pick<Ioc, 'type' | 'value'>, entryIoc: unknown): boolean {
  if (ioc.type === 'md5' || ioc.type === 'sha256') return true; // search_hash matches samples, not IOC values
  if (typeof entryIoc !== 'string') return false;
  const v = entryIoc.trim().toLowerCase();
  const want = ioc.value.toLowerCase();
  if (ioc.type === 'ipv4') return v === want || v.startsWith(`${want}:`);
  if (ioc.type === 'ipv6') return v === want || v === `[${want}]` || v.startsWith(`[${want}]:`);
  if (ioc.type === 'url') return v === want || v === want.replace(/\/$/, '');
  return v === want;
}

export function parseThreatfox(ioc: Ioc, body: Record<string, unknown>): SourceResult {
  const all = Array.isArray(body.data) ? body.data.filter(isRecord) : [];
  const entries = all.filter((e) => matchesIoc(ioc, e.ioc));
  if (entries.length === 0) return notFoundResult(ioc);

  // Show the most confident entry; mention how many matched.
  const top = [...entries].sort((a, b) => (num(b.confidence_level) ?? 0) - (num(a.confidence_level) ?? 0))[0]!;
  const malware = str(top.malware_printable) ?? str(top.malware) ?? 'Unknown malware';
  const threat = str(top.threat_type_desc) ?? str(top.threat_type);
  const id = typeof top.id === 'string' || typeof top.id === 'number' ? String(top.id) : undefined;
  const link = id ? safeLink(`https://${WEB_HOST}/ioc/${encodeURIComponent(id)}/`, WEB_HOST) : undefined;

  return result('threatfox', ioc, {
    status: 'ok',
    verdict: 'malicious',
    headline: threat ? `${malware} · ${threat}` : malware,
    details: rows(
      ['Malware', malware],
      ['Aliases', str(top.malware_alias)],
      ['Threat type', threat],
      ['Confidence', num(top.confidence_level) !== undefined ? `${num(top.confidence_level)}%` : undefined],
      ['IOC', str(top.ioc)],
      ['IOC type', str(top.ioc_type_desc) ?? str(top.ioc_type)],
      ['First seen', textDate(top.first_seen)],
      ['Last seen', textDate(top.last_seen)],
      ['Tags', tagList(top.tags)],
      ['Reporter', str(top.reporter)],
      ['Matching entries', entries.length > 1 ? entries.length : undefined],
    ),
    ...(link && { link }),
  });
}

function notFoundResult(ioc: Ioc): SourceResult {
  return notFound('threatfox', ioc, 'Not in ThreatFox');
}

function request(ioc: Pick<Ioc, 'type' | 'value'>, apiKey: string, signal: AbortSignal) {
  return postAbuseCh({ url: API, json: threatfoxBody(ioc), apiKey, signal });
}

export const threatfox: SourceAdapter = {
  id: 'threatfox',
  name: 'ThreatFox',
  keyId: 'abusech',
  limits: RATE_LIMITS.threatfox,
  supports: (type) => SUPPORTED.has(type),

  async lookup(ioc, apiKey, signal): Promise<SourceResult> {
    const out = await request(ioc, apiKey, signal);
    const h = handleAbuseCh('threatfox', 'ThreatFox', ioc, out, () => notFoundResult(ioc));
    if ('done' in h) return h.done;
    return parseThreatfox(ioc, h.body);
  },

  async testKey(apiKey, signal): Promise<KeyTestResult> {
    return abuseChKeyTest(await request({ type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' }, apiKey, signal));
  },
};

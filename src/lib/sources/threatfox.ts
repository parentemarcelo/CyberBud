// ThreatFox adapter (docs/SPEC.md F3). JSON POST to /api/v1/.
// Docs: https://threatfox.abuse.ch/api/ (checked 2026-11-15).
// - search_ioc for URLs, domains and hashes (exact_match) and IPs (wildcard,
//   then filtered to `ip` or `ip:port`, because ThreatFox stores most IP IOCs
//   as ip:port)
// - Hashes listed as IOCs (md5_hash/sha1_hash/sha256_hash) are only found by
//   search_ioc (verified live 2026-11-15). If that finds nothing, MD5/SHA-256
//   fall back to search_hash, which finds IOCs linked to a malware sample.
//   search_hash rejects SHA-1.
// - IOCs older than 6 months are expired and not returned
// Blocklist semantics: found = malicious, not found = unknown.
import { RATE_LIMITS } from '../constants';
import type { Ioc, IocType, KeyTestResult, SourceAdapter, SourceResult } from '../types';
import { abuseChKeyTest, handleAbuseCh, postAbuseCh } from './abusech';
import { isRecord, notFound, num, result, rows, safeLink, str, tagList, textDate } from './common';

const API = 'https://threatfox-api.abuse.ch/api/v1/';
const WEB_HOST = 'threatfox.abuse.ch';
const SUPPORTED: ReadonlySet<IocType> = new Set(['url', 'domain', 'ipv4', 'ipv6', 'md5', 'sha1', 'sha256']);

/** Primary request: search_ioc for every type. */
export function threatfoxBody(ioc: Pick<Ioc, 'type' | 'value'>): Record<string, unknown> {
  switch (ioc.type) {
    case 'ipv4':
    case 'ipv6':
      return { query: 'search_ioc', search_term: ioc.value, exact_match: false };
    default:
      return { query: 'search_ioc', search_term: ioc.value, exact_match: true };
  }
}

/** Fallback for MD5/SHA-256 not listed as IOCs: IOCs linked to that malware sample. */
export function threatfoxSampleBody(ioc: Pick<Ioc, 'type' | 'value'>): Record<string, unknown> | undefined {
  return ioc.type === 'md5' || ioc.type === 'sha256' ? { query: 'search_hash', hash: ioc.value } : undefined;
}

/** Keep only entries that really are this IOC (wildcard IP search can return 11.2.3.45 for 1.2.3.4). */
export function matchesIoc(ioc: Pick<Ioc, 'type' | 'value'>, entryIoc: unknown): boolean {
  if (typeof entryIoc !== 'string') return false;
  const v = entryIoc.trim().toLowerCase();
  const want = ioc.value.toLowerCase();
  if (ioc.type === 'ipv4') return v === want || v.startsWith(`${want}:`);
  if (ioc.type === 'ipv6') return v === want || v === `[${want}]` || v.startsWith(`[${want}]:`);
  if (ioc.type === 'url') return v === want || v === want.replace(/\/$/, '');
  return v === want;
}

/**
 * `linkedSample`: results come from search_hash, i.e. IOCs linked to the
 * sample rather than the hash itself, so they are not filtered by value.
 */
export function parseThreatfox(ioc: Ioc, body: Record<string, unknown>, linkedSample = false): SourceResult {
  const all = Array.isArray(body.data) ? body.data.filter(isRecord) : [];
  const entries = linkedSample ? all : all.filter((e) => matchesIoc(ioc, e.ioc));
  if (entries.length === 0) return notFoundResult(ioc);

  // Show the most confident entry; mention how many matched.
  const top = [...entries].sort((a, b) => (num(b.confidence_level) ?? 0) - (num(a.confidence_level) ?? 0))[0]!;
  const malware = str(top.malware_printable) ?? str(top.malware) ?? 'Unknown malware';
  const threat = shortThreat(str(top.threat_type));
  const threatDesc = str(top.threat_type_desc);
  const id = typeof top.id === 'string' || typeof top.id === 'number' ? String(top.id) : undefined;
  const link = id ? safeLink(`https://${WEB_HOST}/ioc/${encodeURIComponent(id)}/`, WEB_HOST) : undefined;

  return result('threatfox', ioc, {
    status: 'ok',
    verdict: 'malicious',
    headline: (linkedSample ? 'Linked to ' : '') + (threat ? `${malware} · ${threat}` : malware),
    details: rows(
      ['Malware', malware],
      ['Aliases', str(top.malware_alias)],
      ['Threat type', threatDesc ?? threat],
      ['Confidence', num(top.confidence_level) !== undefined ? `${num(top.confidence_level)}%` : undefined],
      ['IOC', str(top.ioc)],
      ['Match', linkedSample ? 'IOC linked to this malware sample' : undefined],
      ['Compromised legitimate site', top.is_compromised === true ? 'Yes' : undefined],
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

/** "botnet_cc" → "botnet C2", "payload_delivery" → "payload delivery". */
export function shortThreat(type: string | undefined): string | undefined {
  if (!type) return undefined;
  return type.replace(/_cc$/i, ' C2').replace(/_/g, ' ');
}

function notFoundResult(ioc: Ioc): SourceResult {
  return notFound('threatfox', ioc, 'Not in ThreatFox');
}

function post(json: Record<string, unknown>, apiKey: string, signal: AbortSignal) {
  return postAbuseCh({ url: API, json, apiKey, signal });
}

export const threatfox: SourceAdapter = {
  id: 'threatfox',
  name: 'ThreatFox',
  keyId: 'abusech',
  limits: RATE_LIMITS.threatfox,
  supports: (type) => SUPPORTED.has(type),

  async lookup(ioc, apiKey, signal): Promise<SourceResult> {
    const h = handleAbuseCh('threatfox', 'ThreatFox', ioc, await post(threatfoxBody(ioc), apiKey, signal), () =>
      notFoundResult(ioc),
    );
    const primary = 'done' in h ? h.done : parseThreatfox(ioc, h.body);

    const sampleBody = threatfoxSampleBody(ioc);
    if (primary.status !== 'not_found' || !sampleBody) return primary;

    const h2 = handleAbuseCh('threatfox', 'ThreatFox', ioc, await post(sampleBody, apiKey, signal), () =>
      notFoundResult(ioc),
    );
    return 'done' in h2 ? h2.done : parseThreatfox(ioc, h2.body, true);
  },

  async testKey(apiKey, signal): Promise<KeyTestResult> {
    return abuseChKeyTest(await post(threatfoxBody({ type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' }), apiKey, signal));
  },
};

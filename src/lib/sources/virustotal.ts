// VirusTotal API v3 adapter (docs/SPEC.md F3). Read-only GET lookups.
// Docs: https://docs.virustotal.com/reference/overview (checked 2026-11-15)
// Note from VT's docs: IOCs queried via the API may be added to the VT dataset.
import { RATE_LIMITS, VERDICT_THRESHOLDS } from '../constants';
import { requestJson } from '../http';
import type { Ioc, IocType, KeyTestResult, SourceAdapter, SourceResult, Verdict } from '../types';
import {
  bytes,
  errorResult,
  failureResult,
  isRecord,
  keyTestFromOutcome,
  notFound,
  num,
  result,
  rows,
  safeLink,
  str,
  UNEXPECTED,
  unixDate,
} from './common';

const API = 'https://www.virustotal.com/api/v3';
const GUI_HOST = 'www.virustotal.com';
const SUPPORTED: ReadonlySet<IocType> = new Set(['md5', 'sha1', 'sha256', 'domain', 'ipv4', 'ipv6', 'url']);

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

/** SPEC F3 verdict rules for VirusTotal. */
export function vtVerdict(stats: VtStats | undefined): Verdict {
  if (!stats) return 'unknown';
  const t = VERDICT_THRESHOLDS.virustotal;
  if (stats.malicious >= t.maliciousMin) return 'malicious';
  if (stats.malicious + stats.suspicious >= t.suspiciousDetectionsMin) return 'suspicious';
  return engines(stats) > 0 ? 'clean' : 'unknown';
}

/** Engines that gave a verdict (timeouts, failures and unsupported types are not counted). */
function engines(s: VtStats): number {
  return s.malicious + s.suspicious + s.harmless + s.undetected;
}

/** "12/94 engines", plus suspicious engines when any (so "0/92" never hides a detection). */
export function vtHeadline(s: VtStats): string {
  const base = `${s.malicious}/${engines(s)} engines`;
  return s.suspicious > 0 ? `${base} · ${s.suspicious} suspicious` : base;
}

/** VT URL identifier: unpadded URL-safe base64 of the URL (RFC 4648 §5). */
export function vtUrlId(url: string): string {
  const bin = Array.from(new TextEncoder().encode(url), (b) => String.fromCharCode(b)).join('');
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function vtEndpoint(ioc: Ioc): string {
  switch (ioc.type) {
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `${API}/files/${ioc.value}`;
    case 'domain':
      return `${API}/domains/${encodeURIComponent(ioc.value)}`;
    case 'ipv4':
    case 'ipv6':
      return `${API}/ip_addresses/${encodeURIComponent(ioc.value)}`;
    case 'url':
      return `${API}/urls/${vtUrlId(ioc.value)}`;
  }
}

/** GUI page for a found object (`id` from the response), or a search link otherwise. */
export function vtLink(ioc: Ioc, id?: string): string | undefined {
  const enc = encodeURIComponent;
  let url: string;
  if (ioc.type === 'url') url = id ? `https://${GUI_HOST}/gui/url/${enc(id)}` : `https://${GUI_HOST}/gui/search/${enc(enc(ioc.value))}`;
  else if (ioc.type === 'domain') url = `https://${GUI_HOST}/gui/domain/${enc(ioc.value)}`;
  else if (ioc.type === 'ipv4' || ioc.type === 'ipv6') url = `https://${GUI_HOST}/gui/ip-address/${enc(ioc.value)}`;
  else url = `https://${GUI_HOST}/gui/file/${enc(id ?? ioc.value)}`;
  return safeLink(url, GUI_HOST);
}

function parseStats(x: unknown): VtStats | undefined {
  if (!isRecord(x)) return undefined;
  const s = {
    malicious: num(x.malicious) ?? 0,
    suspicious: num(x.suspicious) ?? 0,
    harmless: num(x.harmless) ?? 0,
    undetected: num(x.undetected) ?? 0,
  };
  return engines(s) > 0 || s.malicious > 0 ? s : undefined;
}

/** Turn a VT response body into a SourceResult. Exported for fixture tests. */
export function parseVt(ioc: Ioc, json: unknown): SourceResult {
  const data = isRecord(json) && isRecord(json.data) ? json.data : undefined;
  const attrs = data && isRecord(data.attributes) ? data.attributes : undefined;
  if (!data || !attrs) return errorResult('virustotal', ioc, UNEXPECTED);

  const stats = parseStats(attrs.last_analysis_stats);
  const verdict = vtVerdict(stats);
  const headline = stats ? vtHeadline(stats) : 'Not analysed yet';
  const votes = isRecord(attrs.total_votes) ? attrs.total_votes : {};
  const common = rows(
    ['Malicious', stats?.malicious],
    ['Suspicious', stats?.suspicious],
    ['Harmless', stats?.harmless],
    ['Undetected', stats?.undetected],
    ['Community score', num(attrs.reputation)],
    ['Community votes', isRecord(attrs.total_votes) ? `${num(votes.malicious) ?? 0} malicious / ${num(votes.harmless) ?? 0} harmless` : undefined],
    ['Last analysis', unixDate(attrs.last_analysis_date)],
  );

  let specific: ReturnType<typeof rows>;
  if (ioc.type === 'md5' || ioc.type === 'sha1' || ioc.type === 'sha256') {
    const names = Array.isArray(attrs.names) ? attrs.names.slice(0, 5) : undefined;
    specific = rows(
      ['Name', str(attrs.meaningful_name)],
      ['Other names', names],
      ['Type', str(attrs.type_description)],
      ['Size', bytes(attrs.size)],
      ['SHA-256', str(attrs.sha256)],
      ['First seen', unixDate(attrs.first_submission_date)],
      ['Tags', Array.isArray(attrs.tags) ? attrs.tags : undefined],
    );
  } else if (ioc.type === 'domain') {
    const cats = isRecord(attrs.categories) ? [...new Set(Object.values(attrs.categories).map(String))] : undefined;
    specific = rows(
      ['Registrar', str(attrs.registrar)],
      ['Created', unixDate(attrs.creation_date)],
      ['Categories', cats],
      ['Tags', Array.isArray(attrs.tags) ? attrs.tags : undefined],
    );
  } else if (ioc.type === 'ipv4' || ioc.type === 'ipv6') {
    specific = rows(
      ['AS owner', str(attrs.as_owner)],
      ['ASN', num(attrs.asn)],
      ['Country', str(attrs.country)],
      ['Network', str(attrs.network)],
      ['Tags', Array.isArray(attrs.tags) ? attrs.tags : undefined],
    );
  } else {
    specific = rows(
      ['Final URL', str(attrs.last_final_url)],
      ['Title', str(attrs.title)],
      ['HTTP status', num(attrs.last_http_response_code)],
      ['First seen', unixDate(attrs.first_submission_date)],
    );
  }

  const link = vtLink(ioc, typeof data.id === 'string' ? data.id : undefined);
  return result('virustotal', ioc, {
    status: 'ok',
    verdict,
    headline,
    details: [...common, ...specific],
    ...(link && { link }),
  });
}

export const virustotal: SourceAdapter = {
  id: 'virustotal',
  name: 'VirusTotal',
  keyId: 'vt',
  limits: RATE_LIMITS.virustotal,
  supports: (type) => SUPPORTED.has(type),

  async lookup(ioc, apiKey, signal): Promise<SourceResult> {
    const out = await requestJson({
      url: vtEndpoint(ioc),
      headers: { 'x-apikey': apiKey, Accept: 'application/json' },
      secrets: [apiKey],
      signal,
    });
    if (out.kind === 'not_found') return notFound('virustotal', ioc, 'Not in VirusTotal', vtLink(ioc));
    const failure = failureResult('virustotal', ioc, out);
    if (failure) return failure;
    return parseVt(ioc, out.kind === 'ok' ? out.json : undefined);
  },

  async testKey(apiKey, signal): Promise<KeyTestResult> {
    const out = await requestJson({
      url: `${API}/ip_addresses/8.8.8.8`,
      headers: { 'x-apikey': apiKey, Accept: 'application/json' },
      secrets: [apiKey],
      signal,
    });
    return keyTestFromOutcome(out);
  },
};

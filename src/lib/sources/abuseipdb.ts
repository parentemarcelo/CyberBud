// AbuseIPDB API v2 CHECK adapter (docs/SPEC.md F3). IP addresses only.
// Docs: https://docs.abuseipdb.com/ (checked 2026-11-15)
import { RATE_LIMITS, VERDICT_THRESHOLDS } from '../constants';
import { requestJson } from '../http';
import type { Ioc, KeyTestResult, SourceAdapter, SourceResult, Verdict } from '../types';
import {
  errorResult,
  failureResult,
  isRecord,
  keyTestFromOutcome,
  num,
  result,
  rows,
  safeLink,
  str,
  textDate,
  UNEXPECTED,
} from './common';

const API = 'https://api.abuseipdb.com/api/v2/check';
const WEB_HOST = 'www.abuseipdb.com';
/** Report window used for the score (docs: 1–365, default 30). */
export const MAX_AGE_DAYS = 90;

export interface AbuseIpdbData {
  abuseConfidenceScore: number;
  totalReports: number;
  /** May be null when no whitelist lookup was performed. */
  isWhitelisted: boolean | null;
}

/** SPEC F3 verdict rules for AbuseIPDB. */
export function abuseIpdbVerdict(d: AbuseIpdbData): Verdict {
  const t = VERDICT_THRESHOLDS.abuseipdb;
  if (d.abuseConfidenceScore >= t.maliciousMin) return 'malicious';
  if (d.abuseConfidenceScore >= t.suspiciousMin) return 'suspicious';
  if (d.totalReports > 0 || d.isWhitelisted === true) return 'clean';
  return 'unknown';
}

export function abuseIpdbUrl(ip: string): string {
  return `${API}?${new URLSearchParams({ ipAddress: ip, maxAgeInDays: String(MAX_AGE_DAYS) })}`;
}

export function abuseIpdbLink(ip: string): string | undefined {
  return safeLink(`https://${WEB_HOST}/check/${encodeURIComponent(ip)}`, WEB_HOST);
}

export function parseAbuseIpdb(ioc: Ioc, json: unknown): SourceResult {
  const d = isRecord(json) && isRecord(json.data) ? json.data : undefined;
  const score = d ? num(d.abuseConfidenceScore) : undefined;
  const reports = d ? num(d.totalReports) : undefined;
  if (!d || score === undefined || reports === undefined) return errorResult('abuseipdb', ioc, UNEXPECTED);

  const whitelisted = d.isWhitelisted === true ? true : d.isWhitelisted === false ? false : null;
  const verdict = abuseIpdbVerdict({ abuseConfidenceScore: score, totalReports: reports, isWhitelisted: whitelisted });
  const headline = reports === 0 ? 'No reports' : `${score}% confidence · ${reports} report${reports === 1 ? '' : 's'}`;
  const link = abuseIpdbLink(ioc.value);

  return result('abuseipdb', ioc, {
    status: 'ok',
    verdict,
    headline,
    details: rows(
      ['Abuse confidence', `${score}%`],
      [`Reports (last ${MAX_AGE_DAYS} days)`, reports],
      ['Distinct reporters', num(d.numDistinctUsers)],
      ['Last reported', textDate(d.lastReportedAt)],
      ['ISP', str(d.isp)],
      ['Usage type', str(d.usageType)],
      ['Domain', str(d.domain)],
      ['Hostnames', Array.isArray(d.hostnames) ? d.hostnames : undefined],
      ['Country', str(d.countryName) ?? str(d.countryCode)],
      ['Tor exit node', d.isTor === true ? 'Yes' : undefined],
      ['Whitelisted', whitelisted === true ? 'Yes' : undefined],
    ),
    ...(link && { link }),
  });
}

function request(ip: string, apiKey: string, signal: AbortSignal) {
  return requestJson({
    url: abuseIpdbUrl(ip),
    headers: { Key: apiKey, Accept: 'application/json' },
    secrets: [apiKey],
    signal,
  });
}

export const abuseipdb: SourceAdapter = {
  id: 'abuseipdb',
  name: 'AbuseIPDB',
  keyId: 'abuseipdb',
  limits: RATE_LIMITS.abuseipdb,
  supports: (type) => type === 'ipv4' || type === 'ipv6',

  async lookup(ioc, apiKey, signal): Promise<SourceResult> {
    const out = await request(ioc.value, apiKey, signal);
    // AbuseIPDB answers every valid IP; a 404 means an unexpected endpoint problem.
    if (out.kind === 'not_found') return errorResult('abuseipdb', ioc, UNEXPECTED);
    const failure = failureResult('abuseipdb', ioc, out);
    if (failure) return failure;
    return parseAbuseIpdb(ioc, out.kind === 'ok' ? out.json : undefined);
  },

  async testKey(apiKey, signal): Promise<KeyTestResult> {
    return keyTestFromOutcome(await request('8.8.8.8', apiKey, signal));
  },
};

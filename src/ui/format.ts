// Pure display helpers for the UI (unit-tested).
import type { IocType, SourceId, SourceResult, Verdict } from '../lib/types';

export const TYPE_LABEL: Record<IocType, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
};

export const SOURCE_NAME: Record<SourceId, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  urlhaus: 'URLhaus',
  malwarebazaar: 'MalwareBazaar',
  threatfox: 'ThreatFox',
};

/** Verdicts are never shown by colour alone (SPEC §7): icon + word. */
export const VERDICT_LABEL: Record<Verdict, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'Clean',
  unknown: 'Unknown',
};

export const VERDICT_ICON: Record<Verdict, string> = {
  malicious: '✖',
  suspicious: '!',
  clean: '✓',
  unknown: '?',
};

/** "just now", "5 min ago", "3 h ago", "2 days ago". */
export function relativeTime(at: number, now: number): string {
  const s = Math.max(0, Math.round((now - at) / 1000));
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

/** "≈45 s", "≈3 min", "≈2 h" until `at`; "now" when due. */
export function timeUntil(at: number, now: number): string {
  const s = Math.ceil((at - now) / 1000);
  if (s <= 0) return 'now';
  if (s < 90) return `≈${s} s`;
  const m = Math.round(s / 60);
  if (m < 90) return `≈${m} min`;
  return `≈${Math.round(m / 60)} h`;
}

/** One-line status text for a source card header. */
export function statusText(r: SourceResult, now: number): string {
  switch (r.status) {
    case 'loading':
      return 'Checking…';
    case 'queued':
      return r.retryAt ? `Queued (${timeUntil(r.retryAt, now)})` : 'Queued';
    case 'no_key':
      return 'No API key set';
    case 'disabled':
      return 'Disabled in settings';
    case 'rate_limited':
      return r.retryAt ? `${r.headline || 'Rate limited'} · retry ${timeUntil(r.retryAt, now)}` : r.headline || 'Rate limited';
    case 'error':
      return r.error ?? 'Error';
    case 'not_found':
      return r.headline || 'Not found';
    case 'ok':
      return r.headline;
  }
}

/** Only https links are rendered (SPEC §9 S3); adapters already restrict hosts. */
export function safeHref(link: string | undefined): string | undefined {
  if (!link) return undefined;
  try {
    return new URL(link).protocol === 'https:' ? link : undefined;
  } catch {
    return undefined;
  }
}

/** Defanged display: `evil[.]example`, `hxxps://…`. */
export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

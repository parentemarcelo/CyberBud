// Helpers shared by source adapters.
import type { HttpOutcome } from '../http';
import { MESSAGES } from '../http';
import type { DetailRow, Ioc, KeyTestResult, SourceId, SourceResult, Verdict } from '../types';

export function result(
  source: SourceId,
  ioc: Ioc,
  fields: Partial<SourceResult> & Pick<SourceResult, 'status'>,
): SourceResult {
  return { source, ioc, verdict: 'unknown', headline: '', details: [], fetchedAt: Date.now(), ...fields };
}

export function notFound(source: SourceId, ioc: Ioc, headline: string, link?: string): SourceResult {
  return result(source, ioc, { status: 'not_found', verdict: 'unknown', headline, ...(link && { link }) });
}

export function errorResult(source: SourceId, ioc: Ioc, message: string): SourceResult {
  return result(source, ioc, { status: 'error', headline: message, error: message });
}

/** Map a non-ok HTTP outcome to a result. Returns null for 'ok' and 'not_found'. */
export function failureResult(source: SourceId, ioc: Ioc, out: HttpOutcome): SourceResult | null {
  switch (out.kind) {
    case 'ok':
    case 'not_found':
      return null;
    case 'unauthorized':
      return errorResult(source, ioc, out.message);
    case 'rate_limited': {
      const fields: Partial<SourceResult> = { headline: 'Rate limited by source', error: 'Rate limited by source' };
      if (out.retryAfterMs !== undefined) fields.retryAt = Date.now() + out.retryAfterMs;
      return result(source, ioc, { status: 'rate_limited', ...fields });
    }
    case 'error':
      return errorResult(source, ioc, out.message);
  }
}

/** testKey mapping: a real answer (found or not) proves the key works. */
export function keyTestFromOutcome(out: HttpOutcome): KeyTestResult {
  if (out.kind === 'ok' || out.kind === 'not_found') return 'ok';
  if (out.kind === 'unauthorized') return 'invalid';
  return 'error';
}

export const UNEXPECTED = MESSAGES.badJson;

/** Build a link and keep it only if it is https on the expected host (SPEC §9 S3). */
export function safeLink(url: string | undefined, host: string): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && u.hostname === host ? u.href : undefined;
  } catch {
    return undefined;
  }
}

/** Details without empty values; values are always strings. */
export function rows(...pairs: Array<[string, unknown]>): DetailRow[] {
  const out: DetailRow[] = [];
  for (const [label, value] of pairs) {
    const v = display(value);
    if (v !== '') out.push([label, v]);
  }
  return out;
}

function display(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.map(display).filter(Boolean).join(', ');
  if (typeof value === 'object') return '';
  return String(value).trim();
}

/** Unix seconds → "2026-11-15 12:00 UTC". */
export function unixDate(seconds: unknown): string {
  return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? formatUtc(seconds * 1000) : '';
}

/** ISO-ish date string ("2026-11-15 12:00:00 UTC", "2026-11-15T12:00:00+00:00") → "2026-11-15 12:00 UTC". */
export function textDate(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') return '';
  const normalized = value.trim().replace(' UTC', 'Z').replace(' ', 'T');
  const ms = Date.parse(normalized);
  return Number.isNaN(ms) ? value.trim() : formatUtc(ms);
}

function formatUtc(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export function bytes(n: unknown): string {
  const v = typeof n === 'string' && /^\d+$/.test(n) ? Number(n) : n;
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) return '';
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(1)} ${units[i]}`;
}

export function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

export function num(x: unknown): number | undefined {
  return typeof x === 'number' && Number.isFinite(x) ? x : undefined;
}

export function str(x: unknown): string | undefined {
  return typeof x === 'string' && x.trim() !== '' ? x.trim() : undefined;
}

/** Tags may arrive as an array or a comma-separated string. */
export function tagList(x: unknown): string[] {
  if (Array.isArray(x)) return x.filter((t): t is string => typeof t === 'string' && t.trim() !== '').map((t) => t.trim());
  if (typeof x === 'string') return x.split(',').map((t) => t.trim()).filter(Boolean);
  return [];
}

export type { Verdict };

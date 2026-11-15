// Shared helpers for the abuse.ch APIs (URLhaus, MalwareBazaar, ThreatFox).
// All three use the same Auth-Key header and a `query_status` field.
// abuse.ch does not document how a missing/invalid key is reported, so both
// HTTP 401/403 and a key-related query_status map to "invalid key".
import { MESSAGES, requestJson, type HttpOutcome } from '../http';
import type { Ioc, KeyTestResult, SourceId, SourceResult } from '../types';
import { errorResult, failureResult, isRecord, keyTestFromOutcome } from './common';

export type QueryStatusKind = 'ok' | 'not_found' | 'invalid_key' | 'rejected';

const NOT_FOUND = new Set(['no_results', 'no_result', 'hash_not_found', 'not_found']);

export function classifyQueryStatus(status: unknown): QueryStatusKind {
  if (status === 'ok') return 'ok';
  if (typeof status !== 'string') return 'rejected';
  if (NOT_FOUND.has(status)) return 'not_found';
  if (/auth|api_key|unknown_key|no_key|permission/i.test(status)) return 'invalid_key';
  return 'rejected';
}

export interface AbuseChRequest {
  url: string;
  apiKey: string;
  signal: AbortSignal;
  /** Form fields (URLhaus, MalwareBazaar) or a JSON body (ThreatFox). */
  form?: Record<string, string>;
  json?: Record<string, unknown>;
}

export function postAbuseCh(req: AbuseChRequest): Promise<HttpOutcome> {
  const headers: Record<string, string> = { 'Auth-Key': req.apiKey, Accept: 'application/json' };
  let body: string | URLSearchParams;
  if (req.json) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(req.json);
  } else {
    body = new URLSearchParams(req.form);
  }
  return requestJson({ url: req.url, method: 'POST', headers, body, secrets: [req.apiKey], signal: req.signal });
}

/**
 * Common handling of an abuse.ch response. Returns either a final
 * SourceResult (failure / not found) or the parsed body for the adapter.
 */
export function handleAbuseCh(
  source: SourceId,
  sourceName: string,
  ioc: Ioc,
  out: HttpOutcome,
  notFound: () => SourceResult,
): { done: SourceResult } | { body: Record<string, unknown> } {
  if (out.kind === 'not_found') return { done: errorResult(source, ioc, MESSAGES.badJson) };
  const failure = failureResult(source, ioc, out);
  if (failure) return { done: failure };
  const body = out.kind === 'ok' && isRecord(out.json) ? out.json : undefined;
  if (!body) return { done: errorResult(source, ioc, MESSAGES.badJson) };

  switch (classifyQueryStatus(body.query_status)) {
    case 'ok':
      return { body };
    case 'not_found':
      return { done: notFound() };
    case 'invalid_key':
      return { done: errorResult(source, ioc, MESSAGES.unauthorized) };
    case 'rejected':
      return { done: errorResult(source, ioc, `${sourceName} rejected the request (${safeStatus(body.query_status)})`) };
  }
}

/** testKey for abuse.ch: an HTTP answer with a non-key-related status proves the key works. */
export function abuseChKeyTest(out: HttpOutcome): KeyTestResult {
  if (out.kind !== 'ok') return keyTestFromOutcome(out);
  const status = isRecord(out.json) ? out.json.query_status : undefined;
  const kind = classifyQueryStatus(status);
  if (kind === 'invalid_key') return 'invalid';
  return kind === 'rejected' && typeof status !== 'string' ? 'error' : 'ok';
}

/** query_status is shown to the user: keep it short and plain. */
function safeStatus(status: unknown): string {
  return typeof status === 'string' ? status.replace(/[^a-z0-9_ -]/gi, '').slice(0, 40) || 'unknown' : 'no status';
}

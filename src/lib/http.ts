// Shared HTTP helper for source adapters (docs/SPEC.md §8 "HTTP error mapping").
// - 15 s timeout (REQUEST_TIMEOUT_MS), combined with the caller's AbortSignal
// - Maps HTTP results to a small outcome type that adapters turn into SourceResults
// - Every error message has the API key(s) redacted (SPEC §9 S5)
import { REQUEST_TIMEOUT_MS } from './constants';

/** Responses larger than this are rejected (bounds memory use). */
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

export interface HttpRequest {
  url: string;
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string | URLSearchParams;
  /**
   * Values that must never appear in error messages (API keys). Messages are
   * fixed strings today; `redact` guards any future message built from data.
   */
  secrets?: readonly string[];
  signal?: AbortSignal;
  timeoutMs?: number;
}

export type HttpOutcome =
  /** 2xx with a JSON body. */
  | { kind: 'ok'; status: number; json: unknown }
  /** 404. `json` is the parsed body if there was one. */
  | { kind: 'not_found'; status: 404; json?: unknown }
  /** 401/403. */
  | { kind: 'unauthorized'; status: number; message: string }
  /** 429. `retryAfterMs` from the Retry-After header, if present. */
  | { kind: 'rate_limited'; status: 429; retryAfterMs?: number; json?: unknown }
  /** Anything else: network error, timeout, 4xx/5xx, bad JSON. */
  | { kind: 'error'; status?: number; message: string };

export const MESSAGES = {
  unauthorized: 'Invalid or unauthorized key',
  timeout: `Timed out after ${REQUEST_TIMEOUT_MS / 1000} s`,
  cancelled: 'Cancelled',
  network: 'Network error, check your connection',
  badJson: 'Unexpected response',
  tooLarge: 'Response too large',
} as const;

export async function requestJson(req: HttpRequest): Promise<HttpOutcome> {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), req.timeoutMs ?? REQUEST_TIMEOUT_MS);
  const signal = req.signal ? AbortSignal.any([req.signal, timeout.signal]) : timeout.signal;

  let res: Response;
  try {
    res = await fetch(req.url, {
      method: req.method ?? 'GET',
      headers: req.headers,
      body: req.body,
      signal,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      // APIs don't redirect; never follow one somewhere else.
      redirect: 'error',
    });
  } catch {
    clearTimeout(timer);
    if (req.signal?.aborted) return { kind: 'error', message: MESSAGES.cancelled };
    if (timeout.signal.aborted) return { kind: 'error', message: MESSAGES.timeout };
    // The browser's detail ("NetworkError when attempting…") isn't useful to
    // users, and leaving it out means no outside text ever reaches a message.
    return { kind: 'error', message: MESSAGES.network };
  }

  let text: string;
  try {
    text = await res.text();
  } catch {
    clearTimeout(timer);
    if (req.signal?.aborted) return { kind: 'error', message: MESSAGES.cancelled };
    if (timeout.signal.aborted) return { kind: 'error', message: MESSAGES.timeout };
    return { kind: 'error', status: res.status, message: MESSAGES.network };
  }
  clearTimeout(timer);

  if (text.length > MAX_RESPONSE_BYTES) return { kind: 'error', status: res.status, message: MESSAGES.tooLarge };
  const json = parseJson(text);

  if (res.status === 404) return json === undefined ? { kind: 'not_found', status: 404 } : { kind: 'not_found', status: 404, json };
  if (res.status === 401 || res.status === 403) {
    return { kind: 'unauthorized', status: res.status, message: MESSAGES.unauthorized };
  }
  if (res.status === 429) {
    const retryAfterMs = parseRetryAfter(res.headers.get('Retry-After'));
    return {
      kind: 'rate_limited',
      status: 429,
      ...(retryAfterMs !== undefined && { retryAfterMs }),
      ...(json !== undefined && { json }),
    };
  }
  if (res.status >= 500) return { kind: 'error', status: res.status, message: `Source unavailable (HTTP ${res.status})` };
  if (!res.ok) return { kind: 'error', status: res.status, message: `Request rejected (HTTP ${res.status})` };
  if (json === undefined) return { kind: 'error', status: res.status, message: MESSAGES.badJson };
  return { kind: 'ok', status: res.status, json };
}

/** Retry-After as delta-seconds or an HTTP date → milliseconds from now. */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  if (value === null || value.trim() === '') return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const at = Date.parse(v);
  return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}

/** Replace every occurrence of each secret (4+ chars) with "[redacted]". */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s.length >= 4) out = out.split(s).join('[redacted]');
  }
  return out;
}

function parseJson(text: string): unknown {
  if (text.trim() === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}


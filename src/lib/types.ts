// Core domain types (docs/SPEC.md §8).
// Each union has a runtime tuple next to it so code and tests can iterate the
// allowed values without repeating them.

// ---------- IOCs ----------

export const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'] as const;
export type IocType = (typeof IOC_TYPES)[number];

export const HASH_TYPES = ['md5', 'sha1', 'sha256'] as const satisfies readonly IocType[];
export type HashType = (typeof HASH_TYPES)[number];

/** A detected, normalized indicator. `raw` is what the user gave, `value` is what gets sent. */
export interface Ioc {
  raw: string;
  value: string;
  type: IocType;
}

/** Outcome of parsing one token of user input (SPEC F1). */
export type ParseResult =
  | { kind: 'ioc'; ioc: Ioc }
  /** Private/reserved IP: shown to the user, never sent (SPEC §9 S6). */
  | { kind: 'private'; raw: string; value: string }
  | { kind: 'unsupported'; raw: string }
  /** Valid IOC beyond the batch limit (SPEC F1: "skipped (limit 20)"). */
  | { kind: 'skipped'; raw: string };

// ---------- Sources and results ----------

export const SOURCE_IDS = ['virustotal', 'abuseipdb', 'urlhaus', 'malwarebazaar', 'threatfox'] as const;
export type SourceId = (typeof SOURCE_IDS)[number];

/** API key slots. The three abuse.ch services share one Auth-Key. */
export const KEY_IDS = ['vt', 'abuseipdb', 'abusech'] as const;
export type KeyId = (typeof KEY_IDS)[number];

/** Ordered least to most severe; see VERDICT_SEVERITY in constants.ts. */
export const VERDICTS = ['unknown', 'clean', 'suspicious', 'malicious'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const STATUSES = [
  'ok',
  'not_found',
  'error',
  'no_key',
  'disabled',
  'rate_limited',
  'queued',
  'loading',
] as const;
export type Status = (typeof STATUSES)[number];

/** One label/value row in a result card. */
export type DetailRow = [label: string, value: string];

export interface SourceResult {
  source: SourceId;
  ioc: Ioc;
  status: Status;
  verdict: Verdict;
  /** Short key figure for the card header, e.g. "12/94 engines". */
  headline: string;
  details: DetailRow[];
  /** Deep link to the source's own page for this IOC (https only, SPEC §9 S3). */
  link?: string;
  /** Epoch milliseconds. */
  fetchedAt?: number;
  fromCache?: boolean;
  /** User-facing message. Must never contain an API key (SPEC §9 S5). */
  error?: string;
  /** When status is 'queued' or 'rate_limited': epoch ms of the expected retry. */
  retryAt?: number;
}

export interface RateLimit {
  perMinute: number;
  perDay?: number;
}

export type KeyTestResult = 'ok' | 'invalid' | 'error';

export interface SourceAdapter {
  id: SourceId;
  name: string;
  keyId: KeyId;
  limits: RateLimit;
  supports(type: IocType): boolean;
  lookup(ioc: Ioc, apiKey: string, signal: AbortSignal): Promise<SourceResult>;
  testKey(apiKey: string, signal: AbortSignal): Promise<KeyTestResult>;
}

export interface ReportSummary {
  verdict: Verdict;
  /** Sources with a malicious or suspicious verdict. */
  flagged: number;
  /** Sources that answered (status 'ok' or 'not_found'). */
  total: number;
}

export interface IocReport {
  ioc: Ioc;
  results: SourceResult[];
  summary: ReportSummary;
}

// ---------- UI <-> background messages (SPEC §8) ----------

export type LookupOrigin = 'popup' | 'context_menu' | 'file';

export type RequestMessage =
  | { type: 'lookup'; text: string; origin: LookupOrigin }
  | { type: 'refresh'; ioc: Ioc; source?: SourceId }
  | { type: 'lookupHash'; sha256: string; origin: 'file' };

export type ResponseMessage =
  | { type: 'parsed'; items: ParseResult[] }
  | { type: 'report'; report: IocReport };

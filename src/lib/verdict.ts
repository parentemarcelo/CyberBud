// Per-IOC summary across sources (docs/SPEC.md F3 "Summary line per IOC").
import { VERDICT_SEVERITY } from './constants';
import type { ReportSummary, SourceResult, Status, Verdict } from './types';

export const NO_DATA_MESSAGE = 'No source has data on this IOC. This does not mean it is safe.';
export const NO_ANSWER_MESSAGE = 'No source could be checked.';

/** Statuses that count as an answer (the M in "N of M"). */
const ANSWERED: ReadonlySet<Status> = new Set(['ok', 'not_found']);
const PENDING: ReadonlySet<Status> = new Set(['loading', 'queued']);
const FLAGGED: ReadonlySet<Verdict> = new Set(['malicious', 'suspicious']);

export function isAnswered(r: SourceResult): boolean {
  return ANSWERED.has(r.status);
}

/**
 * Worst verdict wins (malicious > suspicious > clean > unknown). Only answered
 * sources count; errors, missing keys, disabled and rate-limited sources are
 * excluded from `total` and listed separately by the UI.
 */
export function summarize(results: readonly SourceResult[]): ReportSummary {
  let verdict: Verdict = 'unknown';
  let flagged = 0;
  let total = 0;
  let pending = 0;

  for (const r of results) {
    if (PENDING.has(r.status)) pending++;
    if (!isAnswered(r)) continue;
    total++;
    // A not_found answer can never be worse than unknown, whatever the adapter set.
    const v: Verdict = r.status === 'not_found' ? 'unknown' : r.verdict;
    if (FLAGGED.has(v)) flagged++;
    if (VERDICT_SEVERITY[v] > VERDICT_SEVERITY[verdict]) verdict = v;
  }
  return { verdict, flagged, total, pending };
}

/** "N of M sources flag this", or the no-data / no-answer message. */
export function summaryText(s: ReportSummary): string {
  if (s.total === 0) return s.pending > 0 ? 'Checking…' : NO_ANSWER_MESSAGE;
  if (s.verdict === 'unknown' && s.pending === 0) return NO_DATA_MESSAGE;
  const noun = s.total === 1 ? 'source flags' : 'sources flag';
  return `${s.flagged} of ${s.total} ${noun} this`;
}

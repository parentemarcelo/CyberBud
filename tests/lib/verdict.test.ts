import { describe, expect, it } from 'vitest';
import { NO_ANSWER_MESSAGE, NO_DATA_MESSAGE, summarize, summaryText } from '../../src/lib/verdict';
import type { SourceId, SourceResult, Status, Verdict } from '../../src/lib/types';

const ioc = { raw: 'example.com', value: 'example.com', type: 'domain' as const };
const r = (source: SourceId, status: Status, verdict: Verdict = 'unknown'): SourceResult => ({
  source,
  ioc,
  status,
  verdict,
  headline: '',
  details: [],
});

describe('summarize (SPEC F3)', () => {
  it('empty list → unknown, 0 of 0', () => {
    expect(summarize([])).toEqual({ verdict: 'unknown', flagged: 0, total: 0, pending: 0 });
  });

  it('all unknown → unknown with the no-data message', () => {
    const s = summarize([r('virustotal', 'not_found'), r('urlhaus', 'not_found'), r('threatfox', 'ok', 'unknown')]);
    expect(s).toEqual({ verdict: 'unknown', flagged: 0, total: 3, pending: 0 });
    expect(summaryText(s)).toBe(NO_DATA_MESSAGE);
  });

  it('worst verdict wins and flagged counts malicious + suspicious', () => {
    const s = summarize([
      r('virustotal', 'ok', 'suspicious'),
      r('urlhaus', 'ok', 'malicious'),
      r('threatfox', 'not_found'),
      r('abuseipdb', 'ok', 'clean'),
    ]);
    expect(s).toEqual({ verdict: 'malicious', flagged: 2, total: 4, pending: 0 });
    expect(summaryText(s)).toBe('2 of 4 sources flag this');
  });

  it.each<[Verdict[], Verdict]>([
    [['clean', 'unknown'], 'clean'],
    [['unknown', 'clean', 'suspicious'], 'suspicious'],
    [['suspicious', 'malicious', 'clean'], 'malicious'],
    [['clean', 'clean'], 'clean'],
  ])('order: %j → %s', (verdicts, expected) => {
    const sources: SourceId[] = ['virustotal', 'abuseipdb', 'urlhaus'];
    expect(summarize(verdicts.map((v, i) => r(sources[i]!, 'ok', v))).verdict).toBe(expected);
  });

  it('errors, missing keys, disabled and rate-limited sources are excluded from total', () => {
    const s = summarize([
      r('virustotal', 'error', 'malicious'), // verdict on a non-answer is ignored
      r('abuseipdb', 'no_key'),
      r('urlhaus', 'disabled'),
      r('malwarebazaar', 'rate_limited'),
      r('threatfox', 'ok', 'clean'),
    ]);
    expect(s).toEqual({ verdict: 'clean', flagged: 0, total: 1, pending: 0 });
    expect(summaryText(s)).toBe('0 of 1 source flags this');
  });

  it('only errors → no-answer message', () => {
    const s = summarize([r('virustotal', 'error'), r('urlhaus', 'no_key')]);
    expect(s.total).toBe(0);
    expect(summaryText(s)).toBe(NO_ANSWER_MESSAGE);
  });

  it('a not_found result never counts as flagged, even with a wrong verdict', () => {
    expect(summarize([r('virustotal', 'not_found', 'malicious')])).toEqual({
      verdict: 'unknown',
      flagged: 0,
      total: 1,
      pending: 0,
    });
  });

  it('counts pending (loading/queued) results and holds the no-data message until done', () => {
    const s = summarize([r('virustotal', 'queued'), r('urlhaus', 'loading'), r('threatfox', 'not_found')]);
    expect(s).toEqual({ verdict: 'unknown', flagged: 0, total: 1, pending: 2 });
    expect(summaryText(s)).toBe('0 of 1 source flags this');
    expect(summaryText(summarize([r('virustotal', 'loading')]))).toBe('Checking…');
  });
});

import { describe, expect, it } from 'vitest';
import { result } from '../../src/lib/sources/common';
import { defang, relativeTime, safeHref, statusText, timeUntil, VERDICT_ICON, VERDICT_LABEL } from '../../src/ui/format';
import { VERDICTS } from '../../src/lib/types';

const NOW = Date.UTC(2026, 10, 15, 12);
const ioc = { raw: 'x', value: 'x.example', type: 'domain' as const };

describe('format helpers', () => {
  it.each([
    [10_000, 'just now'],
    [5 * 60_000, '5 min ago'],
    [3 * 3_600_000, '3 h ago'],
    [3 * 86_400_000, '3 days ago'],
  ])('relativeTime %i ms → %s', (ago, text) => {
    expect(relativeTime(NOW - ago, NOW)).toBe(text);
  });

  it.each([
    [0, 'now'],
    [45_000, '≈45 s'],
    [5 * 60_000, '≈5 min'],
    [5 * 3_600_000, '≈5 h'],
  ])('timeUntil +%i ms → %s', (ms, text) => {
    expect(timeUntil(NOW + ms, NOW)).toBe(text);
  });

  it('status text for every state', () => {
    const s = (status: Parameters<typeof result>[2]['status'], extra = {}) => statusText(result('virustotal', ioc, { status, headline: 'H', ...extra }), NOW);
    expect(s('loading')).toBe('Checking…');
    expect(s('queued', { retryAt: NOW + 45_000 })).toBe('Queued (≈45 s)');
    expect(s('no_key')).toBe('No API key set');
    expect(s('disabled')).toBe('Disabled in settings');
    expect(s('rate_limited', { headline: 'Daily quota reached', retryAt: NOW + 3_600_000 })).toBe('Daily quota reached · retry ≈60 min');
    expect(s('error', { error: 'Invalid or unauthorized key' })).toBe('Invalid or unauthorized key');
    expect(s('not_found', { headline: 'Not in VirusTotal' })).toBe('Not in VirusTotal');
    expect(s('ok', { headline: '3/90 engines' })).toBe('3/90 engines');
  });

  it('every verdict has a word and an icon (never colour alone)', () => {
    for (const v of VERDICTS) {
      expect(VERDICT_LABEL[v]).toMatch(/\w+/);
      expect(VERDICT_ICON[v]).not.toBe('');
    }
  });

  it('safeHref allows https only', () => {
    expect(safeHref('https://www.virustotal.com/gui/x')).toBe('https://www.virustotal.com/gui/x');
    for (const bad of ['javascript:alert(1)', 'http://x.example', 'data:text/html,x', 'not a url', undefined]) {
      expect(safeHref(bad)).toBeUndefined();
    }
  });

  it('defang', () => {
    expect(defang('https://evil.example/a.b')).toBe('hxxps://evil[.]example/a[.]b');
  });
});

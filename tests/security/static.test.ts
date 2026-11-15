// Static security checks over src/ (SPEC §9, PLAN step 29). These guard the
// review's findings so a later change can't quietly reintroduce a problem.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import config, { HOST_PERMISSIONS } from '../../wxt.config';
import { SOURCE_API_ORIGINS } from '../../src/lib/sources/registry';

const ROOT = join(__dirname, '..', '..');
const SRC = join(ROOT, 'src');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx|html)$/.test(n) ? [p] : [];
  });
}
const sources = files(SRC).map((p) => ({ path: relative(ROOT, p), text: readFileSync(p, 'utf8') }));
const hits = (re: RegExp, except: (path: string) => boolean = () => false) =>
  sources.filter((f) => !except(f.path) && re.test(f.text)).map((f) => f.path);

describe('S3/S4: no HTML injection or dynamic code', () => {
  it.each([
    ['innerHTML / outerHTML', /\b(inner|outer)HTML\b/],
    ['insertAdjacentHTML', /insertAdjacentHTML/],
    ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
    ['document.write', /document\.write/],
    ['eval', /\beval\s*\(/],
    ['new Function', /new\s+Function\s*\(/],
    ['string timers', /set(Timeout|Interval)\(\s*['"`]/],
  ])('%s', (_name, re) => {
    expect(hits(re)).toEqual([]);
  });

  it('no custom content_security_policy (keep the MV3 default)', () => {
    expect(config.manifest).not.toHaveProperty('content_security_policy');
  });

  it('no remote scripts in HTML pages', () => {
    expect(hits(/<script[^>]+src=["']https?:/i)).toEqual([]);
  });

  it('every target="_blank" link has rel="noopener noreferrer"', () => {
    for (const f of sources) {
      for (const m of f.text.matchAll(/<a\b[^>]*target="_blank"[^>]*>/g)) {
        expect(m[0], f.path).toContain('rel="noopener noreferrer"');
      }
    }
  });
});

describe('S1/S5/S7: network, keys, telemetry', () => {
  it('fetch is only called from the HTTP helper', () => {
    expect(hits(/\bfetch\s*\(/, (p) => p === 'src/lib/http.ts')).toEqual([]);
  });

  it('no XMLHttpRequest, WebSocket, sendBeacon or EventSource', () => {
    expect(hits(/XMLHttpRequest|new WebSocket|sendBeacon|EventSource/)).toEqual([]);
  });

  it('no console output anywhere (nothing can log a key)', () => {
    expect(hits(/\bconsole\./)).toEqual([]);
  });

  it('API origins match host_permissions exactly', () => {
    expect([...SOURCE_API_ORIGINS].map((o) => `${o}/*`).sort()).toEqual([...HOST_PERMISSIONS].sort());
  });

  it('every hard-coded API base URL is a declared origin', () => {
    const declared = new Set<string>(SOURCE_API_ORIGINS);
    for (const f of sources.filter((s) => s.path.startsWith('src/lib/sources/'))) {
      for (const m of f.text.matchAll(/const (?:API|[A-Z_]*API[A-Z_]*) = '([^']+)'/g)) {
        expect(declared, `${f.path}: ${m[1]}`).toContain(new URL(m[1]!).origin);
      }
    }
  });

  it('settings are never stored in storage.sync', () => {
    expect(hits(/storage\.sync/)).toEqual([]);
  });

  it('no analytics or telemetry endpoints', () => {
    expect(hits(/google-analytics|googletagmanager|segment\.io|sentry\.io|mixpanel|amplitude|telemetry/i)).toEqual([]);
  });
});

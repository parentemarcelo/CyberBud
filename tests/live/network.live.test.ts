// Live "full session" network check (SPEC S1, S2, S5, S6; PLAN step 29):
// real lookups through the engine with every request recorded.
// Uses 4 VirusTotal requests; only public IOCs are sent to VirusTotal.
import { afterAll, describe, expect, it, vi } from 'vitest';
import { Engine, defaultDeps } from '../../src/background/engine';
import { updateSettings } from '../../src/lib/settings';
import { SOURCE_API_ORIGINS } from '../../src/lib/sources/registry';
import { loadKeys } from './keys';

const keys = loadKeys();
const all = !!(keys.vt && keys.abuseipdb && keys.abusech);

describe.skipIf(!all)('network allowlist (live session)', () => {
  const requests: Array<{ url: string; method: string; body: string; headers: Record<string, string> }> = [];
  const realFetch = globalThis.fetch;

  afterAll(() => {
    vi.unstubAllGlobals();
    console.log(`\nREQUESTS (${requests.length})\n${requests.map((r) => `${r.method} ${new URL(r.url).origin}${new URL(r.url).pathname}`).join('\n')}`);
  });

  it('only the five API origins are contacted, and private/secret data never leaves', async () => {
    vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
      requests.push({ url: String(input), method: init?.method ?? 'GET', body: init?.body ? String(init.body) : '', headers });
      return realFetch(input, init);
    });
    await updateSettings({ keys: { vt: keys.vt!, abuseipdb: keys.abuseipdb!, abusech: keys.abusech! }, urlMode: 'strip' });
    const engine = await Engine.create({ ...defaultDeps(), scheduleAlarm: async () => undefined });

    // One session: defanged URL with a secret token and fragment, a domain,
    // a public IP, a private IP, the EICAR hash, and junk.
    await engine.lookup(
      'hxxps://www[.]google[.]com/search?token=SECRET123#frag-secret google.com 8.8.8.8 10.0.0.5 ' +
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f not-an-ioc',
      'popup',
    );
    await engine.flush();

    expect(requests.length).toBeGreaterThan(8);
    const allowed = new Set<string>(SOURCE_API_ORIGINS);
    for (const r of requests) {
      const where = `${r.method} ${r.url}`;
      expect(allowed.has(new URL(r.url).origin), where).toBe(true);
      expect(new URL(r.url).protocol, where).toBe('https:');
      const sent = `${r.url} ${r.body}`;
      expect(sent, where).not.toContain('10.0.0.5'); // S6 private IP
      expect(sent, where).not.toContain('SECRET123'); // strip mode: query removed
      expect(sent, where).not.toContain('frag-secret'); // fragment never sent
      expect(sent, where).not.toContain('not-an-ioc');
      for (const k of [keys.vt!, keys.abuseipdb!, keys.abusech!]) expect(sent, where).not.toContain(k); // S5: keys only in headers
      // S2: read-only endpoints only
      expect(r.url, where).not.toMatch(/\/(files|urls)$|upload|submit|scan|report$/i);
    }
  }, 120_000);
});

// URLhaus adapter (docs/SPEC.md F3). URLs via /v1/url/, hosts via /v1/host/.
// Docs: https://urlhaus-api.abuse.ch/ (checked 2026-11-15). /v1/host/ accepts
// IPv4, hostnames and domains (not IPv6). URLhaus is a blocklist: found =
// malicious, not found = unknown (never "clean").
// Note: lookups are exact; a URL that differs in any character (e.g. a trailing
// slash) from the listed one is not found. Domain mode finds the host instead.
import { RATE_LIMITS } from '../constants';
import type { Ioc, IocType, KeyTestResult, SourceAdapter, SourceResult } from '../types';
import { abuseChKeyTest, handleAbuseCh, postAbuseCh } from './abusech';
import { isRecord, notFound, num, result, rows, safeLink, str, tagList, textDate } from './common';

const API = 'https://urlhaus-api.abuse.ch/v1';
const WEB_HOST = 'urlhaus.abuse.ch';
const SUPPORTED: ReadonlySet<IocType> = new Set(['url', 'domain', 'ipv4']);

function blocklists(x: unknown): string[] {
  if (!isRecord(x)) return [];
  return Object.entries(x)
    .filter(([, v]) => typeof v === 'string' && v !== 'not listed')
    .map(([k, v]) => `${k}: ${String(v)}`);
}

export function parseUrlhausUrl(ioc: Ioc, body: Record<string, unknown>): SourceResult {
  const status = str(body.url_status) ?? 'unknown';
  const threat = str(body.threat) ?? 'listed';
  const payloads = Array.isArray(body.payloads) ? body.payloads : [];
  const link =
    safeLink(str(body.urlhaus_reference), WEB_HOST) ??
    (typeof body.id === 'string' || typeof body.id === 'number'
      ? safeLink(`https://${WEB_HOST}/url/${encodeURIComponent(String(body.id))}/`, WEB_HOST)
      : undefined);
  return result('urlhaus', ioc, {
    status: 'ok',
    verdict: 'malicious',
    headline: `${threat.replace(/_/g, ' ')} · ${status}`,
    details: rows(
      ['Status', status],
      ['Threat', threat],
      ['Added', textDate(body.date_added)],
      ['Last online', textDate(body.last_online)],
      ['Host', str(body.host)],
      ['Tags', tagList(body.tags)],
      ['Payloads', payloads.length || undefined],
      ['Blocklists', blocklists(body.blacklists)],
      ['Reporter', str(body.reporter)],
    ),
    ...(link && { link }),
  });
}

export function parseUrlhausHost(ioc: Ioc, body: Record<string, unknown>): SourceResult {
  const urls = Array.isArray(body.urls) ? body.urls.filter(isRecord) : [];
  const total = num(body.url_count) ?? (typeof body.url_count === 'string' ? Number(body.url_count) : urls.length);
  const online = urls.filter((u) => u.url_status === 'online').length;
  const link = hostLink(str(body.host) ?? ioc.value, str(body.urlhaus_reference));
  return result('urlhaus', ioc, {
    status: 'ok',
    verdict: 'malicious',
    headline: `${total} malicious URL${total === 1 ? '' : 's'}${online ? ` · ${online} online` : ''}`,
    details: rows(
      ['Malicious URLs', total],
      ['Online now', urls.length ? online : undefined],
      ['First seen', textDate(body.firstseen)],
      ['Blocklists', blocklists(body.blacklists)],
      ['Threats', [...new Set(urls.map((u) => str(u.threat)).filter(Boolean))]],
      ['Tags', [...new Set(urls.flatMap((u) => tagList(u.tags)))].slice(0, 10)],
    ),
    ...(link && { link }),
  });
}

function hostLink(host: string, reference?: string): string | undefined {
  return safeLink(reference, WEB_HOST) ?? safeLink(`https://${WEB_HOST}/host/${encodeURIComponent(host)}/`, WEB_HOST);
}

function request(ioc: Pick<Ioc, 'type' | 'value'>, apiKey: string, signal: AbortSignal) {
  return ioc.type === 'url'
    ? postAbuseCh({ url: `${API}/url/`, form: { url: ioc.value }, apiKey, signal })
    : postAbuseCh({ url: `${API}/host/`, form: { host: ioc.value }, apiKey, signal });
}

export const urlhaus: SourceAdapter = {
  id: 'urlhaus',
  name: 'URLhaus',
  keyId: 'abusech',
  limits: RATE_LIMITS.urlhaus,
  supports: (type) => SUPPORTED.has(type),

  async lookup(ioc, apiKey, signal): Promise<SourceResult> {
    const out = await request(ioc, apiKey, signal);
    const link = ioc.type === 'url' ? undefined : hostLink(ioc.value);
    const h = handleAbuseCh('urlhaus', 'URLhaus', ioc, out, () => notFound('urlhaus', ioc, 'Not listed in URLhaus', link));
    if ('done' in h) return h.done;
    return ioc.type === 'url' ? parseUrlhausUrl(ioc, h.body) : parseUrlhausHost(ioc, h.body);
  },

  async testKey(apiKey, signal): Promise<KeyTestResult> {
    return abuseChKeyTest(await request({ type: 'domain', value: 'example.com' }, apiKey, signal));
  },
};

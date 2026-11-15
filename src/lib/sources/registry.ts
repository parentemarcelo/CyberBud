// Source adapter registry (docs/SPEC.md F3, PLAN step 18).
import type { Settings } from '../settings';
import { SOURCE_IDS, type Ioc, type SourceAdapter, type SourceId, type SourceResult } from '../types';
import { abuseipdb } from './abuseipdb';
import { result } from './common';
import { malwarebazaar } from './malwarebazaar';
import { threatfox } from './threatfox';
import { urlhaus } from './urlhaus';
import { virustotal } from './virustotal';

export const ADAPTERS: Readonly<Record<SourceId, SourceAdapter>> = Object.freeze({
  virustotal,
  abuseipdb,
  urlhaus,
  malwarebazaar,
  threatfox,
});

export interface RunnableSource {
  adapter: SourceAdapter;
  apiKey: string;
}

export interface SourcePlan {
  /** Enabled sources with a key that support this IOC type, in SOURCE_IDS order. */
  runnable: RunnableSource[];
  /** 'disabled' / 'no_key' results for supporting sources that can't run. */
  placeholders: SourceResult[];
}

/**
 * Which sources to query for `ioc`. Sources that don't support the IOC type are
 * left out entirely; a disabled source is 'disabled' even if it has no key.
 */
export function adaptersFor(ioc: Ioc, settings: Pick<Settings, 'keys' | 'enabledSources'>): SourcePlan {
  const plan: SourcePlan = { runnable: [], placeholders: [] };
  for (const id of SOURCE_IDS) {
    const adapter = ADAPTERS[id];
    if (!adapter.supports(ioc.type)) continue;
    if (!settings.enabledSources[id]) {
      plan.placeholders.push(result(id, ioc, { status: 'disabled', headline: 'Disabled in settings' }));
      continue;
    }
    const apiKey = settings.keys[adapter.keyId].trim();
    if (apiKey === '') {
      plan.placeholders.push(result(id, ioc, { status: 'no_key', headline: 'No API key set' }));
      continue;
    }
    plan.runnable.push({ adapter, apiKey });
  }
  return plan;
}

/** Hosts the adapters may contact (must match the manifest's host_permissions). */
export const SOURCE_API_ORIGINS = [
  'https://www.virustotal.com',
  'https://api.abuseipdb.com',
  'https://urlhaus-api.abuse.ch',
  'https://mb-api.abuse.ch',
  'https://threatfox-api.abuse.ch',
] as const;

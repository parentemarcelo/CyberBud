import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface LiveKeys {
  vt?: string;
  abuseipdb?: string;
  abusech?: string;
}

/**
 * Keys for live API checks. Read from environment variables
 * (CYBERBUD_VT_KEY, CYBERBUD_ABUSEIPDB_KEY, CYBERBUD_ABUSECH_KEY) or from the
 * git-ignored docs/KEYS.md ("# VirusTotal", "# AbuseIPDB", "# AbuseCH"
 * headings, each followed by the key). Keys are never printed.
 */
export function loadKeys(): LiveKeys {
  const keys: LiveKeys = {
    vt: process.env.CYBERBUD_VT_KEY,
    abuseipdb: process.env.CYBERBUD_ABUSEIPDB_KEY,
    abusech: process.env.CYBERBUD_ABUSECH_KEY,
  };
  const file = join(__dirname, '..', '..', 'docs', 'KEYS.md');
  if (!existsSync(file)) return keys;

  let section = '';
  for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('#')) {
      section = line.replace(/^#+/, '').trim().toLowerCase().replace(/[^a-z]/g, '');
      continue;
    }
    if (line === '') continue;
    if (section.startsWith('virustotal')) keys.vt ??= line;
    else if (section.startsWith('abuseipdb')) keys.abuseipdb ??= line;
    else if (section.startsWith('abusech')) keys.abusech ??= line;
  }
  return keys;
}

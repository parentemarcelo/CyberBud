// Post-build checks on the shipped files (.output/firefox-mv3), run by `npm run check`.
// Fails if the bundle contains local paths, dynamic code, or unexpected hosts.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const OUT = '.output/firefox-mv3';
const ALLOWED_HOSTS = new Set([
  // APIs (host_permissions)
  'www.virustotal.com', 'api.abuseipdb.com', 'urlhaus-api.abuse.ch', 'mb-api.abuse.ch', 'threatfox-api.abuse.ch',
  // Links the user can click (source pages and "get a key" help links); never fetched
  'www.abuseipdb.com', 'auth.abuse.ch', 'urlhaus.abuse.ch', 'bazaar.abuse.ch', 'threatfox.abuse.ch',
  // XML namespace identifiers inside Preact (SVG/MathML), not network requests
  'www.w3.org',
  // Example text in the options page
  'site',
]);

const files = (d) => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? files(join(d, n)) : [join(d, n)]));
const problems = [];
for (const f of files(OUT).filter((f) => /\.(js|html|css|json)$/.test(f))) {
  const text = readFileSync(f, 'utf8');
  if (text.includes(process.cwd())) problems.push(`${f}: contains the absolute build path`);
  if (/\beval\s*\(|new\s+Function\s*\(/.test(text)) problems.push(`${f}: eval/new Function`);
  for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
    if (!ALLOWED_HOSTS.has(m[1].toLowerCase())) problems.push(`${f}: unexpected host ${m[1]}`);
  }
}
if (problems.length) {
  console.error(`Bundle check failed:\n${[...new Set(problems)].join('\n')}`);
  process.exit(1);
}
console.log(`Bundle check passed (${files(OUT).length} files).`);

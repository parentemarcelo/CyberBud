# API fixtures

These JSON files are **built from each provider's official API documentation**
(field names and example responses), checked on 2026-11-15. They are not yet
recorded from live API calls, because no API keys are available in CI.

| Source | Docs |
|--------|------|
| VirusTotal v3 | https://docs.virustotal.com/reference/overview |
| AbuseIPDB v2 | https://docs.abuseipdb.com/ |
| URLhaus | https://urlhaus-api.abuse.ch/ |
| MalwareBazaar | https://bazaar.abuse.ch/api/ |
| ThreatFox | https://threatfox.abuse.ch/api/ |

**Verified against the live APIs on 2026-11-15** (`npm run test:live`):
- abuse.ch invalid `Auth-Key` → **HTTP 403** on URLhaus, MalwareBazaar and ThreatFox.
- MalwareBazaar `get_info` success → `{"query_status":"ok","data":[…]}`, tags as an array;
  not found → `hash_not_found`; MD5, SHA-1 and SHA-256 all work.
- ThreatFox not found → `{"query_status":"no_result","data":"<message>"}`. Hash IOCs are
  only found with `search_ioc` (exact match), not `search_hash`. Entries include `is_compromised`.
- URLhaus not found → `no_results`; IPv6 host → `invalid_host`.
- Web links checked: `urlhaus.abuse.ch/url/<id>/`, `/host/<host>/`, `bazaar.abuse.ch/sample/<sha256>/`,
  `threatfox.abuse.ch/ioc/<id>/`, `www.abuseipdb.com/check/<ip>`, `www.virustotal.com/gui/…`.

The fixture files themselves are still the doc-based ones above; their shapes match the live responses.

## Live checks

`npm run test:live` runs real lookups with your keys, read from the git-ignored
`docs/KEYS.md` or from `CYBERBUD_VT_KEY`, `CYBERBUD_ABUSEIPDB_KEY`, `CYBERBUD_ABUSECH_KEY`.
It is excluded from `npm test`. It uses 5 VirusTotal requests (with a 60 s pause)
and sends VirusTotal only public IOCs (EICAR, google.com, 8.8.8.8).

**To replace with live recordings** (PLAN manual checks): run one lookup per
type with your own key, save the response body here under the same file name,
and remove anything you don't want committed. Never commit an API key.

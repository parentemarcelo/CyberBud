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

Not documented by the providers, and therefore assumptions until verified live:
- abuse.ch responses to a missing or invalid `Auth-Key` (handled defensively:
  HTTP 401/403 or a `query_status` mentioning the key → "Invalid or unauthorized key").
- MalwareBazaar `get_info` success wrapper (`{"query_status":"ok","data":[…]}` assumed).
- ThreatFox "not found" status (`no_result` assumed; any `no_result*`/`not_found` value accepted).

**To replace with live recordings** (PLAN manual checks): run one lookup per
type with your own key, save the response body here under the same file name,
and remove anything you don't want committed. Never commit an API key.

# CyberBud

**Multi-source IOC reputation for security analysts, right in Firefox.**

CyberBud is a Firefox extension to make life easier for security analysts and technical users. It can check a URL, domain, IP address or file hash against several reputation sources at once, without jumping between tabs and copying IOCs around.

- **One action, all sources:** paste into the popup or right-click → **Check reputation** on selected text, a link or the page.
- **Current sources:** VirusTotal, AbuseIPDB, and abuse.ch (URLhaus, MalwareBazaar, ThreatFox).
- **Raw results, clearly summarised:** per-source cards with the key numbers ("12/94 engines", "87% confidence") and a link to each source's own page, plus a "N of M sources flag this" summary.
- **Defanged input works:** `hxxps://evil[.]example`, `1[.]2[.]3[.]4`, `user[at]example[.]com`.
- **Check files without uploading them:** drop a file to hash it locally (SHA-256 and SHA-1); only the hash is looked up. Optionally activate/disable prompt when a risky download finishes. Note: 'risky' is assessed by file type.
- **Private by design:** everything runs in your browser with your own API keys. No server, no telemetry.


Disclaimer: The extension was coded with support of AI (Claude Code).


## Who is it for?

Technical users. CyberBud shows raw analysis from each source and needs your own API keys (BYOK, "bring your own keys"). All three current integrations allow for access to API keys with a free user account.

## Get your API keys

| Source | Where | Free tier |
|--------|-------|-----------|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/my-apikey) → sign in → API key | 4 requests/min, 500/day. The public API must not be used commercially. |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/account/api) → Account → API → Create key | 1,000 checks/day |
| abuse.ch | [auth.abuse.ch](https://auth.abuse.ch/) → sign in → Auth-Key | One key works for URLhaus, MalwareBazaar and ThreatFox |

Open CyberBud's **Settings** (gear icon), paste each key, then **Save** and **Test**. Sources without a key are simply skipped.

## Using it

- **Popup:** paste one or more IOCs (up to 20 at a time) and press Enter.
- **Right-click:** select text (or right-click a link or page) → **Check reputation**.
- **Files:** popup → *Check a file…* (opens a new tab), then drag&drop a file, even from downloads popup.
- **Downloads:** when a risky file type finishes downloading, click the notification to check it.
- **History:** the History tab lists past lookups. Click one to reopen it from cache.

Verdicts: **Malicious**, **Suspicious**, **Clean** or **Unknown**. *Unknown* means no source has data. It does **not** mean the IOC is safe.

## Privacy

- Lookups run only when you ask. IOCs go **directly from Firefox to the source you enabled**, and nowhere else.
- **VirusTotal states that any IOC queried through its API may be added to the VirusTotal dataset**, visible to its community. Don't look up sensitive values there.
- URLs are sent **without their query string** by default (configurable). The part after `#` is never sent. Private and local addresses (10.x, 192.168.x, localhost…) are never sent.
- Files never leave your browser: only their SHA-256 is looked up.
- API keys, cache and history are stored **only in your Firefox profile** (unencrypted, never synced).

Full details: [PRIVACY.md](PRIVACY.md).

## Permissions

| Permission | Why |
|------------|-----|
| `storage` | Settings, keys, cache and history, locally |
| `contextMenus` | The "Check reputation" right-click item |
| `downloads` | Notice finished downloads; "Show in folder" |
| `notifications` | The download prompt |
| `alarms` | Finish queued lookups when rate limits allow |
| 5 API hosts | VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox |

No access to the pages you visit (no content scripts, no `<all_urls>`).

## Development

Requirements: Node.js ≥ 22.12, Firefox ≥ 140.

```sh
npm ci              # install exact dependency versions
npm run dev         # launch Firefox with the extension loaded (auto-reload)
npm test            # unit and component tests (no network)
npm run check       # types, lint, tests, build, web-ext lint
npm run test:live   # optional: real API checks with your keys (see tests/fixtures/README.md)
```

Extension is under review by Mozilla for public listing. Link will be shared here once validated.

### Build for release (also the build instructions for AMO reviewers)

```sh
npm ci
npm run zip
```

This produces in `.output/`:
- `cyberbud-<version>-firefox.zip`: the extension
- `cyberbud-<version>-sources.zip`: the source code for AMO review. It contains only `src/`, `public/`, the configs, `package*.json`, `README.md` and `PRIVACY.md`. Rebuild from it with `npm ci && npm run zip`.

The build is not minified, to keep AMO review readable.

### Sign for self-distribution (unlisted)

Needs AMO API credentials (addons.mozilla.org → Developer Hub → Manage API Keys):

```sh
npm run zip
WEB_EXT_API_KEY=<jwt issuer> WEB_EXT_API_SECRET=<jwt secret> npm run sign
```

The signed `.xpi` is written to `web-ext-artifacts/`.

## Project layout

```
src/lib/          IOC parsing, sources (adapters), cache, rate limits, settings, history
src/background/   lookup engine, messaging, context menu, download prompt
src/ui/           popup / tab app, options page (Preact)
tests/            unit, component, security and (opt-in) live API tests
```

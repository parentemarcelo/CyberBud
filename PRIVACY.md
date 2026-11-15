# CyberBud Privacy Policy

Last updated: 2026-11-15

CyberBud is a Firefox extension that looks up the reputation of indicators of compromise (IOCs): URLs, domains, IP addresses and file hashes. It has **no server**. The developer receives **no data** from it.

## What is sent, to whom, and when

CyberBud sends data **only when you ask for a lookup**: when you press Check in the popup, choose **Check reputation** from the right-click menu, drop a file on the Check file page, or click the download notification.

For each lookup, CyberBud sends the IOC **directly from your browser** to the reputation services you enabled, using **your own API key** for each service:

| Service | Operator | Receives |
|---------|----------|----------|
| VirusTotal | Google / VirusTotal | URLs, domains, IPs, file hashes |
| AbuseIPDB | AbuseIPDB | IP addresses |
| URLhaus, MalwareBazaar, ThreatFox | abuse.ch | URLs, domains, IPv4, file hashes (by service) |

Each service's own privacy policy and terms apply to what it receives. In particular, **VirusTotal states that any IOC queried through its API may be added to the VirusTotal dataset** and become visible to its community. Don't look up sensitive values (for example internal hostnames or URLs with personal data) on VirusTotal.

What exactly leaves your browser:

- **The IOC you selected or typed**, after normalisation. URLs are sent **without their query string** by default. You can choose "full URL" or "domain only" in Settings. The `#fragment` part of a URL is never sent.
- **For files: only the SHA-256 hash.** The file's content and name never leave your browser.
- **Your API key** for that service, sent only to the service that issued it, as the service requires for authentication.

What is **never** sent:

- Private, reserved and local addresses (for example `10.x.x.x`, `192.168.x.x`, `127.0.0.1`, `localhost`, `fe80::/10`).
- The pages you visit, your browsing history, or anything you didn't select. CyberBud has no access to page content.
- Analytics, telemetry, crash reports or identifiers. CyberBud has none.

## What is stored on your device

All stored in your Firefox profile (`storage.local`, never synced), and deleted when you remove the extension:

- **Settings and API keys.** Keys are stored **unencrypted**, as WebExtensions have no secure key store. Anyone with access to your Firefox profile can read them.
- **Result cache** (default 24 hours; set 0 to disable). Settings → *Clear cache*.
- **Lookup history**: the IOC, its verdict and time (default 7 days; can be turned off). Settings or History → *Clear history*.
- **Temporary lookup state** (queue, current results) in session storage, cleared when Firefox closes.

## Firefox data consent

The extension declares this data use to Firefox (`data_collection_permissions`, required):

- `browsingActivity`: page and link URLs you choose to check.
- `websiteContent`: text you select on a page and choose to check.

File hashes and IOCs you type yourself fit no specific Firefox category; they are described above. Your API key is sent only to the service that issued it, to authenticate, and is not collected by anyone else.

## Contact

Questions or concerns: open an issue at https://github.com/parentemarcelo/CyberBud/issues.

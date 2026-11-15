// Tunable constants (docs/SPEC.md F1, F3, F4, F6). Change values here only.
import type { RateLimit, SourceId, Verdict } from './types';

/** Max IOCs looked up per batch; extras are reported as skipped (SPEC F1). */
export const MAX_BATCH_SIZE = 20;

/** Per-request timeout before a source result becomes an error (SPEC F6). */
export const REQUEST_TIMEOUT_MS = 15_000;

/** Largest file hashed in-browser; the whole file is loaded into memory (SPEC F4). */
export const MAX_FILE_SIZE_BYTES = 1024 ** 3; // 1 GiB

/** Higher number = worse. The summary verdict is the worst one (SPEC F3). */
export const VERDICT_SEVERITY: Readonly<Record<Verdict, number>> = Object.freeze({
  unknown: 0,
  clean: 1,
  suspicious: 2,
  malicious: 3,
});

/**
 * Per-source verdict thresholds (SPEC F3 "Verdict rules").
 * abuse.ch sources are blocklists: found = malicious, not found = unknown,
 * so they need no thresholds.
 */
export const VERDICT_THRESHOLDS = Object.freeze({
  virustotal: Object.freeze({
    /** malicious engines >= this → malicious */
    maliciousMin: 3,
    /** malicious engines >= this (but below maliciousMin) → suspicious */
    suspiciousMaliciousMin: 1,
    /** suspicious engines >= this → suspicious */
    suspiciousMin: 1,
  }),
  abuseipdb: Object.freeze({
    /** abuseConfidenceScore >= this → malicious */
    maliciousMin: 75,
    /** abuseConfidenceScore >= this (but below maliciousMin) → suspicious */
    suspiciousMin: 25,
  }),
});

/** Client-side rate limits per source (SPEC F6). Daily counters reset at 00:00 UTC. */
export const RATE_LIMITS: Readonly<Record<SourceId, Readonly<RateLimit>>> = Object.freeze({
  virustotal: Object.freeze({ perMinute: 4, perDay: 500 }),
  abuseipdb: Object.freeze({ perMinute: 60, perDay: 1_000 }),
  urlhaus: Object.freeze({ perMinute: 60 }),
  malwarebazaar: Object.freeze({ perMinute: 60 }),
  threatfox: Object.freeze({ perMinute: 60 }),
});

/** Default file extensions that trigger the download prompt in "risky" mode (SPEC F4). Lowercase, no dot. */
export const DEFAULT_RISKY_EXTENSIONS: readonly string[] = Object.freeze([
  // Windows executables and libraries
  'exe', 'msi', 'msix', 'dll', 'scr', 'com',
  // Scripts
  'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta',
  // Shortcuts and disk images
  'lnk', 'iso', 'img', 'vhd', 'vhdx',
  // Archives
  'zip', 'rar', '7z', 'cab',
  // Other platforms and runtimes
  'jar', 'apk', 'dmg', 'pkg', 'app',
  // Macro-enabled Office, OneNote, help files, registry
  'docm', 'xlsm', 'pptm', 'one', 'chm', 'reg',
]);

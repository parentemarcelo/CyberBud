import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISKY_EXTENSIONS,
  MAX_BATCH_SIZE,
  MAX_FILE_SIZE_BYTES,
  RATE_LIMITS,
  REQUEST_TIMEOUT_MS,
  VERDICT_SEVERITY,
  VERDICT_THRESHOLDS,
} from '../src/lib/constants';
import { SOURCE_IDS, VERDICTS } from '../src/lib/types';

describe('limits (SPEC F1, F4, F6)', () => {
  it('has the SPEC values', () => {
    expect(MAX_BATCH_SIZE).toBe(20);
    expect(REQUEST_TIMEOUT_MS).toBe(15_000);
    expect(MAX_FILE_SIZE_BYTES).toBe(1_073_741_824);
  });
});

describe('VERDICT_SEVERITY', () => {
  it('ranks malicious > suspicious > clean > unknown', () => {
    const ranked = [...VERDICTS].sort((a, b) => VERDICT_SEVERITY[a] - VERDICT_SEVERITY[b]);
    expect(ranked).toEqual(['unknown', 'clean', 'suspicious', 'malicious']);
  });

  it('covers every verdict with a distinct rank', () => {
    expect(Object.keys(VERDICT_SEVERITY).sort()).toEqual([...VERDICTS].sort());
    expect(new Set(Object.values(VERDICT_SEVERITY)).size).toBe(VERDICTS.length);
  });
});

describe('VERDICT_THRESHOLDS (SPEC F3)', () => {
  it('VirusTotal: >=3 malicious, 1-2 malicious or >=1 suspicious = suspicious', () => {
    expect(VERDICT_THRESHOLDS.virustotal).toEqual({
      maliciousMin: 3,
      suspiciousMaliciousMin: 1,
      suspiciousMin: 1,
    });
  });

  it('AbuseIPDB: >=75 malicious, 25-74 suspicious', () => {
    expect(VERDICT_THRESHOLDS.abuseipdb).toEqual({ maliciousMin: 75, suspiciousMin: 25 });
  });

  it('keeps suspicious thresholds below malicious ones', () => {
    const { virustotal: vt, abuseipdb: ab } = VERDICT_THRESHOLDS;
    expect(vt.suspiciousMaliciousMin).toBeLessThan(vt.maliciousMin);
    expect(ab.suspiciousMin).toBeLessThan(ab.maliciousMin);
  });
});

describe('RATE_LIMITS (SPEC F6)', () => {
  it('defines a limit for every source', () => {
    expect(Object.keys(RATE_LIMITS).sort()).toEqual([...SOURCE_IDS].sort());
  });

  it('has the SPEC values', () => {
    expect(RATE_LIMITS.virustotal).toEqual({ perMinute: 4, perDay: 500 });
    expect(RATE_LIMITS.abuseipdb).toEqual({ perMinute: 60, perDay: 1_000 });
    for (const id of ['urlhaus', 'malwarebazaar', 'threatfox'] as const) {
      expect(RATE_LIMITS[id]).toEqual({ perMinute: 60 });
    }
  });
});

describe('DEFAULT_RISKY_EXTENSIONS (SPEC F4)', () => {
  it('contains exactly the 36 SPEC extensions', () => {
    const spec =
      'exe msi msix dll scr com bat cmd ps1 psm1 vbs vbe js jse wsf hta lnk iso img vhd vhdx zip rar 7z cab jar apk dmg pkg app docm xlsm pptm one chm reg';
    expect([...DEFAULT_RISKY_EXTENSIONS].sort()).toEqual(spec.split(' ').sort());
  });

  it('entries are lowercase, dot-less and unique', () => {
    for (const ext of DEFAULT_RISKY_EXTENSIONS) {
      expect(ext).toMatch(/^[a-z0-9]+$/);
    }
    expect(new Set(DEFAULT_RISKY_EXTENSIONS).size).toBe(DEFAULT_RISKY_EXTENSIONS.length);
  });
});

describe('immutability', () => {
  it('constants cannot be mutated at runtime', () => {
    expect(Object.isFrozen(VERDICT_SEVERITY)).toBe(true);
    expect(Object.isFrozen(VERDICT_THRESHOLDS.virustotal)).toBe(true);
    expect(Object.isFrozen(RATE_LIMITS.virustotal)).toBe(true);
    expect(Object.isFrozen(DEFAULT_RISKY_EXTENSIONS)).toBe(true);
  });
});

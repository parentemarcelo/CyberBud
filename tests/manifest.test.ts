import { describe, expect, it } from 'vitest';
import config, { HOST_PERMISSIONS, PERMISSIONS } from '../wxt.config';

// Guards SPEC §5: the permission set must stay minimal.
describe('manifest permissions', () => {
  const manifest = config.manifest as Record<string, unknown>;

  it('requests exactly the SPEC permissions', () => {
    expect([...PERMISSIONS].sort()).toEqual(
      ['alarms', 'contextMenus', 'downloads', 'notifications', 'storage'].sort(),
    );
    expect(manifest.permissions).toEqual(PERMISSIONS);
  });

  it('limits host permissions to the five reputation APIs over https', () => {
    expect(HOST_PERMISSIONS).toHaveLength(5);
    for (const origin of HOST_PERMISSIONS) {
      expect(origin).toMatch(/^https:\/\/[a-z0-9.-]+\/\*$/);
    }
    expect(manifest.host_permissions).toEqual(HOST_PERMISSIONS);
  });

  it('never asks for broad or invasive permissions', () => {
    const all = [...PERMISSIONS, ...HOST_PERMISSIONS];
    for (const forbidden of ['<all_urls>', 'tabs', 'activeTab', 'webRequest', 'downloads.open', '*://*/*']) {
      expect(all).not.toContain(forbidden);
    }
    expect(manifest).not.toHaveProperty('content_scripts');
  });

  it('targets Firefox 140 ESR or newer with MV3', () => {
    expect(config.manifestVersion).toBe(3);
    const gecko = (manifest.browser_specific_settings as { gecko: { id: string; strict_min_version: string } }).gecko;
    expect(gecko.strict_min_version).toBe('140.0');
    expect(gecko.id).toMatch(/^cyberbud@/);
  });

  it('declares the data it sends to third parties (Firefox data consent)', () => {
    const gecko = (manifest.browser_specific_settings as {
      gecko: { data_collection_permissions?: { required?: string[] } };
    }).gecko;
    expect(gecko.data_collection_permissions?.required).toEqual(['browsingActivity', 'websiteContent']);
  });
});

describe('packaging', () => {
  it('the AMO source zip is an allowlist that never includes docs/ or key files', async () => {
    const { SOURCE_ZIP_INCLUDE, SOURCE_ZIP_EXCLUDE } = await import('../wxt.config');
    const zip = (config as { zip?: { includeSources?: string[]; excludeSources?: string[]; dotSources?: boolean } }).zip;
    expect(zip?.includeSources).toEqual(SOURCE_ZIP_INCLUDE);
    expect(SOURCE_ZIP_INCLUDE.some((p) => p.startsWith('docs'))).toBe(false);
    expect(SOURCE_ZIP_EXCLUDE).toEqual(expect.arrayContaining(['docs/**', '**/*KEYS*', '**/.env*']));
    expect(zip?.dotSources).toBe(false);
  });

  it('has PNG icons up to 128 px for AMO and notifications', () => {
    const icons = (config.manifest as { icons: Record<string, string> }).icons;
    expect(icons['128']).toBe('icon-128.png');
    expect(Object.values(icons).every((f) => f.endsWith('.png'))).toBe(true);
  });
});

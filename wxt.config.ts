import { defineConfig } from 'wxt';
import preact from '@preact/preset-vite';
import type { Plugin } from 'vite';

/**
 * Rollup leaves module-id comments with the absolute build path (e.g. the
 * developer's home directory) in unminified output. Rewrite the project root
 * to "." so the shipped files carry no local paths and rebuilds from the AMO
 * source zip are byte-identical.
 */
function stripAbsolutePaths(): Plugin {
  const root = process.cwd();
  return {
    name: 'cyberbud:strip-absolute-paths',
    renderChunk(code) {
      return code.includes(root) ? { code: code.split(root).join('.'), map: null } : null;
    },
  };
}

// Permissions follow docs/SPEC.md §5. Keep this list minimal: no content
// scripts, no <all_urls>, no tabs/activeTab/webRequest.
export const PERMISSIONS = ['storage', 'contextMenus', 'downloads', 'notifications', 'alarms'];

export const HOST_PERMISSIONS = [
  'https://www.virustotal.com/*',
  'https://api.abuseipdb.com/*',
  'https://urlhaus-api.abuse.ch/*',
  'https://mb-api.abuse.ch/*',
  'https://threatfox-api.abuse.ch/*',
];

/**
 * Files AMO needs to rebuild the extension from source. An allowlist on
 * purpose: WXT's default would include every non-hidden file, such as the
 * git-ignored docs/ folder, which holds local API keys.
 */
export const SOURCE_ZIP_INCLUDE = [
  'src/**',
  'public/**',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'wxt.config.ts',
  'README.md',
  'PRIVACY.md',
  'LICENSE*',
];
export const SOURCE_ZIP_EXCLUDE = ['docs/**', '**/*KEYS*', '**/.env*', 'tests/**', 'coverage/**'];

export default defineConfig({
  srcDir: 'src',
  manifestVersion: 3,
  zip: {
    zipSources: true,
    includeSources: SOURCE_ZIP_INCLUDE,
    excludeSources: SOURCE_ZIP_EXCLUDE,
    dotSources: false,
  },
  vite: () => ({
    plugins: [preact(), stripAbsolutePaths()],
    build: {
      // Readable output simplifies AMO review (SPEC §4).
      minify: false,
    },
  }),
  manifest: {
    name: 'CyberBud',
    description: 'Multi-source IOC reputation lookups for security analysts, right in Firefox.',
    permissions: PERMISSIONS,
    host_permissions: HOST_PERMISSIONS,
    icons: { 16: 'icon-16.png', 32: 'icon-32.png', 48: 'icon-48.png', 96: 'icon-96.png', 128: 'icon-128.png' },
    action: {
      default_title: 'CyberBud',
      default_icon: { 48: 'icon.svg', 96: 'icon.svg' },
    },
    browser_specific_settings: {
      gecko: {
        id: 'cyberbud@parentemarcelo.github.io',
        strict_min_version: '140.0',
        // IOCs the user chooses to look up (page/link URLs, selected page text)
        // are sent to the third-party reputation APIs. That is the core
        // function, so it is declared as required. Review at PLAN step 31.
        data_collection_permissions: {
          required: ['browsingActivity', 'websiteContent'],
        },
      },
    },
  },
});

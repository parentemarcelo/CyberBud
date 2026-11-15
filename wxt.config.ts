import { defineConfig } from 'wxt';
import preact from '@preact/preset-vite';

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

export default defineConfig({
  srcDir: 'src',
  manifestVersion: 3,
  vite: () => ({
    plugins: [preact()],
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
    icons: { 48: 'icon.svg', 96: 'icon.svg' },
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

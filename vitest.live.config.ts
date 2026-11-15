import { defineConfig } from 'vitest/config';
import { WxtVitest } from 'wxt/testing/vitest-plugin';

// Live API checks: real network calls with your own keys (docs/KEYS.md or env).
// Not part of `npm test`. Run with `npm run test:live`.
export default defineConfig({
  plugins: [WxtVitest()],
  test: {
    include: ['tests/live/**/*.live.test.ts'],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
  },
});

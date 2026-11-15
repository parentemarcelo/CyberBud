import { defineConfig } from 'vitest/config';
import { WxtVitest } from 'wxt/testing/vitest-plugin';

export default defineConfig({
  plugins: [WxtVitest()],
  test: {
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx', 'src/**/*.test.ts'],
    // Live API checks make real network calls with your keys: run them with `npm run test:live`.
    exclude: ['tests/live/**', 'node_modules/**'],
    setupFiles: ['tests/setup.ts'],
  },
});

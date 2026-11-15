import { afterEach, beforeEach, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';

// Every test starts with empty extension storage and real timers.
beforeEach(() => {
  fakeBrowser.reset();
});

afterEach(() => {
  vi.useRealTimers();
});

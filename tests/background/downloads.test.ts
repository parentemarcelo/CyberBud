import { describe, expect, it, vi } from 'vitest';
import {
  NOTIFICATION_PREFIX,
  downloadIdFromNotification,
  handleDownloadChanged,
  handleNotificationClicked,
  promptMessage,
  shouldPrompt,
  type DownloadDeps,
  type DownloadInfo,
} from '../../src/background/downloads';
import { DEFAULT_RISKY_EXTENSIONS } from '../../src/lib/constants';

const risky = [...DEFAULT_RISKY_EXTENSIONS];

describe('shouldPrompt (SPEC F4 modes)', () => {
  it.each([
    ['setup.exe', 'risky', true],
    ['INVOICE.PDF.EXE', 'risky', true],
    ['report.pdf', 'risky', false],
    ['README', 'risky', false],
    ['report.pdf', 'always', true],
    ['README', 'always', true],
    ['setup.exe', 'off', false],
  ] as const)('%s in %s mode → %s', (name, mode, expected) => {
    expect(shouldPrompt(name, mode, risky)).toBe(expected);
  });

  it('uses the user-edited list', () => {
    expect(shouldPrompt('notes.pdf', 'risky', ['pdf'])).toBe(true);
    expect(shouldPrompt('setup.exe', 'risky', ['pdf'])).toBe(false);
  });
});

function deps(item: Partial<DownloadInfo> | undefined, mode: 'risky' | 'always' | 'off' = 'risky') {
  const notify = vi.fn(async () => 'id');
  const d: DownloadDeps = {
    search: async () =>
      item === undefined ? undefined : { id: 7, filename: '/dl/setup.exe', fileSize: 13_002_342, totalBytes: 13_002_342, exists: true, ...item },
    getSettings: async () => ({ downloadPrompt: mode, riskyExtensions: risky }),
    notify,
  };
  return { d, notify };
}

describe('handleDownloadChanged', () => {
  it('a completed .exe shows a notification', async () => {
    const { d, notify } = deps({});
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, d)).toBe(true);
    expect(notify).toHaveBeenCalledWith(
      `${NOTIFICATION_PREFIX}7`,
      'CyberBud: check this download?',
      'Downloaded setup.exe (12.4 MB). Click to check its hash.',
    );
  });

  it('a .pdf gets no notification in risky mode, but does in always mode', async () => {
    const pdf = { filename: '/dl/report.pdf' };
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, deps(pdf).d)).toBe(false);
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, deps(pdf, 'always').d)).toBe(true);
  });

  it('off mode never notifies', async () => {
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, deps({}, 'off').d)).toBe(false);
  });

  it('ignores non-complete changes, missing items and deleted files', async () => {
    const { d, notify } = deps({});
    expect(await handleDownloadChanged({ id: 7, state: { current: 'in_progress' } }, d)).toBe(false);
    expect(await handleDownloadChanged({ id: 7 }, d)).toBe(false);
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, deps(undefined).d)).toBe(false);
    expect(await handleDownloadChanged({ id: 7, state: { current: 'complete' } }, deps({ exists: false }).d)).toBe(false);
    expect(notify).not.toHaveBeenCalled();
  });
});

describe('promptMessage', () => {
  it('uses fileSize, then totalBytes, else no size', () => {
    expect(promptMessage({ filename: 'a.exe', fileSize: -1, totalBytes: 2048 })).toBe('Downloaded a.exe (2.0 KB). Click to check its hash.');
    expect(promptMessage({ filename: 'a.exe', fileSize: -1, totalBytes: -1 })).toBe('Downloaded a.exe. Click to check its hash.');
  });

  it('shortens very long, site-controlled names', () => {
    const msg = promptMessage({ filename: `/dl/${'x'.repeat(300)}.exe`, fileSize: 1, totalBytes: 1 });
    expect(msg.length).toBeLessThan(120);
    expect(msg).toContain('.exe');
  });
});

describe('notification click', () => {
  it('opens the File tab for that download and clears the notification', async () => {
    const open = vi.fn(async () => undefined);
    const clear = vi.fn(async () => true);
    expect(await handleNotificationClicked(`${NOTIFICATION_PREFIX}42`, open, clear)).toBe(true);
    expect(open).toHaveBeenCalledWith(expect.stringMatching(/\/app\.html\?download=42#file$/));
    expect(clear).toHaveBeenCalledWith(`${NOTIFICATION_PREFIX}42`);
  });

  it('ignores other notifications', async () => {
    const open = vi.fn();
    expect(await handleNotificationClicked('something-else', open, vi.fn())).toBe(false);
    expect(await handleNotificationClicked(`${NOTIFICATION_PREFIX}abc`, open, vi.fn())).toBe(false);
    expect(open).not.toHaveBeenCalled();
  });

  it('downloadIdFromNotification', () => {
    expect(downloadIdFromNotification(`${NOTIFICATION_PREFIX}0`)).toBe(0);
    expect(downloadIdFromNotification(`${NOTIFICATION_PREFIX}-1`)).toBeNull();
    expect(downloadIdFromNotification(`${NOTIFICATION_PREFIX}1.5`)).toBeNull();
  });
});

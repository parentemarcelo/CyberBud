// Download prompt (docs/SPEC.md F4): when a download completes, offer a hash
// check via a notification. Firefox notifications have no buttons: clicking
// means "check", ignoring means "skip". Nothing is read or sent automatically.
import { basename, fileExtension, truncateMiddle } from '../lib/files';
import { getSettings, type Settings } from '../lib/settings';
import { bytes } from '../lib/sources/common';
import type { DownloadPromptMode } from '../lib/types';

export const NOTIFICATION_PREFIX = 'cyberbud-download-';

/** Whether a completed download should get the prompt. */
export function shouldPrompt(filename: string, mode: DownloadPromptMode, risky: readonly string[]): boolean {
  if (mode === 'off') return false;
  if (mode === 'always') return true;
  const ext = fileExtension(filename);
  return ext !== '' && risky.includes(ext);
}

export interface DownloadInfo {
  id: number;
  filename: string;
  fileSize: number;
  totalBytes: number;
  state?: string;
  exists?: boolean;
}

export interface DownloadDeps {
  search: (id: number) => Promise<DownloadInfo | undefined>;
  getSettings: () => Promise<Pick<Settings, 'downloadPrompt' | 'riskyExtensions'>>;
  notify: (id: string, title: string, message: string) => Promise<unknown>;
}

export const defaultDownloadDeps: DownloadDeps = {
  search: async (id) => (await browser.downloads.search({ id }))[0] as DownloadInfo | undefined,
  getSettings,
  notify: (id, title, message) =>
    browser.notifications.create(id, {
      type: 'basic',
      title,
      message,
      // PNG: not every system notification service renders SVG.
      iconUrl: browser.runtime.getURL('/icon-96.png'),
    }),
};

/** Notification text; the file name comes from a website, so it is shortened. */
export function promptMessage(item: Pick<DownloadInfo, 'filename' | 'fileSize' | 'totalBytes'>): string {
  const name = truncateMiddle(basename(item.filename), 60);
  const size = item.fileSize >= 0 ? item.fileSize : item.totalBytes;
  return `Downloaded ${name}${size >= 0 ? ` (${bytes(size)})` : ''}. Click to check its hash.`;
}

/** downloads.onChanged handler. Returns true when a prompt was shown. */
export async function handleDownloadChanged(
  delta: { id: number; state?: { current?: string } },
  deps: DownloadDeps = defaultDownloadDeps,
): Promise<boolean> {
  if (delta.state?.current !== 'complete') return false;
  const [item, settings] = await Promise.all([deps.search(delta.id), deps.getSettings()]);
  if (!item || item.exists === false) return false;
  if (!shouldPrompt(item.filename, settings.downloadPrompt, settings.riskyExtensions)) return false;
  await deps.notify(`${NOTIFICATION_PREFIX}${item.id}`, 'CyberBud: check this download?', promptMessage(item));
  return true;
}

/** Download id from one of our notification ids, or null. */
export function downloadIdFromNotification(notificationId: string): number | null {
  if (!notificationId.startsWith(NOTIFICATION_PREFIX)) return null;
  const id = Number(notificationId.slice(NOTIFICATION_PREFIX.length));
  return Number.isInteger(id) && id >= 0 ? id : null;
}

/** notifications.onClicked handler: open the File tab for that download. */
export async function handleNotificationClicked(
  notificationId: string,
  open: (url: string) => Promise<unknown> = (url) => browser.tabs.create({ url }),
  clear: (id: string) => Promise<unknown> = (id) => browser.notifications.clear(id),
): Promise<boolean> {
  const id = downloadIdFromNotification(notificationId);
  if (id === null) return false;
  await Promise.all([open(browser.runtime.getURL(`/app.html?download=${id}#file`)), clear(notificationId)]);
  return true;
}

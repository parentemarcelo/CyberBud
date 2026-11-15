// "Check reputation" context menu (docs/SPEC.md F2).
// The lookup runs in the background engine, which persists the current view
// in storage.session; the popup shows it as soon as it connects. The popup is
// opened first, synchronously: Firefox only allows action.openPopup() during
// the click (user action), before any await.
import { MAX_INPUT_CHARS } from '../lib/constants';
import type { Engine } from './engine';

export const MENU_ID = 'cyberbud-check';

export interface MenuClickInfo {
  menuItemId: string | number;
  selectionText?: string;
  linkUrl?: string;
  pageUrl?: string;
}

export async function createContextMenu(): Promise<void> {
  await browser.contextMenus.removeAll();
  browser.contextMenus.create({
    id: MENU_ID,
    title: 'Check reputation',
    contexts: ['selection', 'link', 'page'],
  });
}

/** Text to look up: selection first, then the link, then the page. */
export function menuText(info: MenuClickInfo): string | null {
  const text = info.selectionText?.trim() || info.linkUrl || info.pageUrl || '';
  return text === '' ? null : text.slice(0, MAX_INPUT_CHARS);
}

export interface MenuDeps {
  openPopup: () => Promise<void>;
  openTab: () => Promise<unknown>;
}

export const defaultMenuDeps: MenuDeps = {
  openPopup: () => browser.action.openPopup(),
  openTab: () => browser.tabs.create({ url: browser.runtime.getURL('/app.html') }),
};

export function handleMenuClick(info: MenuClickInfo, engine: Promise<Engine>, deps: MenuDeps = defaultMenuDeps): Promise<void> {
  if (info.menuItemId !== MENU_ID) return Promise.resolve();
  const text = menuText(info);
  if (!text) return Promise.resolve();

  // Must run before any await (user-action requirement).
  let opened: Promise<unknown>;
  try {
    opened = deps.openPopup();
  } catch (err) {
    opened = Promise.reject(err);
  }
  const shown = opened.catch(() => deps.openTab()).catch(() => undefined);
  const looked = engine.then((e) => e.lookup(text, 'context_menu')).then(() => undefined, () => undefined);
  return Promise.all([shown, looked]).then(() => undefined);
}

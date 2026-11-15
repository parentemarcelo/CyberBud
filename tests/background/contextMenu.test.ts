import { describe, expect, it, vi } from 'vitest';
import { MENU_ID, handleMenuClick, menuText } from '../../src/background/contextMenu';
import type { Engine } from '../../src/background/engine';

function fakeEngine() {
  const lookup = vi.fn(async () => []);
  return { engine: Promise.resolve({ lookup } as unknown as Engine), lookup };
}

describe('menuText', () => {
  it('prefers selection, then link, then page', () => {
    expect(menuText({ menuItemId: MENU_ID, selectionText: ' 8.8.8.8 ', linkUrl: 'https://a.example/', pageUrl: 'https://p.example/' })).toBe('8.8.8.8');
    expect(menuText({ menuItemId: MENU_ID, selectionText: '  ', linkUrl: 'https://a.example/x?token=1', pageUrl: 'https://p.example/' })).toBe(
      'https://a.example/x?token=1',
    );
    expect(menuText({ menuItemId: MENU_ID, pageUrl: 'https://p.example/' })).toBe('https://p.example/');
    expect(menuText({ menuItemId: MENU_ID })).toBeNull();
  });

  it('caps very long selections', () => {
    expect(menuText({ menuItemId: MENU_ID, selectionText: 'a '.repeat(200_000) })!.length).toBe(200_000);
  });
});

describe('handleMenuClick', () => {
  it('opens the popup synchronously, then runs the lookup with origin context_menu', async () => {
    const { engine, lookup } = fakeEngine();
    const order: string[] = [];
    const openPopup = vi.fn(() => {
      order.push('popup');
      return Promise.resolve();
    });
    const p = handleMenuClick({ menuItemId: MENU_ID, selectionText: 'evil[.]example' }, engine, { openPopup, openTab: vi.fn() });
    order.push('returned');
    expect(order).toEqual(['popup', 'returned']); // called before any await
    await p;
    expect(lookup).toHaveBeenCalledWith('evil[.]example', 'context_menu');
  });

  it('falls back to a tab when the popup cannot open', async () => {
    const { engine } = fakeEngine();
    const openTab = vi.fn(async () => undefined);
    await handleMenuClick({ menuItemId: MENU_ID, linkUrl: 'https://a.example/' }, engine, {
      openPopup: () => Promise.reject(new Error('openPopup requires a user gesture')),
      openTab,
    });
    expect(openTab).toHaveBeenCalled();
  });

  it('also falls back when openPopup throws synchronously', async () => {
    const { engine } = fakeEngine();
    const openTab = vi.fn(async () => undefined);
    await handleMenuClick({ menuItemId: MENU_ID, pageUrl: 'https://p.example/' }, engine, {
      openPopup: () => {
        throw new Error('not supported');
      },
      openTab,
    });
    expect(openTab).toHaveBeenCalled();
  });

  it('ignores other menu items and empty input', async () => {
    const { engine, lookup } = fakeEngine();
    const openPopup = vi.fn(async () => undefined);
    await handleMenuClick({ menuItemId: 'other', selectionText: 'x' }, engine, { openPopup, openTab: vi.fn() });
    await handleMenuClick({ menuItemId: MENU_ID, selectionText: '' }, engine, { openPopup, openTab: vi.fn() });
    expect(openPopup).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });
});

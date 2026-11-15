// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { routeFromLocation } from '../../src/ui/App';
import { FileView } from '../../src/ui/components/FileView';
import { fakeClient } from '../helpers/port';

afterEach(() => cleanup());

const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const ABC_SHA1 = 'a9993e364706816aba3e25717850c26c9cd0d89d';

function setup(downloadId?: number) {
  const f = fakeClient();
  f.client.connect();
  f.push({ type: 'state', items: [], reports: [] });
  const utils = render(
    <FileView client={f.client} state={f.client.state} now={Date.now()} onOpenSettings={() => undefined} {...(downloadId !== undefined && { downloadId })} />,
  );
  return { ...utils, f };
}

const zone = () => screen.getByRole('button', { name: /Choose a file to check/ });
const drop = (file: File | object) => fireEvent.drop(zone(), { dataTransfer: { files: [file] } });

describe('Check file (step 27)', () => {
  it('drop → both hashes shown with copy buttons → SHA-256 lookup with origin file', async () => {
    const { f } = setup();
    drop(new File(['abc'], 'abc.txt'));
    expect(await screen.findByText(ABC_SHA256)).toBeTruthy();
    expect(screen.getByText(ABC_SHA1)).toBeTruthy();
    expect(screen.getByRole('button', { name: `Copy ${ABC_SHA256}` })).toBeTruthy();
    expect(f.sent).toContainEqual({ type: 'lookupHash', sha256: ABC_SHA256, origin: 'file' });
  });

  it('never sends file contents: only the SHA-256 leaves the page', async () => {
    const { f } = setup();
    drop(new File(['top secret contents'], 'secret.docx'));
    await screen.findByText(/SHA-256/);
    await waitFor(() => expect(f.sent.length).toBeGreaterThan(0));
    const json = JSON.stringify(f.sent);
    expect(json).not.toContain('top secret');
    expect(json).not.toContain('secret.docx');
    expect(f.sent.every((m) => m.type === 'lookupHash')).toBe(true);
  });

  it('files over 1 GiB are refused with a paste-hash hint', async () => {
    const { f } = setup();
    const huge = new File(['x'], 'huge.iso');
    Object.defineProperty(huge, 'size', { value: 1024 ** 3 + 1 });
    drop(huge);
    expect((await screen.findByRole('alert')).textContent).toMatch(/File too large for in-browser hashing.*Paste its hash/);
    expect(f.sent).toEqual([]);
  });

  it('a pasted hash is looked up', () => {
    const { f } = setup();
    fireEvent.input(screen.getByLabelText('Or paste a hash'), { target: { value: ABC_SHA256 } });
    fireEvent.click(screen.getByRole('button', { name: 'Check hash' }));
    expect(f.sent).toContainEqual({ type: 'lookup', text: ABC_SHA256, origin: 'file' });
  });

  it('the drop zone opens the file picker from the keyboard', () => {
    setup();
    const input = document.querySelector('input[type=file]') as HTMLInputElement;
    const click = vi.spyOn(input, 'click').mockImplementation(() => undefined);
    fireEvent.keyDown(zone(), { key: 'Enter' });
    expect(click).toHaveBeenCalled();
  });
});

describe('download context (from the notification)', () => {
  function stubDownload(item: object | undefined) {
    vi.spyOn(browser.downloads, 'search').mockResolvedValue((item ? [item] : []) as never);
    return vi.spyOn(browser.downloads, 'show').mockResolvedValue(true as never);
  }

  it('shows the name and size, and "Show in folder" calls downloads.show', async () => {
    const show = stubDownload({ id: 5, filename: '/home/u/Downloads/abc.txt', fileSize: 3, totalBytes: 3 });
    setup(5);
    expect(await screen.findByText('abc.txt')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Show in folder' }));
    expect(show).toHaveBeenCalledWith(5);
  });

  it('the right file gives no warning', async () => {
    stubDownload({ id: 5, filename: '/dl/abc.txt', fileSize: 3, totalBytes: 3 });
    setup(5);
    await screen.findByText('abc.txt');
    drop(new File(['abc'], 'abc.txt'));
    await screen.findByText(ABC_SHA256);
    expect(screen.queryByText(/doesn't look like/)).toBeNull();
  });

  it('a different file shows the mismatch warning (non-blocking)', async () => {
    stubDownload({ id: 5, filename: '/dl/setup.exe', fileSize: 999, totalBytes: 999 });
    const { f } = setup(5);
    await screen.findByText('setup.exe');
    drop(new File(['abc'], 'abc.txt'));
    expect((await screen.findByRole('alert')).textContent).toMatch(/doesn't look like setup\.exe \(different name and size\)/);
    expect(f.sent).toContainEqual({ type: 'lookupHash', sha256: ABC_SHA256, origin: 'file' });
  });

  it('same name but different size also warns', async () => {
    stubDownload({ id: 5, filename: '/dl/abc.txt', fileSize: 10, totalBytes: 10 });
    setup(5);
    await screen.findByText('abc.txt');
    drop(new File(['abc'], 'abc.txt'));
    expect((await screen.findByRole('alert')).textContent).toMatch(/different size/);
  });
});

describe('routeFromLocation', () => {
  it.each([
    [{ hash: '#file', search: '' }, 'tab', { tab: 'file' }],
    [{ hash: '#file', search: '?download=42' }, 'tab', { tab: 'file', downloadId: 42 }],
    [{ hash: '', search: '?download=42' }, 'tab', { tab: 'file', downloadId: 42 }],
    [{ hash: '', search: '' }, 'tab', { tab: 'lookup' }],
    [{ hash: '#file', search: '' }, 'popup', { tab: 'lookup' }],
    [{ hash: '#file', search: '?download=abc' }, 'tab', { tab: 'file' }],
    [{ hash: '#file', search: '?download=-3' }, 'tab', { tab: 'file' }],
  ] as const)('%j in %s → %j', (loc, mode, expected) => {
    expect(routeFromLocation(loc, mode)).toEqual(expected);
  });
});

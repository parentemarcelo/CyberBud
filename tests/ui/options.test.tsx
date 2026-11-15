// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getSettings, updateSettings } from '../../src/lib/settings';
import { OptionsPage } from '../../src/ui/options/OptionsPage';
import { fakeClient } from '../helpers/port';

// Permission stubs are re-created by every test and deliberately not restored:
// fakeBrowser doesn't implement permissions events, and unmounting removes listeners.
afterEach(() => cleanup());

function stubPermissions(granted: boolean) {
  vi.spyOn(browser.permissions, 'contains').mockResolvedValue(granted as never);
  const request = vi.spyOn(browser.permissions, 'request').mockResolvedValue(true as never);
  vi.spyOn(browser.permissions.onAdded, 'addListener').mockImplementation(() => undefined);
  vi.spyOn(browser.permissions.onRemoved, 'addListener').mockImplementation(() => undefined);
  vi.spyOn(browser.permissions.onAdded, 'removeListener').mockImplementation(() => undefined);
  vi.spyOn(browser.permissions.onRemoved, 'removeListener').mockImplementation(() => undefined);
  return { request };
}

async function renderOptions(granted = true) {
  const perms = stubPermissions(granted);
  const f = fakeClient();
  render(<OptionsPage clientFactory={() => f.client} />);
  await screen.findByText('CyberBud Settings');
  return { f, ...perms };
}

describe('Options page (step 21)', () => {
  it('shows the VirusTotal dataset notice and the unencrypted-storage note', async () => {
    await renderOptions();
    expect(screen.getByText(/may be added to the VirusTotal/)).toBeTruthy();
    expect(screen.getByText('unencrypted')).toBeTruthy();
  });

  it('key fields are masked, with a show toggle', async () => {
    await renderOptions();
    const input = screen.getByLabelText('VirusTotal API key') as HTMLInputElement;
    expect(input.type).toBe('password');
    fireEvent.click(screen.getAllByRole('button', { name: 'Show' })[0]!);
    expect((screen.getByLabelText('VirusTotal API key') as HTMLInputElement).type).toBe('text');
  });

  it('Save stores the trimmed key; Test sends testKey and shows the answer', async () => {
    const { f } = await renderOptions();
    fireEvent.input(screen.getByLabelText('VirusTotal API key'), { target: { value: '  my-vt-key-123 ' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0]!);
    await waitFor(async () => expect((await getSettings()).keys.vt).toBe('my-vt-key-123'));

    fireEvent.click(screen.getAllByRole('button', { name: 'Test' })[0]!);
    expect(f.sent).toContainEqual({ type: 'testKey', keyId: 'vt', apiKey: 'my-vt-key-123' });
    f.push({ type: 'keyTest', keyId: 'vt', result: 'invalid' });
    expect(await screen.findByText('Invalid key')).toBeTruthy();
    f.push({ type: 'keyTest', keyId: 'vt', result: 'ok' });
    expect(await screen.findByText('OK: key works')).toBeTruthy();
  });

  it('rejects keys with spaces before saving', async () => {
    await renderOptions();
    fireEvent.input(screen.getByLabelText('AbuseIPDB API key'), { target: { value: 'has space' } });
    expect(await screen.findByText(/without spaces/)).toBeTruthy();
    expect(screen.getAllByRole('button', { name: 'Save' })[1]).toHaveProperty('disabled', true);
  });

  it('typing right after the page opens is not overwritten', async () => {
    await renderOptions();
    fireEvent.input(screen.getByLabelText('VirusTotal API key'), { target: { value: 'typed-fast' } });
    await new Promise((r) => setTimeout(r, 50));
    expect((screen.getByLabelText('VirusTotal API key') as HTMLInputElement).value).toBe('typed-fast');
  });

  it('a key saved elsewhere updates the field', async () => {
    await renderOptions();
    await updateSettings({ keys: { abusech: 'from-other-tab' } });
    await waitFor(() =>
      expect((screen.getByLabelText(/abuse\.ch Auth-Key/) as HTMLInputElement).value).toBe('from-other-tab'),
    );
  });

  it('changing settings persists them', async () => {
    await renderOptions();
    fireEvent.click(screen.getByLabelText(/Full URL/));
    fireEvent.click(screen.getByRole('checkbox', { name: 'VirusTotal' }));
    fireEvent.change(screen.getByLabelText(/Keep results in the cache/), { target: { value: '6' } });
    await waitFor(async () => {
      const s = await getSettings();
      expect(s.urlMode).toBe('full');
      expect(s.enabledSources.virustotal).toBe(false);
      expect(s.cacheTtlHours).toBe(6);
    });
  });

  it('reflects settings changed elsewhere', async () => {
    await renderOptions();
    await updateSettings({ urlMode: 'domain' });
    await waitFor(() => expect((screen.getByLabelText(/Domain only/) as HTMLInputElement).checked).toBe(true));
  });

  it('Clear cache / Clear history go through the background', async () => {
    const { f } = await renderOptions();
    fireEvent.click(screen.getByRole('button', { name: 'Clear cache' }));
    vi.stubGlobal('confirm', () => true);
    fireEvent.click(screen.getByRole('button', { name: 'Clear history' }));
    vi.unstubAllGlobals();
    expect(f.sent).toEqual(expect.arrayContaining([{ type: 'clearCache' }, { type: 'clearHistory' }]));
    f.push({ type: 'cleared', what: 'cache' });
    expect(await screen.findByText('Cache cleared.')).toBeTruthy();
  });

  it('shows the Grant banner when host permissions are missing', async () => {
    const { request } = await renderOptions(false);
    const grant = await screen.findByRole('button', { name: 'Grant' });
    fireEvent.click(grant);
    expect(request).toHaveBeenCalledWith({ origins: expect.arrayContaining(['https://www.virustotal.com/*']) });
  });

  it('no banner when permissions are granted', async () => {
    await renderOptions(true);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Grant' })).toBeNull());
  });
});

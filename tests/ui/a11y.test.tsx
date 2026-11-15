// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { updateSettings } from '../../src/lib/settings';
import { result } from '../../src/lib/sources/common';
import { App } from '../../src/ui/App';
import { UNREACHABLE } from '../../src/ui/client';
import { SourceCard } from '../../src/ui/components/SourceCard';
import { fakeClient } from '../helpers/port';

afterEach(() => cleanup());

describe('first run (step 30)', () => {
  it('with no keys, the Lookup tab points to Settings', async () => {
    const open = vi.spyOn(browser.runtime, 'openOptionsPage').mockResolvedValue(undefined);
    render(<App mode="popup" clientFactory={() => fakeClient().client} />);
    expect(await screen.findByText('Welcome to CyberBud.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Open Settings' }));
    expect(open).toHaveBeenCalled();
  });

  it('the banner disappears once a key is saved', async () => {
    render(<App mode="popup" clientFactory={() => fakeClient().client} />);
    await screen.findByText('Welcome to CyberBud.');
    await updateSettings({ keys: { abusech: 'k' } });
    await waitFor(() => expect(screen.queryByText('Welcome to CyberBud.')).toBeNull());
  });

  it('no banner when a key is already set', async () => {
    await updateSettings({ keys: { vt: 'k' } });
    render(<App mode="popup" clientFactory={() => fakeClient().client} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText('Welcome to CyberBud.')).toBeNull();
  });
});

describe('keyboard: tabs follow the ARIA pattern', () => {
  it('arrows, Home and End move selection and focus; only the active tab is tabbable', () => {
    render(<App mode="tab" clientFactory={() => fakeClient().client} />);
    const tab = (name: string) => screen.getByRole('tab', { name });
    expect(tab('Lookup').tabIndex).toBe(0);
    expect(tab('Check file').tabIndex).toBe(-1);

    fireEvent.keyDown(tab('Lookup'), { key: 'ArrowRight' });
    expect(tab('Check file').getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(tab('Check file'));

    fireEvent.keyDown(tab('Check file'), { key: 'End' });
    expect(tab('History').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('History'), { key: 'ArrowRight' });
    expect(tab('Lookup').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('Lookup'), { key: 'ArrowLeft' });
    expect(tab('History').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('History'), { key: 'Home' });
    expect(tab('Lookup').getAttribute('aria-selected')).toBe('true');
  });

  it('the lookup box has focus when the popup opens', () => {
    render(<App mode="popup" clientFactory={() => fakeClient().client} />);
    expect(document.activeElement).toBe(screen.getByLabelText('IOCs to check'));
  });
});

describe('readable errors', () => {
  const ioc = { raw: 'x', value: 'x.example', type: 'domain' as const };
  it('an invalid-key error offers "Check key in Settings"', () => {
    const onOpenSettings = vi.fn();
    render(
      <SourceCard
        r={result('virustotal', ioc, { status: 'error', headline: '', error: 'Invalid or unauthorized key' })}
        now={Date.now()}
        actions={{ onRefresh: vi.fn(), onOpenSettings }}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Check key in Settings' }));
    expect(onOpenSettings).toHaveBeenCalled();
  });

  it('other errors offer Retry only', () => {
    render(
      <SourceCard
        r={result('virustotal', ioc, { status: 'error', headline: '', error: 'Network error, check your connection' })}
        now={Date.now()}
        actions={{ onRefresh: vi.fn(), onOpenSettings: vi.fn() }}
      />,
    );
    expect(screen.queryByRole('button', { name: 'Check key in Settings' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  });

  it('after repeated disconnects the user is told how to recover', () => {
    vi.useFakeTimers();
    const f = fakeClient();
    f.client.connect();
    for (let i = 0; i < 6; i++) {
      f.drop();
      vi.advanceTimersByTime(5000);
    }
    expect(f.client.state.error).toBe(UNREACHABLE);
  });
});

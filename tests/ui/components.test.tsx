// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { addHistory } from '../../src/lib/history';
import { result } from '../../src/lib/sources/common';
import type { Ioc, IocReport, ParseResult, SourceResult } from '../../src/lib/types';
import { summarize } from '../../src/lib/verdict';
import { App } from '../../src/ui/App';
import { HistoryView } from '../../src/ui/components/HistoryView';
import { LookupView } from '../../src/ui/components/LookupView';
import { fakeClient } from '../helpers/port';

afterEach(() => cleanup());

const NOW = Date.UTC(2026, 10, 15, 12);
const dom: Ioc = { raw: 'evil[.]example', value: 'evil.example', type: 'domain' };
const reportOf = (ioc: Ioc, results: SourceResult[]): IocReport => ({ ioc, results, summary: summarize(results) });

function renderLookup(items: ParseResult[], reports: IocReport[] = []) {
  const f = fakeClient();
  f.client.connect();
  f.push({ type: 'state', items, reports });
  const onOpenSettings = vi.fn();
  const utils = render(<LookupView client={f.client} state={f.client.state} now={NOW} onOpenSettings={onOpenSettings} />);
  return { ...utils, f, onOpenSettings };
}

describe('LookupView: input', () => {
  it('Enter submits a lookup; Shift+Enter does not', () => {
    const { f } = renderLookup([]);
    const box = screen.getByLabelText('IOCs to check');
    fireEvent.input(box, { target: { value: 'evil[.]example' } });
    fireEvent.keyDown(box, { key: 'Enter', shiftKey: true });
    expect(f.sent.filter((m) => m.type === 'lookup')).toEqual([]);
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(f.sent).toContainEqual({ type: 'lookup', text: 'evil[.]example', origin: 'popup' });
  });

  it('the Check button is disabled for empty input', () => {
    renderLookup([]);
    expect(screen.getByRole('button', { name: 'Check' })).toHaveProperty('disabled', true);
  });
});

describe('LookupView: single IOC (step 22)', () => {
  const results: SourceResult[] = [
    result('virustotal', dom, { status: 'ok', verdict: 'malicious', headline: '12/94 engines', details: [['Registrar', 'Example']], link: 'https://www.virustotal.com/gui/domain/evil.example', fromCache: true, fetchedAt: NOW - 3 * 3_600_000 }),
    result('abuseipdb', dom, { status: 'loading', headline: '' }),
    result('urlhaus', dom, { status: 'queued', headline: 'Queued', retryAt: NOW + 45_000 }),
    result('malwarebazaar', dom, { status: 'no_key', headline: '' }),
    result('threatfox', dom, { status: 'error', headline: '', error: 'Invalid or unauthorized key' }),
  ];

  it('shows the row header: type, value, verdict chip with text, N of M', () => {
    renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, results)]);
    const row = screen.getByRole('listitem');
    expect(within(row).getByText('Domain')).toBeTruthy();
    expect(within(row).getByText('evil.example')).toBeTruthy();
    expect(within(row).getAllByText('Malicious').length).toBeGreaterThan(0);
    expect(within(row).getByText('1 of 1 source flags this')).toBeTruthy();
  });

  it('a single result is expanded and shows every card state', () => {
    renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, results)]);
    expect(screen.getByText('12/94 engines')).toBeTruthy();
    expect(screen.getByText('cached 3 h ago')).toBeTruthy();
    expect(screen.getByText('Checking…')).toBeTruthy();
    expect(screen.getByText('Queued (≈45 s)')).toBeTruthy();
    expect(screen.getByText('No API key set')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toBe('Invalid or unauthorized key');
    const link = screen.getByRole('link', { name: /Open in VirusTotal/ });
    expect(link.getAttribute('href')).toBe('https://www.virustotal.com/gui/domain/evil.example');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
  });

  it('Refresh / Retry send refresh for that source; no-key opens settings', () => {
    const { f, onOpenSettings } = renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, results)]);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(f.sent.filter((m) => m.type === 'refresh').map((m) => m.type === 'refresh' && m.source)).toEqual(['virustotal', 'threatfox']);
    fireEvent.click(screen.getByRole('button', { name: 'Add key in Settings' }));
    expect(onOpenSettings).toHaveBeenCalled();
  });

  it('details render as text (no HTML injection)', () => {
    const evil = result('virustotal', dom, { status: 'ok', verdict: 'clean', headline: '<img src=x onerror=alert(1)>', details: [['Title', '<script>alert(1)</script>']] });
    const { container } = renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, [evil])]);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeTruthy();
  });

  it('a non-https link is not rendered', () => {
    const bad = result('virustotal', dom, { status: 'ok', verdict: 'clean', headline: 'x', link: 'javascript:alert(1)' });
    renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, [bad])]);
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('all-unknown shows the no-data warning', () => {
    renderLookup([{ kind: 'ioc', ioc: dom }], [reportOf(dom, [result('urlhaus', dom, { status: 'not_found', headline: 'Not listed in URLhaus' })])]);
    expect(screen.getByText('No source has data on this IOC. This does not mean it is safe.')).toBeTruthy();
  });
});

describe('LookupView: multiple IOCs (step 23)', () => {
  it('shows each row, private/unsupported labels, and collapses skipped items', () => {
    const iocs: ParseResult[] = Array.from({ length: 20 }, (_, i) => ({ kind: 'ioc', ioc: { raw: `h${i}.example`, value: `h${i}.example`, type: 'domain' } }));
    const items: ParseResult[] = [
      ...iocs,
      { kind: 'private', raw: '10.0.0.1', value: '10.0.0.1' },
      { kind: 'unsupported', raw: 'foo' },
      ...Array.from({ length: 5 }, (_, i): ParseResult => ({ kind: 'skipped', raw: `s${i}.example` })),
    ];
    renderLookup(items);
    expect(screen.getAllByRole('listitem')).toHaveLength(23);
    expect(screen.getByText('Private/reserved, not looked up')).toBeTruthy();
    expect(screen.getByText('Unsupported input')).toBeTruthy();
    expect(screen.getByText('5 more skipped (limit 20 per lookup)')).toBeTruthy();
    // Several results start collapsed.
    expect(screen.getAllByRole('button', { name: 'Show sources' })).toHaveLength(20);
  });

  it('expanding a row shows its cards', () => {
    const a: Ioc = { raw: 'a.example', value: 'a.example', type: 'domain' };
    const b: Ioc = { raw: 'b.example', value: 'b.example', type: 'domain' };
    renderLookup(
      [{ kind: 'ioc', ioc: a }, { kind: 'ioc', ioc: b }],
      [reportOf(a, [result('virustotal', a, { status: 'ok', verdict: 'clean', headline: '0/90 engines' })])],
    );
    expect(screen.queryByText('0/90 engines')).toBeNull();
    fireEvent.click(screen.getAllByRole('button', { name: 'Show sources' })[0]!);
    expect(screen.getByText('0/90 engines')).toBeTruthy();
  });
});

describe('HistoryView (step 24)', () => {
  it('lists entries newest first; clicking reopens; Clear asks first', async () => {
    await addHistory({ value: 'old.example', type: 'domain' }, 'clean', 'popup', { historyEnabled: true }, NOW - 7_200_000);
    await addHistory({ value: 'new.example', type: 'domain' }, 'malicious', 'context_menu', { historyEnabled: true }, NOW - 60_000);
    const f = fakeClient();
    f.client.connect();
    const onOpened = vi.fn();
    render(<HistoryView client={f.client} now={NOW} onOpened={onOpened} />);
    const items = await screen.findAllByRole('button', { name: /example/ });
    expect(items.map((b) => b.textContent)).toEqual([expect.stringContaining('new.example'), expect.stringContaining('old.example')]);
    expect(items[0]!.textContent).toContain('Malicious');

    fireEvent.click(items[0]!);
    expect(f.sent).toContainEqual({ type: 'open', ioc: { raw: 'new.example', value: 'new.example', type: 'domain' } });
    expect(onOpened).toHaveBeenCalled();

    vi.stubGlobal('confirm', () => false);
    fireEvent.click(screen.getByRole('button', { name: 'Clear history' }));
    expect(f.sent.some((m) => m.type === 'clearHistory')).toBe(false);
    vi.stubGlobal('confirm', () => true);
    fireEvent.click(screen.getByRole('button', { name: 'Clear history' }));
    expect(f.sent).toContainEqual({ type: 'clearHistory' });
    vi.unstubAllGlobals();
  });

  it('empty history', async () => {
    const f = fakeClient();
    render(<HistoryView client={f.client} now={NOW} onOpened={() => undefined} />);
    expect(await screen.findByText('No lookups yet.')).toBeTruthy();
  });
});

describe('App shell', () => {
  it('switches between Lookup and History tabs', async () => {
    const f = fakeClient();
    render(<App mode="popup" clientFactory={() => f.client} />);
    expect(screen.getByRole('tab', { name: 'Lookup' }).getAttribute('aria-selected')).toBe('true');
    fireEvent.click(screen.getByRole('tab', { name: 'History' }));
    expect(await screen.findByText('No lookups yet.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Open in a tab' })).toBeTruthy();
  });

  it('tab mode has no "Open in a tab" button but has the Check file tab', () => {
    const f = fakeClient();
    render(<App mode="tab" clientFactory={() => f.client} />);
    expect(screen.queryByRole('button', { name: 'Open in a tab' })).toBeNull();
    expect(screen.getByRole('tab', { name: 'Check file' })).toBeTruthy();
  });

  it('the popup has no File tab, only a link that opens it in a tab', () => {
    const f = fakeClient();
    const create = vi.spyOn(browser.tabs, 'create').mockResolvedValue({} as never);
    vi.stubGlobal('close', vi.fn());
    render(<App mode="popup" clientFactory={() => f.client} />);
    expect(screen.queryByRole('tab', { name: 'Check file' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Check a file…' }));
    expect(create).toHaveBeenCalledWith({ url: expect.stringMatching(/\/app\.html#file$/) });
    vi.unstubAllGlobals();
  });
});

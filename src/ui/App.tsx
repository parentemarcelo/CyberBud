import { useState } from 'preact/hooks';
import type { LookupClient } from './client';
import { FileView } from './components/FileView';
import { HistoryView } from './components/HistoryView';
import { LookupView } from './components/LookupView';
import { useLookupClient, useNow } from './hooks';

type Tab = 'lookup' | 'file' | 'history';

const TAB_LABEL: Record<Tab, string> = { lookup: 'Lookup', file: 'Check file', history: 'History' };

/** Initial tab and download id from the page URL (app.html?download=<id>#file). */
export function routeFromLocation(loc: Pick<Location, 'hash' | 'search'>, mode: 'popup' | 'tab'): { tab: Tab; downloadId?: number } {
  const id = Number(new URLSearchParams(loc.search).get('download'));
  const downloadId = Number.isInteger(id) && id >= 0 && new URLSearchParams(loc.search).has('download') ? id : undefined;
  const tab: Tab = mode === 'tab' && (loc.hash === '#file' || downloadId !== undefined) ? 'file' : 'lookup';
  return { tab, ...(downloadId !== undefined && { downloadId }) };
}

export function App({ mode, clientFactory }: { mode: 'popup' | 'tab'; clientFactory?: () => LookupClient }) {
  const { client, state } = useLookupClient(clientFactory);
  const now = useNow();
  const [route] = useState(() => routeFromLocation(window.location, mode));
  const [tab, setTab] = useState<Tab>(route.tab);
  const tabs: Tab[] = mode === 'tab' ? ['lookup', 'file', 'history'] : ['lookup', 'history'];
  const openFileTab = () => {
    void browser.tabs.create({ url: browser.runtime.getURL('/app.html#file') });
    if (mode === 'popup') window.close();
  };

  const openSettings = () => void browser.runtime.openOptionsPage();
  const openInTab = () => {
    void browser.tabs.create({ url: browser.runtime.getURL('/app.html') });
    if (mode === 'popup') window.close();
  };

  return (
    <div class={`app ${mode}`}>
      <header class="app-header">
        <h1 class="app-title">CyberBud</h1>
        {mode === 'popup' && (
          <button type="button" class="btn icon" title="Open in a tab" aria-label="Open in a tab" onClick={openInTab}>
            ⤢
          </button>
        )}
        <button type="button" class="btn icon" title="Settings" aria-label="Settings" onClick={openSettings}>
          ⚙
        </button>
      </header>
      <nav class="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            id={`tab-${t}`}
            class="tab-btn"
            aria-selected={tab === t}
            aria-controls="panel"
            onClick={() => setTab(t)}
          >
            {TAB_LABEL[t]}
          </button>
        ))}
      </nav>
      <div class="panel" role="tabpanel" id="panel" aria-labelledby={`tab-${tab}`}>
        {tab === 'lookup' && (
          <>
            {mode === 'popup' && (
              <p class="file-link small">
                <button type="button" class="btn link" onClick={openFileTab}>
                  Check a file…
                </button>
                <span class="muted"> (opens in a tab)</span>
              </p>
            )}
            <LookupView client={client} state={state} now={now} onOpenSettings={openSettings} />
          </>
        )}
        {tab === 'file' && (
          <FileView
            client={client}
            state={state}
            now={now}
            onOpenSettings={openSettings}
            {...(route.downloadId !== undefined && { downloadId: route.downloadId })}
          />
        )}
        {tab === 'history' && <HistoryView client={client} now={now} onOpened={() => setTab('lookup')} />}
      </div>
    </div>
  );
}

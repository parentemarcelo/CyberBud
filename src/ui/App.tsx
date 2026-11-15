import { useState } from 'preact/hooks';
import type { LookupClient } from './client';
import { HistoryView } from './components/HistoryView';
import { LookupView } from './components/LookupView';
import { useLookupClient, useNow } from './hooks';

type Tab = 'lookup' | 'history';

export function App({ mode, clientFactory }: { mode: 'popup' | 'tab'; clientFactory?: () => LookupClient }) {
  const { client, state } = useLookupClient(clientFactory);
  const now = useNow();
  const [tab, setTab] = useState<Tab>('lookup');

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
        {(['lookup', 'history'] as const).map((t) => (
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
            {t === 'lookup' ? 'Lookup' : 'History'}
          </button>
        ))}
      </nav>
      <div class="panel" role="tabpanel" id="panel" aria-labelledby={`tab-${tab}`}>
        {tab === 'lookup' ? (
          <LookupView client={client} state={state} now={now} onOpenSettings={openSettings} />
        ) : (
          <HistoryView client={client} now={now} onOpened={() => setTab('lookup')} />
        )}
      </div>
    </div>
  );
}

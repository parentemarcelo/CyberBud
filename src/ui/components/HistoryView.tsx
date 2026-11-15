import { useEffect, useState } from 'preact/hooks';
import { HISTORY_KEY, listHistory, type HistoryEntry } from '../../lib/history';
import type { LookupClient } from '../client';
import { relativeTime } from '../format';
import { TypeBadge, VerdictChip } from './Bits';

/** Past lookups, newest first. Clicking one reopens it (cache or re-run). */
export function HistoryView({ client, now, onOpened }: { client: LookupClient; now: number; onOpened: () => void }) {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);

  useEffect(() => {
    const load = () => void listHistory().then(setEntries);
    load();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      if (area === 'local' && HISTORY_KEY in changes) load();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, []);

  if (entries === null) return <p class="muted">Loading…</p>;

  return (
    <div>
      <div class="toolbar">
        <span class="muted small">
          {entries.length} lookup{entries.length === 1 ? '' : 's'} · stored only in this browser
        </span>
        <button
          type="button"
          class="btn"
          disabled={entries.length === 0}
          onClick={() => {
            if (confirm('Clear all lookup history?')) client.send({ type: 'clearHistory' });
          }}
        >
          Clear history
        </button>
      </div>
      {entries.length === 0 ? (
        <p class="muted">No lookups yet.</p>
      ) : (
        <ul class="history" aria-label="History">
          {entries.map((e) => (
            <li key={`${e.type}|${e.value}`}>
              <button
                type="button"
                class="history-item"
                onClick={() => {
                  client.send({ type: 'open', ioc: { raw: e.value, value: e.value, type: e.type } });
                  onOpened();
                }}
              >
                <TypeBadge type={e.type} />
                <span class="mono">{e.value}</span>
                <span class="row-actions">
                  <VerdictChip verdict={e.verdict} />
                  <span class="muted small">{relativeTime(e.timestamp, now)}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

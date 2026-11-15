import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import {
  CACHE_TTL_HOURS_MAX,
  HISTORY_RETENTION_DAYS_MAX,
  HISTORY_RETENTION_DAYS_MIN,
  getSettings,
  parseExtensionList,
  subscribeSettings,
  updateSettings,
  type Settings,
  type SettingsPatch,
} from '../../lib/settings';
import { SOURCE_API_ORIGINS } from '../../lib/sources/registry';
import { SOURCE_IDS, type KeyId, type KeyTestOutcome } from '../../lib/types';
import { LookupClient } from '../client';
import { SOURCE_NAME } from '../format';

export const HOST_ORIGINS = SOURCE_API_ORIGINS.map((o) => `${o}/*`);

const KEY_FIELDS: Array<{ id: KeyId; label: string; help: string; url: string }> = [
  { id: 'vt', label: 'VirusTotal API key', help: 'Free account → API key', url: 'https://www.virustotal.com/gui/my-apikey' },
  { id: 'abuseipdb', label: 'AbuseIPDB API key', help: 'Free account → API → Create key', url: 'https://www.abuseipdb.com/account/api' },
  {
    id: 'abusech',
    label: 'abuse.ch Auth-Key (URLhaus, MalwareBazaar, ThreatFox)',
    help: 'One free key works for all three',
    url: 'https://auth.abuse.ch/',
  },
];

const TEST_TEXT: Record<KeyTestOutcome, string> = {
  ok: 'OK: key works',
  invalid: 'Invalid key',
  error: 'Network error, try again',
  busy: 'Rate limit reached, try again in a minute',
};

export function OptionsPage({ clientFactory }: { clientFactory?: () => LookupClient }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [hostsGranted, setHostsGranted] = useState(true);
  const [notice, setNotice] = useState('');
  const client = useMemo(() => (clientFactory ? clientFactory() : new LookupClient()), []);

  useEffect(() => {
    void getSettings().then(setSettings);
    const unsubscribe = subscribeSettings(setSettings);
    const checkHosts = () => void browser.permissions.contains({ origins: HOST_ORIGINS }).then(setHostsGranted, () => setHostsGranted(false));
    checkHosts();
    browser.permissions.onAdded.addListener(checkHosts);
    browser.permissions.onRemoved.addListener(checkHosts);
    client.connect();
    const off = client.onMessage((m) => {
      if (m.type === 'cleared') setNotice(m.what === 'cache' ? 'Cache cleared.' : 'History cleared.');
    });
    return () => {
      unsubscribe();
      off();
      client.close();
      browser.permissions.onAdded.removeListener(checkHosts);
      browser.permissions.onRemoved.removeListener(checkHosts);
    };
  }, [client]);

  if (!settings) return <p class="options muted">Loading…</p>;
  const save = (patch: SettingsPatch) => void updateSettings(patch).then(setSettings);

  return (
    <main class="options">
      <h1>CyberBud Settings</h1>
      <p class="muted">Everything is stored only in this browser. Lookups go directly from Firefox to each source.</p>

      {!hostsGranted && (
        <div class="banner" role="alert">
          CyberBud can't reach the reputation APIs: host permissions are missing.{' '}
          <button
            type="button"
            class="btn primary"
            onClick={() => void browser.permissions.request({ origins: HOST_ORIGINS }).then(setHostsGranted)}
          >
            Grant
          </button>
        </div>
      )}

      <h2>API keys</h2>
      <p class="notice small">
        Keys are stored <strong>unencrypted</strong> in your Firefox profile (<code>storage.local</code>), never synced.
        <br />
        <strong>VirusTotal:</strong> VirusTotal states that any IOC queried through its API may be added to the VirusTotal
        dataset, visible to its community. Don't look up sensitive values there. This is why URLs are sent without their
        query string by default (see Privacy below).
      </p>
      {KEY_FIELDS.map((f) => (
        <KeyField key={f.id} field={f} value={settings.keys[f.id]} client={client} onSave={(v) => save({ keys: { [f.id]: v } })} />
      ))}

      <h2>Sources</h2>
      {SOURCE_IDS.map((id) => (
        <label key={id} class="choice">
          <input
            type="checkbox"
            checked={settings.enabledSources[id]}
            onChange={(e) => save({ enabledSources: { [id]: (e.target as HTMLInputElement).checked } })}
          />
          <span>{SOURCE_NAME[id]}</span>
        </label>
      ))}
      <p class="muted small">A source without a key is skipped and shows "No API key set".</p>

      <h2>Privacy: what part of a URL is sent</h2>
      {(
        [
          ['strip', 'Without query string (recommended)', 'https://site/path?token=… → https://site/path'],
          ['full', 'Full URL', 'Query strings can contain secrets such as reset tokens or session IDs.'],
          ['domain', 'Domain only', 'Look up only the host, as a domain or IP.'],
        ] as const
      ).map(([value, label, help]) => (
        <label key={value} class="choice">
          <input type="radio" name="urlMode" checked={settings.urlMode === value} onChange={() => save({ urlMode: value })} />
          <span>
            {label}
            <br />
            <span class="muted small">{help}</span>
          </span>
        </label>
      ))}
      <p class="muted small">The part after # is never sent. Private and local addresses are never sent.</p>

      <h2>Downloads</h2>
      <div class="field">
        <label for="dl-mode">Offer a hash check when a download finishes</label>
        <select
          id="dl-mode"
          value={settings.downloadPrompt}
          onChange={(e) => save({ downloadPrompt: (e.target as HTMLSelectElement).value as Settings['downloadPrompt'] })}
        >
          <option value="risky">Only for risky file types</option>
          <option value="always">For every download</option>
          <option value="off">Never</option>
        </select>
      </div>
      <ExtensionsField value={settings.riskyExtensions} onSave={(list) => save({ riskyExtensions: list })} />

      <h2>Cache and history</h2>
      <div class="field">
        <label for="ttl">Keep results in the cache for (hours, 0 = no cache)</label>
        <input
          id="ttl"
          type="number"
          min={0}
          max={CACHE_TTL_HOURS_MAX}
          value={settings.cacheTtlHours}
          onChange={(e) => save({ cacheTtlHours: Number((e.target as HTMLInputElement).value) })}
        />
      </div>
      <label class="choice">
        <input type="checkbox" checked={settings.historyEnabled} onChange={(e) => save({ historyEnabled: (e.target as HTMLInputElement).checked })} />
        <span>Keep lookup history</span>
      </label>
      <div class="field">
        <label for="retention">Delete history after (days)</label>
        <input
          id="retention"
          type="number"
          min={HISTORY_RETENTION_DAYS_MIN}
          max={HISTORY_RETENTION_DAYS_MAX}
          disabled={!settings.historyEnabled}
          value={settings.historyRetentionDays}
          onChange={(e) => save({ historyRetentionDays: Number((e.target as HTMLInputElement).value) })}
        />
      </div>
      <div class="field-row">
        <button type="button" class="btn" onClick={() => client.send({ type: 'clearCache' })}>
          Clear cache
        </button>
        <button
          type="button"
          class="btn"
          onClick={() => {
            if (confirm('Clear all lookup history?')) client.send({ type: 'clearHistory' });
          }}
        >
          Clear history
        </button>
        <span class="muted" role="status">
          {notice}
        </span>
      </div>
    </main>
  );
}

function KeyField({
  field,
  value,
  client,
  onSave,
}: {
  field: (typeof KEY_FIELDS)[number];
  value: string;
  client: LookupClient;
  onSave: (v: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  const [show, setShow] = useState(false);
  const [status, setStatus] = useState<{ text: string; ok: boolean } | null>(null);
  useSyncedDraft(value, setDraft);
  useEffect(
    () =>
      client.onMessage((m) => {
        if (m.type === 'keyTest' && m.keyId === field.id) setStatus({ text: TEST_TEXT[m.result], ok: m.result === 'ok' });
      }),
    [client, field.id],
  );

  const inputId = `key-${field.id}`;
  const trimmed = draft.trim();
  const valid = trimmed === '' || /^[\x21-\x7e]{1,512}$/.test(trimmed);
  const inputProps = {
    id: inputId,
    class: 'key-input',
    autocomplete: 'off',
    spellcheck: false,
    value: draft,
    'aria-invalid': !valid,
    onInput: (e: Event) => {
      setDraft((e.target as HTMLInputElement).value);
      setStatus(null);
    },
  };
  return (
    <div class="field">
      <label for={inputId}>{field.label}</label>
      <div class="field-row">
        {show ? <input type="text" {...inputProps} /> : <input type="password" {...inputProps} />}
        <button type="button" class="btn" aria-pressed={show} onClick={() => setShow(!show)}>
          {show ? 'Hide' : 'Show'}
        </button>
        <button type="button" class="btn primary" disabled={!valid || trimmed === value} onClick={() => onSave(trimmed)}>
          Save
        </button>
        <button
          type="button"
          class="btn"
          disabled={!valid || trimmed === ''}
          onClick={() => {
            setStatus({ text: 'Testing…', ok: true });
            client.send({ type: 'testKey', keyId: field.id, apiKey: trimmed });
          }}
        >
          Test
        </button>
      </div>
      <span class="small" role="status">
        {!valid ? (
          <span class="status-bad">Keys contain only printable characters without spaces.</span>
        ) : status ? (
          <span class={status.ok ? 'status-ok' : 'status-bad'}>{status.text}</span>
        ) : (
          <span class="muted">
            {field.help}:{' '}
            <a href={field.url} target="_blank" rel="noopener noreferrer">
              {new URL(field.url).hostname}
            </a>
          </span>
        )}
      </span>
    </div>
  );
}

function ExtensionsField({ value, onSave }: { value: string[]; onSave: (list: string[]) => void }) {
  const joined = value.join(', ');
  const [draft, setDraft] = useState(joined);
  useSyncedDraft(joined, setDraft);
  return (
    <div class="field">
      <label for="risky">Risky file types (comma separated)</label>
      <textarea id="risky" rows={3} value={draft} onInput={(e) => setDraft((e.target as HTMLTextAreaElement).value)} onBlur={() => onSave(parseExtensionList(draft))} />
    </div>
  );
}

/**
 * Copy a saved value into an edit field only when the saved value really
 * changes (e.g. edited in another tab). Effects run after render, so an
 * unconditional sync would overwrite text typed right after the page opens.
 */
function useSyncedDraft(value: string, setDraft: (v: string) => void) {
  const last = useRef(value);
  useEffect(() => {
    if (last.current !== value) {
      last.current = value;
      setDraft(value);
    }
  }, [value, setDraft]);
}

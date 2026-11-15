import { useEffect, useRef, useState } from 'preact/hooks';
import { MAX_BATCH_SIZE } from '../../lib/constants';
import type { ParseResult } from '../../lib/types';
import type { LookupClient, ViewState } from '../client';
import { iocKey } from '../../background/engine';
import { InfoRow, IocRow, SkippedRow } from './ResultRow';
import type { CardActions } from './SourceCard';

export function LookupView({
  client,
  state,
  now,
  onOpenSettings,
  autoFocus = true,
}: {
  client: LookupClient;
  state: ViewState;
  now: number;
  onOpenSettings: () => void;
  autoFocus?: boolean;
}) {
  const [text, setText] = useState('');
  const input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    if (autoFocus) input.current?.focus();
  }, [autoFocus]);

  const submit = () => {
    if (text.trim() === '') return;
    client.send({ type: 'lookup', text, origin: 'popup' });
  };

  const actions: CardActions = {
    onRefresh: (r) => client.send({ type: 'refresh', ioc: r.ioc, source: r.source }),
    onOpenSettings,
  };

  const iocItems = state.items.filter((i): i is Extract<ParseResult, { kind: 'ioc' }> => i.kind === 'ioc');
  const skipped = state.items.filter((i): i is Extract<ParseResult, { kind: 'skipped' }> => i.kind === 'skipped');
  const single = iocItems.length === 1;

  return (
    <div>
      <form
        class="lookup-form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label class="sr-only" for="lookup-input">
          IOCs to check
        </label>
        <textarea
          id="lookup-input"
          ref={input}
          class="lookup-input"
          rows={1}
          placeholder="URL, domain, IP or hash"
          value={text}
          onInput={(e) => setText((e.target as HTMLTextAreaElement).value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
        />
        <button type="submit" class="btn primary" disabled={text.trim() === ''}>
          Check
        </button>
      </form>
      <p class="hint muted small">Defanged input is fine · Enter to check · Shift+Enter for a new line · up to {MAX_BATCH_SIZE} at once</p>

      {!state.connected && <div class="banner info">Connecting to CyberBud…</div>}
      {state.error && (
        <div class="banner" role="alert">
          {state.error}
        </div>
      )}

      {state.items.length > 0 && (
        <ul class="results" aria-label="Results">
          {state.items.map((item) => {
            if (item.kind === 'ioc') {
              const report = state.reports[iocKey(item.ioc)];
              return (
                <IocRow
                  key={`ioc|${iocKey(item.ioc)}`}
                  item={item}
                  {...(report && { report })}
                  now={now}
                  actions={actions}
                  defaultOpen={single}
                  showDefanged={false}
                />
              );
            }
            if (item.kind === 'skipped') return null;
            return <InfoRow key={`${item.kind}|${item.raw}`} item={item} />;
          })}
          {skipped.length > 0 && <SkippedRow items={skipped} limit={MAX_BATCH_SIZE} />}
        </ul>
      )}
    </div>
  );
}

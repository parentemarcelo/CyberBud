import type { SourceResult } from '../../lib/types';
import { SOURCE_NAME, relativeTime, safeHref, statusText } from '../format';
import { VerdictChip } from './Bits';

export interface CardActions {
  onRefresh: (r: SourceResult) => void;
  onOpenSettings: () => void;
}

/** One source's result for an IOC, in every state from SPEC §7. */
export function SourceCard({ r, now, actions }: { r: SourceResult; now: number; actions: CardActions }) {
  const href = safeHref(r.link);
  const answered = r.status === 'ok' || r.status === 'not_found';
  const busy = r.status === 'loading' || r.status === 'queued';
  const name = SOURCE_NAME[r.source];

  return (
    <article class="card" data-status={r.status} aria-label={`${name}: ${statusText(r, now)}`}>
      <div class="card-head">
        <span class="card-name">{name}</span>
        {answered && <VerdictChip verdict={r.status === 'not_found' ? 'unknown' : r.verdict} />}
        <span class={`card-status ${answered ? '' : 'muted'}`} role={r.status === 'error' ? 'alert' : undefined}>
          {statusText(r, now)}
        </span>
      </div>

      {r.status === 'ok' && r.details.length > 0 && (
        <details>
          <summary>Details</summary>
          <dl class="details">
            {r.details.map(([label, value]) => (
              <>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </>
            ))}
          </dl>
        </details>
      )}

      <div class="card-foot">
        {href && (
          <a href={href} target="_blank" rel="noopener noreferrer">
            Open in {name} ↗
          </a>
        )}
        {r.fromCache && r.fetchedAt !== undefined && <span class="muted">cached {relativeTime(r.fetchedAt, now)}</span>}
        {r.status === 'no_key' && (
          <button type="button" class="btn link" onClick={actions.onOpenSettings}>
            Add key in Settings
          </button>
        )}
        {r.status === 'error' && r.error === 'Invalid or unauthorized key' && (
          <button type="button" class="btn link" onClick={actions.onOpenSettings}>
            Check key in Settings
          </button>
        )}
        {r.status === 'disabled' && (
          <button type="button" class="btn link" onClick={actions.onOpenSettings}>
            Settings
          </button>
        )}
        {!busy && r.status !== 'no_key' && r.status !== 'disabled' && (
          <button type="button" class="btn link" onClick={() => actions.onRefresh(r)}>
            {r.status === 'error' || r.status === 'rate_limited' ? 'Retry' : 'Refresh'}
          </button>
        )}
      </div>
    </article>
  );
}

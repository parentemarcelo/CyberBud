import { useState } from 'preact/hooks';
import type { IocReport, ParseResult } from '../../lib/types';
import { summaryText } from '../../lib/verdict';
import { defang } from '../format';
import { CopyButton, TypeBadge, VerdictChip } from './Bits';
import { SourceCard, type CardActions } from './SourceCard';

/** A looked-up IOC: header with summary, expandable source cards. */
export function IocRow({
  item,
  report,
  now,
  actions,
  defaultOpen,
  showDefanged,
}: {
  item: Extract<ParseResult, { kind: 'ioc' }>;
  report?: IocReport;
  now: number;
  actions: CardActions;
  defaultOpen: boolean;
  showDefanged: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const { ioc } = item;
  const shown = showDefanged ? defang(ioc.value) : ioc.value;
  const summary = report?.summary;
  const bodyId = `row-${ioc.type}-${ioc.value}`;

  return (
    <li class="row" data-verdict={summary?.verdict ?? 'pending'}>
      <div class="row-head">
        <TypeBadge type={ioc.type} />
        <span class="row-value mono" title={ioc.raw !== ioc.value ? `You entered: ${ioc.raw}` : undefined}>
          {shown}
        </span>
        <span class="row-actions">
          <CopyButton text={ioc.value} />
          <button
            type="button"
            class="btn icon"
            aria-expanded={open}
            aria-controls={bodyId}
            aria-label={open ? 'Hide sources' : 'Show sources'}
            onClick={() => setOpen(!open)}
          >
            {open ? '▾' : '▸'}
          </button>
        </span>
        <span class="row-meta">
          {summary && (summary.pending === 0 || summary.total > 0) && <VerdictChip verdict={summary.verdict} />}
          <span class="muted small" aria-live="polite">
            {summary ? summaryText(summary) : 'Checking…'}
          </span>
        </span>
      </div>
      {open && (
        <div class="row-body" id={bodyId}>
          {report && report.results.length > 0 ? (
            report.results.map((r) => <SourceCard key={r.source} r={r} now={now} actions={actions} />)
          ) : (
            <span class="muted">{report ? 'No source supports this type.' : 'Checking…'}</span>
          )}
        </div>
      )}
    </li>
  );
}

/** Private / unsupported input: shown, never looked up. */
export function InfoRow({ item }: { item: Extract<ParseResult, { kind: 'private' | 'unsupported' }> }) {
  const text = item.kind === 'private' ? 'Private/reserved, not looked up' : 'Unsupported input';
  return (
    <li class="row dim" data-kind={item.kind}>
      <div class="row-head">
        <span class="badge">{item.kind === 'private' ? 'Private' : '—'}</span>
        <span class="row-value mono">{item.kind === 'private' ? item.value : item.raw}</span>
        <span />
        <span class="row-meta muted small">{text}</span>
      </div>
    </li>
  );
}

/** Everything over the batch limit, collapsed into one row. */
export function SkippedRow({ items, limit }: { items: Array<Extract<ParseResult, { kind: 'skipped' }>>; limit: number }) {
  return (
    <li class="row dim" data-kind="skipped">
      <details class="row-head" style="display:block">
        <summary>
          {items.length} more skipped (limit {limit} per lookup)
        </summary>
        <p class="mono small muted">{items.slice(0, 200).map((i) => i.raw).join(' ')}{items.length > 200 ? ' …' : ''}</p>
      </details>
    </li>
  );
}

import { useState } from 'preact/hooks';
import type { IocType, Verdict } from '../../lib/types';
import { TYPE_LABEL, VERDICT_ICON, VERDICT_LABEL } from '../format';

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  return (
    <span class={`chip ${verdict}`}>
      <span aria-hidden="true">{VERDICT_ICON[verdict]}</span>
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function TypeBadge({ type }: { type: IocType }) {
  return <span class="badge">{TYPE_LABEL[type]}</span>;
}

/** Copies `text`; shows "Copied" briefly. */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      class="btn icon"
      title={`${label}: ${text}`}
      aria-label={`${label} ${text}`}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(
          () => {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          },
          () => undefined,
        );
      }}
    >
      {done ? '✓' : '⧉'}
    </button>
  );
}

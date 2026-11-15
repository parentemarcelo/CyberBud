// Check file tab (docs/SPEC.md F4). The file is hashed locally; only the
// SHA-256 goes to the sources. Shown only in the full-page tab: Firefox
// closes the popup when a file picker opens or focus moves to a file manager.
import { useEffect, useRef, useState } from 'preact/hooks';
import { basename } from '../../lib/files';
import { FileTooLargeError, hashFile, type FileHashes } from '../../lib/hash';
import { bytes } from '../../lib/sources/common';
import { iocKey } from '../../background/engine';
import { MAX_FILE_SIZE_BYTES } from '../../lib/constants';
import type { LookupClient, ViewState } from '../client';
import { CopyButton } from './Bits';
import { IocRow } from './ResultRow';
import type { CardActions } from './SourceCard';

/** The download that the notification was about (from ?download=<id>). */
export interface DownloadContext {
  id: number;
  name: string;
  /** Bytes, or undefined when Firefox doesn't know. */
  size?: number;
}

type Phase =
  | { kind: 'idle' }
  | { kind: 'hashing'; name: string; size: number }
  | { kind: 'done'; name: string; hashes: FileHashes }
  | { kind: 'error'; message: string };

export function FileView({
  client,
  state,
  now,
  onOpenSettings,
  downloadId,
}: {
  client: LookupClient;
  state: ViewState;
  now: number;
  onOpenSettings: () => void;
  downloadId?: number;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const [download, setDownload] = useState<DownloadContext | null>(null);
  const [dragging, setDragging] = useState(false);
  const [pasted, setPasted] = useState('');
  const picker = useRef<HTMLInputElement>(null);

  // Load the download's name and size for the "Show in folder" and mismatch check.
  useEffect(() => {
    if (downloadId === undefined) return;
    void browser.downloads.search({ id: downloadId }).then(
      ([item]) => {
        if (!item) return;
        const size = item.fileSize >= 0 ? item.fileSize : item.totalBytes >= 0 ? item.totalBytes : undefined;
        setDownload({ id: downloadId, name: basename(item.filename), ...(size !== undefined && { size }) });
      },
      () => undefined,
    );
  }, [downloadId]);

  // A file dropped outside the zone would make Firefox navigate to it.
  useEffect(() => {
    const block = (e: DragEvent) => e.preventDefault();
    window.addEventListener('dragover', block);
    window.addEventListener('drop', block);
    return () => {
      window.removeEventListener('dragover', block);
      window.removeEventListener('drop', block);
    };
  }, []);

  const check = async (files: FileList | null | undefined) => {
    const file = files?.[0];
    if (!file) return;
    setPhase({ kind: 'hashing', name: file.name, size: file.size });
    try {
      const hashes = await hashFile(file);
      setPhase({ kind: 'done', name: file.name, hashes });
      client.send({ type: 'lookupHash', sha256: hashes.sha256, origin: 'file' });
    } catch (err) {
      setPhase({
        kind: 'error',
        message: err instanceof FileTooLargeError ? `${err.message} (limit ${bytes(MAX_FILE_SIZE_BYTES)}). Paste its hash below instead.` : 'Could not read the file.',
      });
    }
  };

  const actions: CardActions = {
    onRefresh: (r) => client.send({ type: 'refresh', ioc: r.ioc, source: r.source }),
    onOpenSettings,
  };

  const done = phase.kind === 'done' ? phase : null;
  const mismatch =
    done && download && (done.name !== download.name || (download.size !== undefined && done.hashes.size !== download.size));
  const resultItem = state.items.length === 1 && state.items[0]?.kind === 'ioc' ? state.items[0] : null;
  const showResult = resultItem && (done ? resultItem.ioc.value === done.hashes.sha256 : true) && phase.kind !== 'hashing';

  return (
    <div class="file-view">
      {download && (
        <div class="notice">
          <div>
            Downloaded: <strong class="mono">{download.name}</strong>
            {download.size !== undefined && <span class="muted"> ({bytes(download.size)})</span>}
          </div>
          <div class="field-row small">
            <button type="button" class="btn" onClick={() => void browser.downloads.show(download.id)}>
              Show in folder
            </button>
            <span class="muted">then drag the file here.</span>
          </div>
        </div>
      )}

      <div
        class={`dropzone ${dragging ? 'over' : ''}`}
        role="button"
        tabIndex={0}
        aria-label="Choose a file to check, or drop it here"
        onClick={() => picker.current?.click()}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            picker.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          void check(e.dataTransfer?.files);
        }}
      >
        <strong>Drop a file here</strong> or <span class="btn link">choose a file</span>
        <div class="muted small">The file never leaves your browser. Only its SHA-256 is looked up.</div>
      </div>
      <input
        ref={picker}
        type="file"
        class="sr-only"
        tabIndex={-1}
        aria-hidden="true"
        onChange={(e) => void check((e.target as HTMLInputElement).files)}
      />

      {phase.kind === 'hashing' && (
        <p role="status">
          Hashing <span class="mono">{phase.name}</span> ({bytes(phase.size)})…
        </p>
      )}
      {phase.kind === 'error' && (
        <div class="banner" role="alert">
          {phase.message}
        </div>
      )}
      {done && (
        <dl class="details hashes">
          <dt>File</dt>
          <dd class="mono">
            {done.name} <span class="muted">({bytes(done.hashes.size)})</span>
          </dd>
          <dt>SHA-256</dt>
          <dd class="mono">
            {done.hashes.sha256} <CopyButton text={done.hashes.sha256} />
          </dd>
          <dt>SHA-1</dt>
          <dd class="mono">
            {done.hashes.sha1} <CopyButton text={done.hashes.sha1} />
          </dd>
        </dl>
      )}
      {mismatch && download && (
        <div class="banner" role="alert">
          This doesn't look like <span class="mono">{download.name}</span>
          {done.name !== download.name ? ' (different name' : ' (different size'}
          {done.name !== download.name && download.size !== undefined && done.hashes.size !== download.size ? ' and size)' : ')'}. Check
          that you dropped the right file.
        </div>
      )}

      {showResult && resultItem && (
        <ul class="results" aria-label="Results">
          <IocRow
            key={iocKey(resultItem.ioc)}
            item={resultItem}
            {...(state.reports[iocKey(resultItem.ioc)] && { report: state.reports[iocKey(resultItem.ioc)] })}
            now={now}
            actions={actions}
            defaultOpen
            showDefanged={false}
          />
        </ul>
      )}

      <form
        class="lookup-form paste-hash"
        onSubmit={(e) => {
          e.preventDefault();
          if (pasted.trim()) client.send({ type: 'lookup', text: pasted, origin: 'file' });
          setPhase({ kind: 'idle' });
        }}
      >
        <label class="sr-only" for="paste-hash">
          Or paste a hash
        </label>
        <input
          id="paste-hash"
          class="lookup-input"
          type="text"
          placeholder="Or paste an MD5, SHA-1 or SHA-256"
          value={pasted}
          onInput={(e) => setPasted((e.target as HTMLInputElement).value)}
        />
        <button type="submit" class="btn" disabled={pasted.trim() === ''}>
          Check hash
        </button>
      </form>
    </div>
  );
}

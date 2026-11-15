// UI <-> background port protocol (docs/SPEC.md §8, PLAN step 20).
// The UI connects with runtime.connect({ name: PORT_NAME }); the background
// sends the current state, then streams every engine update. Incoming
// messages are validated strictly: they decide what is sent to third parties.
import { MAX_INPUT_CHARS } from '../lib/constants';
import { parseInput } from '../lib/ioc/parse';
import {
  LOOKUP_ORIGINS,
  SOURCE_IDS,
  type Ioc,
  type LookupOrigin,
  type RequestMessage,
  type ResponseMessage,
  type SourceId,
} from '../lib/types';
import type { Engine } from './engine';

export const PORT_NAME = 'cyberbud-ui';

/** The subset of runtime.Port used here (lets tests use a fake port). */
export interface PortLike {
  name: string;
  sender?: { id?: string };
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(cb: (message: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
}

/**
 * Wire a UI port to the engine. Listeners are attached synchronously so no
 * early message is lost while the engine is still restoring.
 * Returns false (and disconnects) for ports that are not ours.
 */
export function attachPort(port: PortLike, engine: Promise<Engine>, extensionId: string): boolean {
  if (port.name !== PORT_NAME || port.sender?.id !== extensionId) {
    port.disconnect();
    return false;
  }

  let open = true;
  let unsubscribe: (() => void) | undefined;
  const post = (msg: ResponseMessage) => {
    if (!open) return;
    try {
      port.postMessage(msg);
    } catch {
      close();
    }
  };
  const close = () => {
    open = false;
    unsubscribe?.();
  };

  port.onDisconnect.addListener(close);
  port.onMessage.addListener((raw) => {
    void handle(raw);
  });

  void engine.then((e) => {
    if (!open) return;
    unsubscribe = e.subscribe(post);
    post({ type: 'state', ...e.getState() });
  });

  async function handle(raw: unknown) {
    const msg = validateRequest(raw);
    if (!msg) return post({ type: 'error', message: 'Invalid request' });
    const e = await engine;
    try {
      switch (msg.type) {
        case 'lookup':
          await e.lookup(msg.text, msg.origin);
          break;
        case 'lookupHash':
          await e.lookupHash(msg.sha256);
          break;
        case 'refresh':
          await e.refresh(msg.ioc, msg.source);
          break;
        case 'getState':
          post({ type: 'state', ...e.getState() });
          break;
      }
    } catch {
      post({ type: 'error', message: 'Lookup failed' });
    }
  }
  return true;
}

/** Strict validation of a UI request; returns null when anything is off. */
export function validateRequest(raw: unknown): RequestMessage | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const m = raw as Record<string, unknown>;
  switch (m.type) {
    case 'lookup':
      if (typeof m.text !== 'string' || m.text.length > MAX_INPUT_CHARS) return null;
      if (!(LOOKUP_ORIGINS as readonly unknown[]).includes(m.origin)) return null;
      return { type: 'lookup', text: m.text, origin: m.origin as LookupOrigin };
    case 'lookupHash':
      return typeof m.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(m.sha256) ? { type: 'lookupHash', sha256: m.sha256, origin: 'file' } : null;
    case 'refresh': {
      if (m.source !== undefined && !(SOURCE_IDS as readonly unknown[]).includes(m.source)) return null;
      const ioc = validIoc(m.ioc);
      if (!ioc) return null;
      return { type: 'refresh', ioc, ...(m.source !== undefined && { source: m.source as SourceId }) };
    }
    case 'getState':
      return { type: 'getState' };
    default:
      return null;
  }
}

/**
 * An IOC from the UI is only accepted if re-parsing its value yields exactly
 * the same single public IOC, so a crafted message can't send arbitrary or
 * private values to the APIs.
 */
function validIoc(x: unknown): Ioc | null {
  if (typeof x !== 'object' || x === null) return null;
  const { value, type, raw } = x as Record<string, unknown>;
  if (typeof value !== 'string' || typeof type !== 'string' || value.length > 4096) return null;
  const parsed = parseInput(value, 'full');
  const only = parsed.length === 1 ? parsed[0] : undefined;
  if (only?.kind !== 'ioc' || only.ioc.type !== type || only.ioc.value !== value) return null;
  return { raw: typeof raw === 'string' ? raw.slice(0, 4096) : value, value, type: only.ioc.type };
}

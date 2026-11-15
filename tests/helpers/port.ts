import { LookupClient } from '../../src/ui/client';
import type { RequestMessage, ResponseMessage } from '../../src/lib/types';

/** A LookupClient wired to an in-memory port. `push` delivers background messages. */
export function fakeClient() {
  const sent: RequestMessage[] = [];
  const messageCbs: Array<(m: unknown) => void> = [];
  const disconnectCbs: Array<() => void> = [];
  let connects = 0;
  const client = new LookupClient(() => {
    connects++;
    return {
      name: 'cyberbud-ui',
      postMessage: (m: unknown) => sent.push(m as RequestMessage),
      disconnect: () => undefined,
      onMessage: { addListener: (cb: (m: unknown) => void) => messageCbs.push(cb) },
      onDisconnect: { addListener: (cb: () => void) => disconnectCbs.push(cb) },
    } as unknown as Browser.runtime.Port;
  });
  return {
    client,
    sent,
    connects: () => connects,
    push: (m: ResponseMessage) => messageCbs.forEach((cb) => cb(m)),
    drop: () => disconnectCbs.splice(0).forEach((cb) => cb()),
  };
}

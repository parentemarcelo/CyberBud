import { describe, expect, it, vi } from 'vitest';
import { PORT_NAME, attachPort, validateRequest, type PortLike } from '../../src/background/messaging';
import type { ResponseMessage } from '../../src/lib/types';
import { fakeAdapter, makeEngine } from '../helpers/engine';

const EXT_ID = 'test-extension-id';

/** In-memory runtime.Port. */
function fakePort(opts: { name?: string; id?: string } = {}) {
  const sent: ResponseMessage[] = [];
  const onMessage: Array<(m: unknown) => void> = [];
  const onDisconnect: Array<() => void> = [];
  const port: PortLike & { disconnected: boolean } = {
    name: opts.name ?? PORT_NAME,
    sender: { id: opts.id ?? EXT_ID },
    disconnected: false,
    postMessage: (m) => {
      if (port.disconnected) throw new Error('Attempt to postMessage on disconnected port');
      sent.push(structuredClone(m) as ResponseMessage);
    },
    disconnect: () => {
      port.disconnected = true;
    },
    onMessage: { addListener: (cb) => onMessage.push(cb) },
    onDisconnect: { addListener: (cb) => onDisconnect.push(cb) },
  };
  return {
    port,
    sent,
    send: (m: unknown) => onMessage.forEach((cb) => cb(m)),
    close: () => {
      port.disconnected = true;
      onDisconnect.forEach((cb) => cb());
    },
  };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe('connection', () => {
  it('sends the current state on connect', async () => {
    const h = await makeEngine([fakeAdapter('virustotal').adapter]);
    await h.engine.lookup('evil.example', 'popup');
    const p = fakePort();
    expect(attachPort(p.port, Promise.resolve(h.engine), EXT_ID)).toBe(true);
    await settle();
    expect(p.sent[0]).toMatchObject({ type: 'state', items: [{ kind: 'ioc' }], reports: [{ ioc: { value: 'evil.example' } }] });
  });

  it.each([
    ['another extension', { id: 'other-extension' }],
    ['a different port name', { name: 'something-else' }],
    ['no sender id', { id: '' }],
  ])('rejects %s', async (_l, opts) => {
    const h = await makeEngine([fakeAdapter('virustotal').adapter]);
    const p = fakePort(opts);
    expect(attachPort(p.port, Promise.resolve(h.engine), EXT_ID)).toBe(false);
    expect(p.port.disconnected).toBe(true);
    p.send({ type: 'lookup', text: 'evil.example', origin: 'popup' });
    await settle();
    expect(p.sent).toEqual([]);
  });

  it('does not lose a message sent before the engine is ready', async () => {
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    let resolve!: (e: typeof h.engine) => void;
    const p = fakePort();
    attachPort(p.port, new Promise((r) => (resolve = r)), EXT_ID);
    p.send({ type: 'lookup', text: 'evil.example', origin: 'popup' });
    resolve(h.engine);
    await vi.waitFor(() => expect(vt.lookup).toHaveBeenCalledTimes(1));
  });
});

describe('requests', () => {
  it('lookup → parsed + report updates', async () => {
    const h = await makeEngine([fakeAdapter('virustotal').adapter]);
    const p = fakePort();
    attachPort(p.port, Promise.resolve(h.engine), EXT_ID);
    p.send({ type: 'lookup', text: 'evil[.]example', origin: 'popup' });
    await vi.waitFor(() =>
      expect(p.sent.some((m) => m.type === 'report' && m.report.summary.pending === 0)).toBe(true),
    );
    expect(p.sent.map((m) => m.type)).toEqual(['state', 'parsed', 'report', 'report']);
  });

  it('lookupHash and refresh reach the engine', async () => {
    const mb = fakeAdapter('malwarebazaar');
    const h = await makeEngine([mb.adapter]);
    const p = fakePort();
    attachPort(p.port, Promise.resolve(h.engine), EXT_ID);
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    p.send({ type: 'lookupHash', sha256: sha });
    await vi.waitFor(() => expect(mb.lookup).toHaveBeenCalledTimes(1));
    p.send({ type: 'refresh', ioc: { raw: sha, value: sha, type: 'sha256' }, source: 'malwarebazaar' });
    await vi.waitFor(() => expect(mb.lookup).toHaveBeenCalledTimes(2));
  });

  it('getState answers with state', async () => {
    const h = await makeEngine([fakeAdapter('virustotal').adapter]);
    const p = fakePort();
    attachPort(p.port, Promise.resolve(h.engine), EXT_ID);
    await settle();
    p.send({ type: 'getState' });
    await settle();
    expect(p.sent.filter((m) => m.type === 'state')).toHaveLength(2);
  });

  it('invalid requests get an error and never reach an adapter', async () => {
    const vt = fakeAdapter('virustotal');
    const h = await makeEngine([vt.adapter]);
    const p = fakePort();
    attachPort(p.port, Promise.resolve(h.engine), EXT_ID);
    p.send({ type: 'refresh', ioc: { value: '10.0.0.1', type: 'ipv4' } });
    p.send('lookup evil.example');
    await settle();
    expect(p.sent.filter((m) => m.type === 'error')).toEqual([
      { type: 'error', message: 'Invalid request' },
      { type: 'error', message: 'Invalid request' },
    ]);
    expect(vt.lookup).not.toHaveBeenCalled();
  });
});

describe('disconnect', () => {
  it('stops sending after the popup closes, and the lookup still completes', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const vt = fakeAdapter('virustotal', async (ioc) => {
      await gate;
      return { source: 'virustotal', ioc, status: 'ok', verdict: 'clean', headline: '', details: [] };
    });
    const h = await makeEngine([vt.adapter]);
    const p = fakePort();
    attachPort(p.port, Promise.resolve(h.engine), EXT_ID);
    p.send({ type: 'lookup', text: 'evil.example', origin: 'popup' });
    await vi.waitFor(() => expect(vt.lookup).toHaveBeenCalled());
    const before = p.sent.length;
    p.close();
    release();
    await vi.waitFor(() => expect(h.engine.getReport({ type: 'domain', value: 'evil.example' })?.summary.pending).toBe(0));
    expect(p.sent.length).toBe(before);

    // Reopening the popup shows the completed result.
    const p2 = fakePort();
    attachPort(p2.port, Promise.resolve(h.engine), EXT_ID);
    await settle();
    expect(p2.sent[0]).toMatchObject({ type: 'state', reports: [{ results: [{ status: 'ok' }] }] });
  });
});

describe('validateRequest', () => {
  const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  it.each([
    [{ type: 'lookup', text: 'x', origin: 'popup' }, true],
    [{ type: 'lookup', text: 'x', origin: 'context_menu' }, true],
    [{ type: 'lookup', text: 'x', origin: 'evil' }, false],
    [{ type: 'lookup', text: 42, origin: 'popup' }, false],
    [{ type: 'lookup', text: 'x'.repeat(200_001), origin: 'popup' }, false],
    [{ type: 'lookupHash', sha256: sha }, true],
    [{ type: 'lookupHash', sha256: 'abc' }, false],
    [{ type: 'refresh', ioc: { raw: 'r', value: 'evil.example', type: 'domain' } }, true],
    [{ type: 'refresh', ioc: { value: 'evil.example', type: 'domain' }, source: 'virustotal' }, true],
    [{ type: 'refresh', ioc: { value: 'evil.example', type: 'domain' }, source: 'shodan' }, false],
    [{ type: 'refresh', ioc: { value: 'EVIL.example', type: 'domain' } }, false],
    [{ type: 'refresh', ioc: { value: 'evil.example', type: 'url' } }, false],
    [{ type: 'refresh', ioc: { value: 'evil.example other.example', type: 'domain' } }, false],
    [{ type: 'refresh', ioc: { value: 'http://localhost/x', type: 'url' } }, false],
    [{ type: 'refresh', ioc: { value: 'https://evil.example/p?token=1', type: 'url' } }, true],
    [{ type: 'getState' }, true],
    [{ type: 'deleteEverything' }, false],
    [null, false],
    [[], false],
  ])('%j → %s', (msg, ok) => {
    expect(validateRequest(msg) !== null).toBe(ok);
  });

  it('lookupHash always has origin "file"', () => {
    expect(validateRequest({ type: 'lookupHash', sha256: sha, origin: 'popup' })).toEqual({ type: 'lookupHash', sha256: sha, origin: 'file' });
  });
});

// Port client for extension pages: connects to the background, keeps the
// current view in sync, and reconnects if the background restarts.
import { PORT_NAME } from '../background/messaging';
import type { IocReport, ParseResult, RequestMessage, ResponseMessage } from '../lib/types';
import { iocKey } from '../background/engine';

export interface ViewState {
  items: ParseResult[];
  /** Reports by iocKey. */
  reports: Record<string, IocReport>;
  connected: boolean;
  error?: string;
}

type Listener = (state: ViewState) => void;

const MAX_RETRIES = 5;
export const UNREACHABLE =
  "Can't reach CyberBud's background. Close and reopen this window; if it keeps happening, reload CyberBud in about:addons.";
type MessageListener = (msg: ResponseMessage) => void;

export interface PortFactory {
  (): Browser.runtime.Port;
}

export class LookupClient {
  state: ViewState = { items: [], reports: {}, connected: false };
  private port: Browser.runtime.Port | undefined;
  private readonly listeners = new Set<Listener>();
  private readonly messageListeners = new Set<MessageListener>();
  private outbox: RequestMessage[] = [];
  private closed = false;
  private retries = 0;

  constructor(private readonly connectPort: PortFactory = () => browser.runtime.connect({ name: PORT_NAME })) {}

  connect(): this {
    this.closed = false;
    const port = this.connectPort();
    this.port = port;
    port.onMessage.addListener((m: unknown) => this.receive(m as ResponseMessage));
    port.onDisconnect.addListener(() => {
      this.port = undefined;
      this.set({ connected: false });
      // The event page may have been restarted: reconnect a few times.
      if (!this.closed && this.retries < MAX_RETRIES) {
        this.retries++;
        setTimeout(() => this.connect(), 300 * this.retries);
      } else if (!this.closed) {
        this.set({ error: UNREACHABLE });
      }
    });
    for (const m of this.outbox.splice(0)) port.postMessage(m);
    return this;
  }

  close() {
    this.closed = true;
    this.port?.disconnect();
    this.port = undefined;
  }

  send(msg: RequestMessage) {
    if (this.port) this.port.postMessage(msg);
    else this.outbox.push(msg);
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onMessage(listener: MessageListener): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  /** Reports for the current items, in order. */
  currentReports(): Array<{ item: ParseResult; report?: IocReport }> {
    return this.state.items.map((item) => ({
      item,
      ...(item.kind === 'ioc' && this.state.reports[iocKey(item.ioc)] && { report: this.state.reports[iocKey(item.ioc)] }),
    }));
  }

  private receive(msg: ResponseMessage) {
    this.retries = 0;
    switch (msg.type) {
      case 'state': {
        const reports: Record<string, IocReport> = {};
        for (const r of msg.reports) reports[iocKey(r.ioc)] = r;
        this.set({ items: msg.items, reports, connected: true, error: undefined });
        break;
      }
      case 'parsed':
        this.set({ items: msg.items, connected: true, error: undefined });
        break;
      case 'report':
        this.set({ reports: { ...this.state.reports, [iocKey(msg.report.ioc)]: msg.report }, connected: true });
        break;
      case 'error':
        this.set({ error: msg.message });
        break;
      default:
        break;
    }
    for (const l of this.messageListeners) l(msg);
  }

  private set(patch: Partial<ViewState>) {
    const next = { ...this.state, ...patch };
    if (patch.error === undefined && 'error' in patch) delete next.error;
    this.state = next;
    for (const l of this.listeners) l(this.state);
  }
}

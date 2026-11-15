// Lookup orchestrator (docs/SPEC.md F6, PLAN step 19).
// Parses input, serves from cache, applies rate limits, runs adapters
// concurrently per IOC, streams IocReport updates, and writes cache and
// history. Queue, limiter and current reports are persisted to
// storage.session so a suspended event page or a reopened popup can resume.
// API keys are never persisted: queued jobs read them from settings when they run.
import { getCached, invalidate, putCached, ttlMs } from '../lib/cache';
import { MAX_REQUEST_ATTEMPTS } from '../lib/constants';
import { addHistory } from '../lib/history';
import { parseInput } from '../lib/ioc/parse';
import { RateLimiter, RequestQueue, WINDOW_MS, type RateLimiterState, type RequestQueueState } from '../lib/ratelimit';
import { getSettings, type Settings } from '../lib/settings';
import { errorResult, result } from '../lib/sources/common';
import { adaptersFor as defaultAdaptersFor } from '../lib/sources/registry';
import {
  SOURCE_IDS,
  type Ioc,
  type IocReport,
  type LookupOrigin,
  type ParseResult,
  type ResponseMessage,
  type SourceAdapter,
  type SourceId,
  type SourceResult,
} from '../lib/types';
import { summarize } from '../lib/verdict';

export const SESSION_KEY = 'engine';
export const DRAIN_ALARM = 'cyberbud-drain';
/** Reports kept for reopening the popup (current view and running reports are always kept). */
export const MAX_REPORTS = 100;

interface JobPayload {
  ioc: Ioc;
  origin: LookupOrigin;
  attempt: number;
}

export interface EngineState {
  v: 1;
  queue: RequestQueueState<JobPayload>;
  limiter: RateLimiterState;
  reports: IocReport[];
  items: ParseResult[];
}

export interface EngineDeps {
  getSettings: () => Promise<Settings>;
  adaptersFor: typeof defaultAdaptersFor;
  now: () => number;
  loadState: () => Promise<unknown>;
  saveState: (state: EngineState) => Promise<void>;
  /** Backup wake-up for when the event page is suspended (alarms). null clears it. */
  scheduleAlarm: (at: number | null) => Promise<void>;
}

export function defaultDeps(): EngineDeps {
  return {
    getSettings,
    adaptersFor: defaultAdaptersFor,
    now: () => Date.now(),
    loadState: async () => (await browser.storage.session.get(SESSION_KEY))[SESSION_KEY],
    saveState: (state) => browser.storage.session.set({ [SESSION_KEY]: state }),
    scheduleAlarm: async (at) => {
      if (at === null) await browser.alarms.clear(DRAIN_ALARM);
      else await browser.alarms.create(DRAIN_ALARM, { when: at });
    },
  };
}

export const iocKey = (ioc: Pick<Ioc, 'type' | 'value'>) => `${ioc.type}|${ioc.value}`;

type Listener = (msg: ResponseMessage) => void;

export class Engine {
  private reports = new Map<string, IocReport>();
  private items: ParseResult[] = [];
  private queue = new RequestQueue<JobPayload>();
  private limiter = new RateLimiter();
  private readonly listeners = new Set<Listener>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private saving: Promise<void> = Promise.resolve();
  /** Running drain, so concurrent wake-ups don't overlap. */
  private draining: Promise<void> | null = null;

  private constructor(private readonly deps: EngineDeps) {}

  /** Create an engine, restoring any persisted session state. */
  static async create(deps: EngineDeps = defaultDeps()): Promise<Engine> {
    const engine = new Engine(deps);
    await engine.restore(await deps.loadState());
    return engine;
  }

  // ---------- public API ----------

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Current view: last parsed items and their reports. */
  getState(): { items: ParseResult[]; reports: IocReport[] } {
    const reports = this.items.flatMap((i) => {
      const r = i.kind === 'ioc' ? this.reports.get(iocKey(i.ioc)) : undefined;
      return r ? [r] : [];
    });
    return { items: this.items, reports };
  }

  getReport(ioc: Pick<Ioc, 'type' | 'value'>): IocReport | undefined {
    return this.reports.get(iocKey(ioc));
  }

  /** Parse `text` and look up every IOC in it. Resolves when all non-queued requests have finished. */
  async lookup(text: string, origin: LookupOrigin): Promise<ParseResult[]> {
    const settings = await this.deps.getSettings();
    const items = parseInput(text, settings.urlMode);
    this.setItems(items);
    await Promise.all(items.map((i) => (i.kind === 'ioc' ? this.runIoc(i.ioc, origin, settings, {}) : undefined)));
    this.afterChange();
    return items;
  }

  /** Look up a file hash computed in the browser (SPEC F4). */
  async lookupHash(sha256: string): Promise<void> {
    const value = sha256.toLowerCase();
    const ioc: Ioc = { raw: value, value, type: 'sha256' };
    const settings = await this.deps.getSettings();
    this.setItems([{ kind: 'ioc', ioc }]);
    await this.runIoc(ioc, 'file', settings, {});
    this.afterChange();
  }

  /** Re-query one source (or all) for an IOC, bypassing the cache. */
  async refresh(ioc: Ioc, source?: SourceId): Promise<void> {
    const settings = await this.deps.getSettings();
    await this.runIoc(ioc, 'popup', settings, { bypassCache: true, ...(source && { only: source }) });
    this.afterChange();
  }

  /** Run every queued job that the rate limiter now allows. */
  drain(): Promise<void> {
    if (this.draining) return this.draining;
    this.draining = this.drainOnce().finally(() => {
      this.draining = null;
    });
    return this.draining;
  }

  // ---------- core ----------

  private async runIoc(
    ioc: Ioc,
    origin: LookupOrigin,
    settings: Settings,
    opts: { bypassCache?: boolean; only?: SourceId },
  ): Promise<void> {
    const key = iocKey(ioc);
    const existing = this.reports.get(key);
    if (!opts.bypassCache && existing && existing.summary.pending > 0) {
      this.emit({ type: 'report', report: existing }); // already running: don't start twice
      return;
    }

    const plan = this.deps.adaptersFor(ioc, settings);
    const runnable = plan.runnable.filter((r) => !opts.only || r.adapter.id === opts.only);
    const fresh = new Map<SourceId, SourceResult>();
    for (const p of plan.placeholders) fresh.set(p.source, p);
    for (const r of runnable) fresh.set(r.adapter.id, result(r.adapter.id, ioc, { status: 'loading', headline: 'Checking…' }));

    const merged = SOURCE_IDS.flatMap((id) => {
      const next = opts.only && id !== opts.only ? existing?.results.find((r) => r.source === id) : fresh.get(id);
      return next ? [next] : [];
    });
    const report = this.setReport({ ioc, results: merged, summary: summarize(merged) });
    if (!opts.only) await this.recordHistory(report, origin, settings);

    await Promise.all(runnable.map((r) => this.startSource(ioc, origin, r.adapter, r.apiKey, settings, !!opts.bypassCache)));
  }

  private async startSource(
    ioc: Ioc,
    origin: LookupOrigin,
    adapter: SourceAdapter,
    apiKey: string,
    settings: Settings,
    bypassCache: boolean,
  ): Promise<void> {
    if (bypassCache) {
      await invalidate(adapter.id, ioc);
    } else {
      const cached = await getCached(adapter.id, ioc, ttlMs(settings.cacheTtlHours), this.deps.now());
      if (cached) return this.update(cached, origin, settings);
    }

    // Keep FIFO order: never overtake jobs already waiting for this source.
    if (this.queue.list().some((j) => j.source === adapter.id)) return this.enqueue(ioc, origin, adapter.id, 1, settings);

    const d = this.limiter.acquire(adapter.id, this.deps.now());
    if (d.kind === 'now') return this.execute(ioc, origin, adapter, apiKey, 1, settings);
    if (d.kind === 'wait') return this.enqueue(ioc, origin, adapter.id, 1, settings);
    return this.update(quotaResult(adapter.id, ioc, d.resetAt), origin, settings);
  }

  private async execute(
    ioc: Ioc,
    origin: LookupOrigin,
    adapter: SourceAdapter,
    apiKey: string,
    attempt: number,
    settings: Settings,
  ): Promise<void> {
    let r: SourceResult;
    try {
      r = await adapter.lookup(ioc, apiKey, new AbortController().signal);
    } catch {
      r = errorResult(adapter.id, ioc, 'Unexpected error');
    }
    r = { ...r, ioc, fetchedAt: r.fetchedAt ?? this.deps.now() };

    if (r.status === 'rate_limited' && attempt < MAX_REQUEST_ATTEMPTS) {
      const now = this.deps.now();
      this.limiter.penalize(adapter.id, (r.retryAt ?? now + WINDOW_MS) - now, now);
      return this.enqueue(ioc, origin, adapter.id, attempt + 1, settings);
    }
    await putCached(r, this.deps.now());
    await this.update(r, origin, settings);
  }

  private async enqueue(ioc: Ioc, origin: LookupOrigin, source: SourceId, attempt: number, settings: Settings) {
    const job = this.queue.enqueue(source, { ioc, origin, attempt }, this.deps.now());
    const retryAt = this.queue.estimateStart(job.id, this.limiter, this.deps.now()) ?? undefined;
    await this.update(
      result(source, ioc, { status: 'queued', headline: 'Queued', ...(retryAt !== undefined && { retryAt }) }),
      origin,
      settings,
    );
  }

  private async drainOnce(): Promise<void> {
    const now = this.deps.now();
    const { ready, exhausted } = this.queue.drain(this.limiter, now);
    if (ready.length || exhausted.length) {
      const settings = await this.deps.getSettings();
      for (const job of exhausted) {
        const d = this.limiter.check(job.source, now);
        const resetAt = d.kind === 'quota' ? d.resetAt : now;
        await this.update(quotaResult(job.source, job.payload.ioc, resetAt), job.payload.origin, settings);
      }
      await Promise.all(
        ready.map(async (job) => {
          const { ioc, origin, attempt } = job.payload;
          // Settings may have changed while queued (key removed, source disabled).
          const plan = this.deps.adaptersFor(ioc, settings);
          const run = plan.runnable.find((r) => r.adapter.id === job.source);
          if (run) return this.execute(ioc, origin, run.adapter, run.apiKey, attempt, settings);
          const placeholder = plan.placeholders.find((p) => p.source === job.source);
          return this.update(placeholder ?? errorResult(job.source, ioc, 'Source no longer available'), origin, settings);
        }),
      );
    }
    await this.refreshQueuedEstimates();
    this.afterChange();
  }

  // ---------- state ----------

  private async update(r: SourceResult, origin: LookupOrigin, settings: Settings): Promise<void> {
    const key = iocKey(r.ioc);
    const current = this.reports.get(key);
    const base = current?.results ?? [];
    const results = SOURCE_IDS.flatMap((id) => {
      if (id === r.source) return [r];
      const existing = base.find((x) => x.source === id);
      return existing ? [existing] : [];
    });
    const wasPending = (current?.summary.pending ?? 1) > 0;
    const report = this.setReport({ ioc: current?.ioc ?? r.ioc, results, summary: summarize(results) });
    if (wasPending && report.summary.pending === 0) await this.recordHistory(report, origin, settings);
    this.persist();
  }

  private setReport(report: IocReport): IocReport {
    const key = iocKey(report.ioc);
    this.reports.delete(key);
    this.reports.set(key, report);
    this.trimReports();
    this.emit({ type: 'report', report });
    return report;
  }

  private setItems(items: ParseResult[]) {
    this.items = items;
    this.emit({ type: 'parsed', items });
  }

  private async recordHistory(report: IocReport, origin: LookupOrigin, settings: Settings) {
    await addHistory(report.ioc, report.summary.verdict, origin, settings, this.deps.now());
  }

  /** Update "Queued (≈N s)" estimates after the queue moved. */
  private async refreshQueuedEstimates() {
    const now = this.deps.now();
    for (const job of this.queue.list()) {
      const report = this.reports.get(iocKey(job.payload.ioc));
      const r = report?.results.find((x) => x.source === job.source);
      const retryAt = this.queue.estimateStart(job.id, this.limiter, now) ?? undefined;
      if (r && r.status === 'queued' && r.retryAt !== retryAt) {
        const results = report!.results.map((x) => (x === r ? { ...r, ...(retryAt !== undefined && { retryAt }) } : x));
        this.setReport({ ...report!, results });
      }
    }
  }

  private trimReports() {
    const keep = new Set(this.items.flatMap((i) => (i.kind === 'ioc' ? [iocKey(i.ioc)] : [])));
    for (const [key, r] of this.reports) {
      if (this.reports.size <= MAX_REPORTS) break;
      if (!keep.has(key) && r.summary.pending === 0) this.reports.delete(key);
    }
  }

  private afterChange() {
    this.scheduleWake();
    this.persist();
  }

  private scheduleWake() {
    const now = this.deps.now();
    const at = this.queue.nextWakeAt(this.limiter, now);
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    if (at !== null) {
      this.timer = setTimeout(() => void this.drain(), Math.max(0, at - now));
    }
    void this.deps.scheduleAlarm(at).catch(() => undefined);
  }

  /** Serialize writes so an older state never overwrites a newer one. */
  private persist() {
    const state: EngineState = {
      v: 1,
      queue: this.queue.serialize(),
      limiter: this.limiter.serialize(),
      reports: [...this.reports.values()],
      items: this.items,
    };
    this.saving = this.saving.then(() => this.deps.saveState(state)).catch(() => undefined);
  }

  /** Resolves when all pending state writes are done (for tests and shutdown). */
  flush(): Promise<void> {
    return this.saving;
  }

  private async restore(raw: unknown) {
    const s = isRecord(raw) && raw.v === 1 ? raw : undefined;
    if (!s) return;
    this.queue = RequestQueue.restore<JobPayload>(s.queue);
    this.limiter = RateLimiter.restore(s.limiter);
    this.items = Array.isArray(s.items) ? (s.items as ParseResult[]) : [];
    for (const r of Array.isArray(s.reports) ? (s.reports as IocReport[]) : []) {
      if (r && r.ioc && Array.isArray(r.results)) this.reports.set(iocKey(r.ioc), r);
    }
    // Requests that were in flight when the page stopped are re-queued.
    const queued = new Set(this.queue.list().map((j) => `${iocKey(j.payload.ioc)}|${j.source}`));
    for (const report of this.reports.values()) {
      for (const r of report.results) {
        if (r.status === 'loading' && !queued.has(`${iocKey(report.ioc)}|${r.source}`)) {
          this.queue.enqueue(r.source, { ioc: report.ioc, origin: 'popup', attempt: 1 }, this.deps.now());
          const results = report.results.map((x) => (x === r ? { ...r, status: 'queued' as const, headline: 'Queued' } : x));
          this.reports.set(iocKey(report.ioc), { ...report, results, summary: summarize(results) });
        }
      }
    }
    this.scheduleWake();
  }

  private emit(msg: ResponseMessage) {
    for (const l of this.listeners) {
      try {
        l(msg);
      } catch {
        // A failing listener (e.g. a closed port) must not break the engine.
      }
    }
  }
}

function quotaResult(source: SourceId, ioc: Ioc, resetAt: number): SourceResult {
  return result(source, ioc, {
    status: 'rate_limited',
    headline: 'Daily quota reached',
    error: 'Daily quota reached',
    retryAt: resetAt,
  });
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

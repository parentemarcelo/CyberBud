// Client-side rate limiting (docs/SPEC.md F6).
// Per source: a sliding 60 s window (at most `perMinute` requests in any
// 60 s span; stricter than a token bucket, which would let VirusTotal's 5th
// request through after 15 s and earn an HTTP 429) plus a daily counter that
// resets at 00:00 UTC. State is plain JSON so it can live in storage.session.
import { RATE_LIMITS } from './constants';
import { SOURCE_IDS, type RateLimit, type SourceId } from './types';

export const WINDOW_MS = 60_000;
export const DAY_MS = 86_400_000;

export type Decision =
  | { kind: 'now' }
  /** Try again in `ms` (at epoch `at`). */
  | { kind: 'wait'; ms: number; at: number }
  /** Daily quota used up until `resetAt` (next 00:00 UTC). */
  | { kind: 'quota'; resetAt: number };

interface SourceState {
  /** Timestamps of requests within the last window. */
  recent: number[];
  /** UTC day number (epoch ms / DAY_MS) that dayCount belongs to. */
  day: number;
  dayCount: number;
  /** Set from a server Retry-After; no requests before this time. */
  blockedUntil: number;
}

export interface RateLimiterState {
  v: 1;
  sources: Partial<Record<SourceId, SourceState>>;
}

const utcDay = (now: number) => Math.floor(now / DAY_MS);

export class RateLimiter {
  private readonly sources: Partial<Record<SourceId, SourceState>>;

  constructor(
    private readonly limits: Readonly<Record<SourceId, Readonly<RateLimit>>> = RATE_LIMITS,
    state?: RateLimiterState,
  ) {
    this.sources = state ? structuredClone(state.sources) : {};
  }

  /** Whether a request may run now, without consuming a slot. */
  check(source: SourceId, now: number = Date.now()): Decision {
    const st = this.state(source, now);
    const { perMinute, perDay } = this.limits[source];

    if (perDay !== undefined && st.dayCount >= perDay) {
      return { kind: 'quota', resetAt: (st.day + 1) * DAY_MS };
    }
    let at = st.blockedUntil > now ? st.blockedUntil : now;
    if (st.recent.length >= perMinute) {
      // The slot frees when the oldest request still counted leaves the window.
      at = Math.max(at, st.recent[st.recent.length - perMinute]! + WINDOW_MS);
    }
    return at > now ? { kind: 'wait', ms: at - now, at } : { kind: 'now' };
  }

  /** Like check(), but records the request when the answer is 'now'. */
  acquire(source: SourceId, now: number = Date.now()): Decision {
    const decision = this.check(source, now);
    if (decision.kind === 'now') {
      const st = this.state(source, now);
      st.recent.push(now);
      st.dayCount++;
    }
    return decision;
  }

  /** Honour a server Retry-After (HTTP 429): block the source for `ms`. */
  penalize(source: SourceId, ms: number, now: number = Date.now()): void {
    const st = this.state(source, now);
    st.blockedUntil = Math.max(st.blockedUntil, now + Math.max(0, ms));
  }

  /** Requests left today, or undefined when the source has no daily limit. */
  remainingToday(source: SourceId, now: number = Date.now()): number | undefined {
    const { perDay } = this.limits[source];
    return perDay === undefined ? undefined : Math.max(0, perDay - this.state(source, now).dayCount);
  }

  serialize(): RateLimiterState {
    return { v: 1, sources: structuredClone(this.sources) };
  }

  /** Rebuild from serialized state; invalid input gives a fresh limiter. */
  static restore(state: unknown, limits = RATE_LIMITS): RateLimiter {
    return new RateLimiter(limits, isLimiterState(state) ? state : undefined);
  }

  /** Current state for a source, after day rollover and window pruning. */
  private state(source: SourceId, now: number): SourceState {
    const today = utcDay(now);
    let st = this.sources[source];
    if (!st) {
      st = { recent: [], day: today, dayCount: 0, blockedUntil: 0 };
      this.sources[source] = st;
    }
    if (st.day !== today) {
      st.day = today;
      st.dayCount = 0;
    }
    // Drop timestamps outside the window, and any "from the future" (clock moved back).
    st.recent = st.recent.filter((t) => t > now - WINDOW_MS && t <= now);
    if (st.blockedUntil > now + DAY_MS) st.blockedUntil = now + DAY_MS;
    return st;
  }
}

// ---------- Queue ----------

export interface QueuedJob<T> {
  id: string;
  source: SourceId;
  payload: T;
  enqueuedAt: number;
}

export interface RequestQueueState<T> {
  v: 1;
  jobs: QueuedJob<T>[];
}

/** FIFO per source. Payloads must be JSON-serializable. */
export class RequestQueue<T> {
  private jobs: QueuedJob<T>[];

  constructor(state?: RequestQueueState<T>) {
    this.jobs = state ? structuredClone(state.jobs) : [];
  }

  get size(): number {
    return this.jobs.length;
  }

  list(): readonly QueuedJob<T>[] {
    return this.jobs;
  }

  enqueue(source: SourceId, payload: T, now: number = Date.now()): QueuedJob<T> {
    const job: QueuedJob<T> = { id: crypto.randomUUID(), source, payload, enqueuedAt: now };
    this.jobs.push(job);
    return job;
  }

  /**
   * Remove and return the jobs that may run now, acquiring a limiter slot for
   * each. Jobs whose source hit its daily quota are removed and returned in
   * `exhausted` so the caller can mark them rate_limited.
   */
  drain(limiter: RateLimiter, now: number = Date.now()): { ready: QueuedJob<T>[]; exhausted: QueuedJob<T>[] } {
    const ready: QueuedJob<T>[] = [];
    const exhausted: QueuedJob<T>[] = [];
    const blocked = new Set<SourceId>();
    const keep: QueuedJob<T>[] = [];

    for (const job of this.jobs) {
      if (blocked.has(job.source)) {
        keep.push(job); // keep FIFO order behind a waiting job of the same source
        continue;
      }
      const d = limiter.acquire(job.source, now);
      if (d.kind === 'now') ready.push(job);
      else if (d.kind === 'quota') exhausted.push(job);
      else {
        blocked.add(job.source);
        keep.push(job);
      }
    }
    this.jobs = keep;
    return { ready, exhausted };
  }

  /** Earliest time a queued job could run (for an alarm), or null if nothing is waiting. */
  nextWakeAt(limiter: RateLimiter, now: number = Date.now()): number | null {
    let next: number | null = null;
    for (const source of new Set(this.jobs.map((j) => j.source))) {
      const d = limiter.check(source, now);
      const at = d.kind === 'now' ? now : d.kind === 'wait' ? d.at : d.resetAt;
      if (next === null || at < next) next = at;
    }
    return next;
  }

  /**
   * Rough start time for a queued job, for "Queued (≈45 s)": wait for the
   * first free slot, plus one window per full `perMinute` batch ahead of it.
   */
  estimateStart(
    jobId: string,
    limiter: RateLimiter,
    now: number = Date.now(),
    limits = RATE_LIMITS,
  ): number | null {
    const job = this.jobs.find((j) => j.id === jobId);
    if (!job) return null;
    const ahead = this.jobs.filter((j) => j.source === job.source).indexOf(job);
    const d = limiter.check(job.source, now);
    if (d.kind === 'quota') return d.resetAt;
    const first = d.kind === 'wait' ? d.at : now;
    return first + Math.floor(ahead / limits[job.source].perMinute) * WINDOW_MS;
  }

  /** Remove jobs matching `predicate`; returns them. */
  remove(predicate: (job: QueuedJob<T>) => boolean): QueuedJob<T>[] {
    const removed = this.jobs.filter(predicate);
    this.jobs = this.jobs.filter((j) => !predicate(j));
    return removed;
  }

  serialize(): RequestQueueState<T> {
    return { v: 1, jobs: structuredClone(this.jobs) };
  }

  static restore<T>(state: unknown): RequestQueue<T> {
    return new RequestQueue<T>(isQueueState<T>(state) ? state : undefined);
  }
}

// ---------- validation of restored state ----------

function isLimiterState(x: unknown): x is RateLimiterState {
  if (typeof x !== 'object' || x === null) return false;
  const s = x as Partial<RateLimiterState>;
  if (s.v !== 1 || typeof s.sources !== 'object' || s.sources === null) return false;
  return Object.entries(s.sources).every(
    ([id, st]) =>
      (SOURCE_IDS as readonly string[]).includes(id) &&
      typeof st === 'object' &&
      st !== null &&
      Array.isArray(st.recent) &&
      st.recent.every((t) => typeof t === 'number') &&
      typeof st.day === 'number' &&
      typeof st.dayCount === 'number' &&
      typeof st.blockedUntil === 'number',
  );
}

function isQueueState<T>(x: unknown): x is RequestQueueState<T> {
  if (typeof x !== 'object' || x === null) return false;
  const s = x as Partial<RequestQueueState<T>>;
  return (
    s.v === 1 &&
    Array.isArray(s.jobs) &&
    s.jobs.every(
      (j) =>
        typeof j === 'object' &&
        j !== null &&
        typeof j.id === 'string' &&
        (SOURCE_IDS as readonly string[]).includes(j.source) &&
        typeof j.enqueuedAt === 'number',
    )
  );
}

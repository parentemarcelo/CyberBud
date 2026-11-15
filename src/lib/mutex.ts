/**
 * Serializes async read-modify-write sections within one JS context, so
 * concurrent updates to the same storage key don't overwrite each other.
 */
export function createMutex() {
  let tail: Promise<unknown> = Promise.resolve();
  return function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = tail.then(fn, fn);
    tail = run.catch(() => undefined);
    return run;
  };
}

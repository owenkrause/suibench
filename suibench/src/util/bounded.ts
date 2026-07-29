// Bounded-concurrency map: at most `limit` calls to `fn` in flight, results in
// input order. A fixed pool of workers pulls from a shared cursor; the first
// rejection propagates (Promise.all semantics), so a real defect aborts the run.
export async function boundedMap<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError(`boundedMap limit must be a positive integer; got ${limit}`);
  }
  const results = new Array<R>(items.length);
  let cursor = 0;
  let failed = false;
  let firstError: unknown;
  const worker = async (): Promise<void> => {
    for (;;) {
      if (failed) return;
      const i = cursor++;
      if (i >= items.length) return;
      try {
        results[i] = await fn(items[i], i);
      } catch (err) {
        if (!failed) {
          failed = true;
          firstError = err;
        }
        return;
      }
    }
  };
  const workers = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: workers }, worker));
  if (failed) throw firstError;
  return results;
}

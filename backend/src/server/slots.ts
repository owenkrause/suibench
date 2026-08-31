// Global cap on concurrent heavy Docker grading topologies. A permit is held for the
// WHOLE of fn — including its teardown — so cleanup-before-release holds: the finally
// runs before the next waiter is admitted.
export class SlotPool {
  private avail: number;
  private readonly waiters: Array<() => void> = [];

  constructor(n: number) {
    if (n < 1) throw new Error("SlotPool n must be >= 1");
    this.avail = n;
  }

  private acquire(): Promise<void> {
    if (this.avail > 0) {
      this.avail--;
      return Promise.resolve();
    }
    return new Promise((res) => this.waiters.push(res));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.avail++;
  }

  async withSlot<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

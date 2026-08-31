import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export interface TrajectorySink {
  save(t: { id: string }): Promise<void>;
}

// A trajectory is a trusted, plain-JSON blob (no bigints or bytes): plain write,
// no atomic rename or checksum.
export class FileTrajectorySink implements TrajectorySink {
  constructor(private readonly dir: string) {}

  async save(t: { id: string }): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    await writeFile(join(this.dir, `${t.id}.json`), JSON.stringify(t, null, 2));
  }
}

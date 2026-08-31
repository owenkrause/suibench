// Host-side chain-snapshot gather. Reads the local benchmark through the
// native gRPC client and returns the small DTO consumed by confirmer.ts.
import type { SuiClientTypes } from "@mysten/sui/client";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import { ChainDiscovery } from "./chain-discovery.js";

const CLOCK_OBJECT_ID = "0x6";
const BATCH = 50;
const MAX_OBJECTS = 256;
const MAX_DEPTH = 4;

interface SnapshotObject {
  objectId: string;
  type: string;
  owner: unknown;
  fields: Record<string, unknown>;
}

export async function captureChainSnapshot(
  client: SuiGrpcClient,
  addresses: string[],
  checkpoint: bigint,
): Promise<{
  balances: Record<string, Record<string, string>>;
  objects: SnapshotObject[];
}> {
  const chain = new ChainDiscovery(client, checkpoint);

  const balances: Record<string, Record<string, string>> = {};
  const objects: SnapshotObject[] = [];
  const seen = new Set<string>();
  const known = new Set<string>();

  // Bound the gather: reserve every id we intend to fetch or traverse and fail loud
  // past MAX_OBJECTS, so a hostile/degenerate object graph can't blow up the snapshot.
  function reserve(id: string): boolean {
    if (known.has(id)) return false;
    if (known.size >= MAX_OBJECTS) {
      throw new Error(`snapshot object limit exceeded (${MAX_OBJECTS})`);
    }
    known.add(id);
    return true;
  }

  function add(object: SuiClientTypes.Object<{ json: true }> | Error): void {
    if (object instanceof Error) {
      throw object;
    }
    if (!object.json || !object.type.includes("::")) {
      throw new Error(`snapshot object ${object.objectId} has no parsed Move data`);
    }
    if (seen.has(object.objectId)) return;
    reserve(object.objectId);
    seen.add(object.objectId);
    objects.push({
      objectId: object.objectId,
      type: object.type,
      owner: object.owner,
      fields: object.json,
    });
  }

  async function fetchInto(ids: readonly string[]): Promise<void> {
    for (let index = 0; index < ids.length; index += BATCH) {
      const objectIds = ids.slice(index, index + BATCH).filter((id) => !seen.has(id));
      if (objectIds.length === 0) continue;
      const { objects: found } = await client.core.getObjects({
        objectIds,
        include: { json: true },
      });
      for (const object of found) add(object);
    }
  }

  for (const owner of addresses) {
    const coins: Record<string, string> = {};
    let cursor: string | null = null;
    do {
      const page = await client.core.listBalances({ owner, cursor });
      for (const balance of page.balances) coins[balance.coinType] = balance.balance;
      cursor = page.hasNextPage ? page.cursor : null;
    } while (cursor);
    balances[owner] = coins;

    cursor = null;
    do {
      const page: SuiClientTypes.ListOwnedObjectsResponse<{ json: true }> =
        await client.core.listOwnedObjects({
        owner,
        cursor,
        include: { json: true },
        });
      for (const object of page.objects) add(object);
      cursor = page.hasNextPage ? page.cursor : null;
    } while (cursor);
  }

  const discovered = new Set([
    CLOCK_OBJECT_ID,
    ...(await chain.findTouchedObjectIds(addresses)),
  ]);
  await fetchInto([...discovered]);

  // Recursive dynamic-field + nested-object closure, breadth-first and bounded by
  // MAX_OBJECTS / MAX_DEPTH. Following dynamic fields deepens by one level; nested
  // UIDs embedded in an object's fields (`{ id }` — e.g. a Table/Bag handle) are the
  // parents whose dynamic fields we must list, so they enter at the SAME depth.
  const queried = new Set<string>();
  const queue: Array<{ id: string; depth: number }> = [];

  const enqueue = (object: SnapshotObject, depth: number): void => {
    queue.push({ id: object.objectId, depth });
    const walk = (value: unknown): void => {
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) {
        for (const item of value) walk(item);
        return;
      }
      const record = value as Record<string, unknown>;
      if (typeof record.id === "string" && reserve(record.id)) {
        queue.push({ id: record.id, depth });
      }
      for (const nested of Object.values(record)) walk(nested);
    };
    walk(object.fields);
  };

  for (const object of objects) enqueue(object, 0);

  for (let i = 0; i < queue.length; i++) {
    const parent = queue[i];
    if (queried.has(parent.id)) continue;
    queried.add(parent.id);

    const childIds: string[] = [];
    let cursor: string | null = null;
    do {
      const page = await client.core.listDynamicFields({
        parentId: parent.id,
        cursor,
      });
      for (const field of page.dynamicFields) {
        const id = field.$kind === "DynamicObject" ? field.childId : field.fieldId;
        if (!id || seen.has(id) || !reserve(id)) continue;
        if (parent.depth >= MAX_DEPTH) {
          throw new Error(
            `snapshot dynamic-field depth limit exceeded (${MAX_DEPTH})`,
          );
        }
        childIds.push(id);
      }
      cursor = page.hasNextPage ? page.cursor : null;
    } while (cursor);

    const firstAdded = objects.length;
    await fetchInto(childIds);
    for (const child of objects.slice(firstAdded)) {
      enqueue(child, parent.depth + 1);
    }
  }

  return { balances, objects };
}

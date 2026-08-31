import { describe, expect, it } from "vitest";
import {
  classifyVictimOutcome,
  parseSnapshotObject,
  collectCheckEvidence,
  finalizeAttackEvidence,
  InfraError,
} from "./confirmer.js";
import type { DrainResult } from "./gate.js";

describe("classifyVictimOutcome", () => {
  it("classifies a native preflight result without a legacy transaction envelope", () => {
    expect(
      classifyVictimOutcome({
        status: {
          success: false,
          error: {
            message: "MoveAbort in benchmark::module::entry",
          },
        },
      }),
    ).toEqual({
      status: "abort",
      message: "MoveAbort in benchmark::module::entry",
    });
  });
});

describe("parseSnapshotObject", () => {
  it("maps a native gRPC object DTO without JSON-RPC content wrappers", () => {
    expect(
      parseSnapshotObject({
        objectId: "0xobject",
        type: "0xpkg::module::State",
        owner: {
          $kind: "Shared",
          Shared: { initialSharedVersion: "7" },
        },
        fields: { count: "3" },
      }),
    ).toEqual({
      id: "0xobject",
      state: {
        type: "0xpkg::module::State",
        owner: { Shared: { initial_shared_version: "7" } },
        fields: { count: "3" },
      },
    });
  });

  it("rejects an unrecognized native owner instead of inventing one", () => {
    expect(() =>
      parseSnapshotObject({
        objectId: "0xobject",
        type: "0xpkg::module::State",
        owner: { $kind: "FutureOwner" },
        fields: {},
      }),
    ).toThrow("unknown native object owner");
  });
});

// ── collectCheckEvidence / finalizeAttackEvidence ────────────────────────────

function txPayload(overrides: {
  digest?: string;
  success?: boolean;
  events?: unknown;
}): Record<string, unknown> {
  const { digest = "d1", success = true, events = [] } = overrides;
  return {
    digest,
    status: { success, error: success ? null : { message: "boom" } },
    events,
  };
}

function txEnvelope(overrides: {
  digest?: string;
  success?: boolean;
  events?: unknown;
} = {}): unknown {
  const success = overrides.success ?? true;
  const payload = txPayload(overrides);
  return success
    ? { $kind: "Transaction", Transaction: payload }
    : { $kind: "FailedTransaction", FailedTransaction: payload };
}

interface FakeCore {
  core: { getTransaction: (opts: { digest: string; signal?: AbortSignal }) => Promise<unknown> };
  calls: string[];
}

function fakeCore(handler: (digest: string) => unknown | Promise<unknown>): FakeCore {
  const calls: string[] = [];
  return {
    calls,
    core: {
      getTransaction: async (opts: { digest: string; signal?: AbortSignal }) => {
        calls.push(opts.digest);
        return handler(opts.digest);
      },
    },
  };
}

describe("collectCheckEvidence", () => {
  it("returns empty evidence for an empty digest list without an RPC call", async () => {
    const { core, calls } = fakeCore(() => txEnvelope());
    const evidence = await collectCheckEvidence(core as never, []);
    expect(evidence).toEqual({ attackTransactions: [] });
    expect(calls).toEqual([]);
  });

  it("preserves digest order and duplicates exactly", async () => {
    const { core, calls } = fakeCore((digest) => txEnvelope({ digest }));
    const evidence = await collectCheckEvidence(core as never, ["b", "a", "b"]);
    expect(calls).toEqual(["b", "a", "b"]);
    expect(evidence.attackTransactions.map((t) => t.digest)).toEqual(["b", "a", "b"]);
  });

  it("maps a successful $kind Transaction to status success", async () => {
    const { core } = fakeCore((digest) => txEnvelope({ digest, success: true }));
    const evidence = await collectCheckEvidence(core as never, ["ok-1"]);
    expect(evidence.attackTransactions).toEqual([
      { digest: "ok-1", status: "success", events: [] },
    ]);
  });

  it("maps a failed $kind FailedTransaction to status failure and retains its events", async () => {
    const { core } = fakeCore((digest) =>
      txEnvelope({
        digest,
        success: false,
        events: [{ eventType: "0xpkg::mod::Diagnostic", json: { n: 1 } }],
      }),
    );
    const evidence = await collectCheckEvidence(core as never, ["fail-1"]);
    expect(evidence.attackTransactions).toEqual([
      {
        digest: "fail-1",
        status: "failure",
        events: [{ type: "0xpkg::mod::Diagnostic", json: { n: 1 } }],
      },
    ]);
  });

  it("maps events to {type, json} only, in RPC order", async () => {
    const { core } = fakeCore((digest) =>
      txEnvelope({
        digest,
        events: [
          { eventType: "0xpkg::mod::First", json: { a: 1 }, bcs: new Uint8Array([1]) },
          { eventType: "0xpkg::mod::Second", json: null, sender: "0xattacker" },
        ],
      }),
    );
    const evidence = await collectCheckEvidence(core as never, ["e-1"]);
    expect(evidence.attackTransactions[0]!.events).toEqual([
      { type: "0xpkg::mod::First", json: { a: 1 } },
      { type: "0xpkg::mod::Second", json: null },
    ]);
  });

  it("never fetches an extra transaction not present in the supplied digest list", async () => {
    const { core, calls } = fakeCore((digest) => {
      if (digest === "attack-1") return txEnvelope({ digest });
      throw new Error(`unexpected fetch of ${digest}`);
    });
    const evidence = await collectCheckEvidence(core as never, ["attack-1"]);
    expect(calls).toEqual(["attack-1"]);
    expect(evidence.attackTransactions.map((t) => t.digest)).toEqual(["attack-1"]);
  });

  it("wraps an RPC rejection as InfraError and returns no partial evidence", async () => {
    const { core } = fakeCore((digest) => {
      if (digest === "bad") return Promise.reject(new Error("rpc down"));
      return txEnvelope({ digest });
    });
    await expect(collectCheckEvidence(core as never, ["ok", "bad"])).rejects.toThrow(InfraError);
  });

  it("wraps a deadline exceeded (client ignores abort) as InfraError", async () => {
    const core = {
      getTransaction: () => new Promise<unknown>(() => {}), // never resolves, ignores signal
    };
    await expect(collectCheckEvidence(core as never, ["stuck"], 20)).rejects.toThrow(InfraError);
  });
});

describe("finalizeAttackEvidence", () => {
  function drainResult(overrides: Partial<DrainResult> = {}): DrainResult {
    return {
      kind: "complete",
      digests: [],
      rejected: 0,
      ambiguous: 0,
      capsHit: [],
      ...overrides,
    };
  }

  it("throws InfraError without fetching when the drain did not complete", async () => {
    const waitCalls: string[] = [];
    const getCalls: string[] = [];
    const client = {
      core: {
        waitForTransaction: async ({ digest }: { digest: string }) => {
          waitCalls.push(digest);
        },
        getTransaction: async ({ digest }: { digest: string }) => {
          getCalls.push(digest);
          return txEnvelope({ digest });
        },
      },
    };
    const drain = drainResult({ kind: "ambiguous", digests: ["a"], ambiguous: 1 });
    await expect(finalizeAttackEvidence(client as never, drain)).rejects.toThrow(InfraError);
    expect(waitCalls).toEqual([]);
    expect(getCalls).toEqual([]);
  });

  it("confirms visibility and fetches evidence for exactly drain.digests — never setup/victim", async () => {
    const waitCalls: string[] = [];
    const getCalls: string[] = [];
    const client = {
      core: {
        waitForTransaction: async ({ digest }: { digest: string }) => {
          waitCalls.push(digest);
          if (digest !== "attack-1") throw new Error(`unexpected visibility wait for ${digest}`);
          return {};
        },
        getTransaction: async ({ digest }: { digest: string }) => {
          getCalls.push(digest);
          if (digest !== "attack-1") throw new Error(`unexpected fetch of ${digest}`);
          return txEnvelope({ digest });
        },
      },
    };
    // setup-1/victim-1 are fetchable by the fake client but never appear in
    // drain.digests — only the gate-drained attack digest does.
    const drain = drainResult({ kind: "complete", digests: ["attack-1"] });
    const evidence = await finalizeAttackEvidence(client as never, drain);
    expect(waitCalls).toEqual(["attack-1"]);
    expect(getCalls).toEqual(["attack-1"]);
    expect(evidence.attackTransactions.map((t) => t.digest)).toEqual(["attack-1"]);
  });
});

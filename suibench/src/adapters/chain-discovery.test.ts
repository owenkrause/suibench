import { describe, expect, it, vi } from "vitest";
import { GrpcTypes } from "@mysten/sui/grpc";
import { ChainDiscovery } from "./chain-discovery.js";

function fakeClient() {
  return {
    ledgerService: {
      getServiceInfo: vi.fn().mockResolvedValue({
        response: { checkpointHeight: 4n },
      }),
      getCheckpoint: vi.fn(async ({ checkpointId }) => {
        const checkpoint = checkpointId.sequenceNumber as bigint;
        return {
          response: {
            checkpoint: {
              objects: {
                objects: [
                  {
                    objectId: `0xobject${checkpoint}`,
                    objectType: `0xabc::module::Thing${checkpoint}`,
                  },
                ],
              },
              transactions: [
                {
                  digest: `tx-${checkpoint}`,
                  transaction: {
                    sender: checkpoint === 3n ? "0x000b" : "0x000a",
                  },
                  effects: {
                    changedObjects: [
                      {
                        objectId: `0xobject${checkpoint}`,
                        idOperation:
                          GrpcTypes.ChangedObject_IdOperation.CREATED,
                      },
                    ],
                  },
                },
              ],
            },
          },
        };
      }),
    },
  };
}

describe("ChainDiscovery", () => {
  it("returns only sender-created objects from its bounded checkpoint range", async () => {
    const raw = fakeClient();
    const discovery = new ChainDiscovery(raw as never, 2n);

    await expect(discovery.findCreatedObjects("0xa")).resolves.toEqual([
      {
        id: "0xobject4",
        type: "0x0000000000000000000000000000000000000000000000000000000000000abc::module::Thing4",
        digest: "tx-4",
        checkpoint: 4n,
      },
      {
        id: "0xobject2",
        type: "0x0000000000000000000000000000000000000000000000000000000000000abc::module::Thing2",
        digest: "tx-2",
        checkpoint: 2n,
      },
    ]);

    expect(raw.ledgerService.getCheckpoint).toHaveBeenCalledTimes(3);
  });

  it("normalizes checkpoint Move type strings like the native object client", async () => {
    const raw = {
      ledgerService: {
        getServiceInfo: vi.fn().mockResolvedValue({
          response: { checkpointHeight: 2n },
        }),
        getCheckpoint: vi.fn().mockResolvedValue({
          response: {
            checkpoint: {
              objects: {
                objects: [
                  {
                    objectId: "0xstate",
                    objectType: "0x9::module::State<0x2::sui::SUI>",
                  },
                ],
              },
              transactions: [
                {
                  digest: "tx-2",
                  transaction: { sender: "0xa" },
                  effects: {
                    changedObjects: [
                      {
                        objectId: "0xstate",
                        idOperation:
                          GrpcTypes.ChangedObject_IdOperation.CREATED,
                      },
                    ],
                  },
                },
              ],
            },
          },
        }),
      },
    };
    const discovery = new ChainDiscovery(raw as never, 2n);

    await expect(discovery.findCreatedObjects("0xa")).resolves.toEqual([
      {
        id: "0xstate",
        type: "0x0000000000000000000000000000000000000000000000000000000000000009::module::State<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>",
        digest: "tx-2",
        checkpoint: 2n,
      },
    ]);
  });

  it("returns changed object IDs and a matching event from native checkpoint data", async () => {
    const raw = {
      ledgerService: {
        getServiceInfo: vi.fn().mockResolvedValue({
          response: { checkpointHeight: 2n },
        }),
        getCheckpoint: vi.fn().mockResolvedValue({
          response: {
            checkpoint: {
              objects: { objects: [] },
              transactions: [
                {
                  digest: "tx-2",
                  transaction: { sender: "0xa" },
                  effects: {
                    changedObjects: [
                      {
                        objectId: "0xchanged",
                        outputState:
                          GrpcTypes.ChangedObject_OutputObjectState.OBJECT_WRITE,
                      },
                      {
                        objectId: "0xother",
                        outputState:
                          GrpcTypes.ChangedObject_OutputObjectState.OBJECT_WRITE,
                      },
                      {
                        objectId: "0xdeleted",
                        outputState:
                          GrpcTypes.ChangedObject_OutputObjectState.DOES_NOT_EXIST,
                      },
                    ],
                  },
                  events: {
                    events: [{ eventType: "0xp::game::Authorization" }],
                  },
                },
              ],
            },
          },
        }),
      },
      core: {
        getTransaction: vi.fn().mockResolvedValue({
          $kind: "Transaction",
          Transaction: {
            events: [
              {
                eventType: "0xp::game::Authorization",
                json: { pack_id: "7" },
              },
            ],
          },
        }),
      },
    };
    const discovery = new ChainDiscovery(raw as never, 2n);

    await expect(discovery.findTouchedObjectIds(["0xa"])).resolves.toEqual([
      "0xchanged",
      "0xother",
    ]);
    await expect(
      discovery.findMoveEvents("0xp::game::Authorization"),
    ).resolves.toEqual([
      {
        type: "0xp::game::Authorization",
        json: { pack_id: "7" },
        digest: "tx-2",
      },
    ]);
    expect(raw.ledgerService.getCheckpoint).toHaveBeenCalledWith(
      expect.objectContaining({
        readMask: expect.objectContaining({
          paths: expect.arrayContaining(["transactions.events"]),
        }),
      }),
    );
  });

  it("drops a previously touched object when a later checkpoint removes it", async () => {
    const raw = {
      ledgerService: {
        getServiceInfo: vi.fn().mockResolvedValue({
          response: { checkpointHeight: 3n },
        }),
        getCheckpoint: vi.fn(({ checkpointId }) => {
          const checkpoint = checkpointId.sequenceNumber as bigint;
          return {
            response: {
              checkpoint: {
                objects: { objects: [] },
                transactions: [
                  {
                    digest: `tx-${checkpoint}`,
                    transaction: { sender: "0xa" },
                    effects: {
                      changedObjects:
                        checkpoint === 2n
                          ? [
                              {
                                objectId: "0xgone",
                                outputState:
                                  GrpcTypes.ChangedObject_OutputObjectState
                                    .OBJECT_WRITE,
                              },
                            ]
                          : [
                              {
                                objectId: "0xgone",
                                outputState:
                                  GrpcTypes.ChangedObject_OutputObjectState
                                    .DOES_NOT_EXIST,
                              },
                            ],
                    },
                  },
                ],
              },
            },
          };
        }),
      },
    };
    const discovery = new ChainDiscovery(raw as never, 2n);

    await expect(discovery.findTouchedObjectIds(["0xa"])).resolves.toEqual([]);
  });

  it("returns package IDs published by a sender", async () => {
    const raw = {
      ledgerService: {
        getServiceInfo: vi.fn().mockResolvedValue({
          response: { checkpointHeight: 2n },
        }),
        getCheckpoint: vi.fn().mockResolvedValue({
          response: {
            checkpoint: {
              objects: { objects: [] },
              transactions: [
                {
                  digest: "publish-2",
                  transaction: { sender: "0xa" },
                  effects: {
                    changedObjects: [
                      {
                        objectId: "0xpackage",
                        outputState:
                          GrpcTypes.ChangedObject_OutputObjectState.PACKAGE_WRITE,
                      },
                    ],
                  },
                },
              ],
            },
          },
        }),
      },
    };
    const discovery = new ChainDiscovery(raw as never, 2n);

    await expect(discovery.findPublishedPackages("0xa")).resolves.toEqual([
      { id: "0xpackage", digest: "publish-2", checkpoint: 2n },
    ]);
  });
});

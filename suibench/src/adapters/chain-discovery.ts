import { GrpcTypes, type SuiGrpcClient } from "@mysten/sui/grpc";
import { normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils";

export interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

export interface MoveEvent {
  readonly type: string;
  readonly json: unknown;
  readonly digest: string;
}

export interface PublishedPackage {
  readonly id: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

interface RecordedCreatedObject extends CreatedObject {
  readonly sender: string;
}

interface RecordedTransaction {
  readonly sender: string;
  readonly digest: string;
  readonly checkpoint: bigint;
  readonly changedObjects: readonly {
    readonly id: string;
    readonly outputState: GrpcTypes.ChangedObject_OutputObjectState | undefined;
  }[];
  readonly publishedPackageIds: readonly string[];
  readonly eventTypes: readonly string[];
}

export class ChainDiscovery {
  private readonly created: RecordedCreatedObject[] = [];
  private readonly transactions: RecordedTransaction[] = [];
  private scannedThrough: bigint;

  constructor(
    private readonly client: SuiGrpcClient,
    fromCheckpoint: bigint,
  ) {
    this.scannedThrough = fromCheckpoint - 1n;
  }

  async findCreatedObjects(sender: string): Promise<readonly CreatedObject[]> {
    await this.scan();
    const wanted = normalizeSuiAddress(sender);
    return this.created
      .filter((object) => normalizeSuiAddress(object.sender) === wanted)
      .map(({ sender: _sender, ...object }) => object);
  }

  async findTouchedObjectIds(
    senders: readonly string[],
  ): Promise<readonly string[]> {
    await this.scan();
    const wanted = new Set(senders.map((sender) => normalizeSuiAddress(sender)));
    const live = new Set<string>();
    for (const transaction of this.transactions) {
      const isRelevantSender = wanted.has(
        normalizeSuiAddress(transaction.sender),
      );
      for (const change of transaction.changedObjects) {
        if (
          change.outputState ===
          GrpcTypes.ChangedObject_OutputObjectState.DOES_NOT_EXIST
        ) {
          live.delete(change.id);
        } else if (
          change.outputState ===
            GrpcTypes.ChangedObject_OutputObjectState.OBJECT_WRITE &&
          (isRelevantSender || live.has(change.id))
        ) {
          live.add(change.id);
        }
      }
    }
    return [...live];
  }

  async findPublishedPackages(
    sender: string,
  ): Promise<readonly PublishedPackage[]> {
    await this.scan();
    const wanted = normalizeSuiAddress(sender);
    return this.transactions
      .filter((transaction) => normalizeSuiAddress(transaction.sender) === wanted)
      .flatMap((transaction) =>
        transaction.publishedPackageIds.map((id) => ({
          id,
          digest: transaction.digest,
          checkpoint: transaction.checkpoint,
        })),
      );
  }

  async findMoveEvents(eventType: string): Promise<readonly MoveEvent[]> {
    await this.scan();
    const matches: MoveEvent[] = [];
    for (const transaction of this.transactions) {
      if (!transaction.eventTypes.includes(eventType)) continue;
      const result = await this.client.core.getTransaction({
        digest: transaction.digest,
        include: { events: true },
      });
      const executed = result.Transaction ?? result.FailedTransaction;
      for (const event of executed.events ?? []) {
        if (event.eventType !== eventType) continue;
        matches.push({
          type: event.eventType,
          json: event.json,
          digest: transaction.digest,
        });
      }
    }
    return matches;
  }

  private async scan(): Promise<void> {
    const { response: info } = await this.client.ledgerService.getServiceInfo({});
    const tip = info.checkpointHeight;
    if (tip === undefined || tip <= this.scannedThrough) return;

    for (let checkpoint = this.scannedThrough + 1n; checkpoint <= tip; checkpoint++) {
      const { response } = await this.client.ledgerService.getCheckpoint({
        checkpointId: {
          oneofKind: "sequenceNumber",
          sequenceNumber: checkpoint,
        },
        readMask: {
          paths: [
            "transactions.digest",
            "transactions.transaction.sender",
            "transactions.effects.changed_objects",
            "transactions.events",
            "objects.objects.object_id",
            "objects.objects.object_type",
          ],
        },
      });
      const value = response.checkpoint;
      if (!value) continue;

      const types = new Map(
        (value.objects?.objects ?? [])
          .filter((object) => object.objectId && object.objectType)
          .map((object) => [
            object.objectId!,
            object.objectType!.includes("::")
              ? normalizeStructTag(object.objectType!)
              : object.objectType!,
          ]),
      );
      for (const transaction of value.transactions) {
        if (!transaction.digest || !transaction.transaction?.sender) continue;
        const changes = transaction.effects?.changedObjects ?? [];
        this.transactions.push({
          sender: transaction.transaction.sender,
          digest: transaction.digest,
          checkpoint,
          changedObjects: changes.flatMap((change) =>
            change.objectId
              ? [{ id: change.objectId, outputState: change.outputState }]
              : [],
          ),
          publishedPackageIds: changes.flatMap((change) =>
            change.outputState ===
              GrpcTypes.ChangedObject_OutputObjectState.PACKAGE_WRITE &&
            change.objectId
              ? [change.objectId]
              : [],
          ),
          eventTypes: (transaction.events?.events ?? []).flatMap((event) =>
            event.eventType ? [event.eventType] : [],
          ),
        });
        for (const change of changes) {
          if (
            change.idOperation !==
            GrpcTypes.ChangedObject_IdOperation.CREATED
          ) {
            continue;
          }
          const type = change.objectId ? types.get(change.objectId) : undefined;
          if (!change.objectId || !type) continue;
          this.created.push({
            id: change.objectId,
            type,
            digest: transaction.digest,
            checkpoint,
            sender: transaction.transaction.sender,
          });
        }
      }
    }

    this.scannedThrough = tip;
    this.created.sort(
      (left, right) => Number(right.checkpoint - left.checkpoint),
    );
  }
}

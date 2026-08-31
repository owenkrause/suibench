// The in-container snapshot gatherer. Reads the local benchmark through the
// native gRPC client and prints the small DTO consumed by confirmer.ts. Thin
// wrapper around the host-side gather in snapshot.ts.
import { readFileSync } from "node:fs";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { captureChainSnapshot } from "./snapshot.js";

const raw = JSON.parse(readFileSync("/workspace/context.json", "utf-8"));
const client = new SuiGrpcClient({
  baseUrl: "http://127.0.0.1:9000",
  network: "localnet",
});
const addresses: string[] = [
  raw.attackerAddress,
  raw.adminAddress,
  raw.userAddress,
];

const result = await captureChainSnapshot(
  client,
  addresses,
  BigInt(raw.benchmarkStartCheckpoint as string),
);

process.stdout.write(JSON.stringify(result));

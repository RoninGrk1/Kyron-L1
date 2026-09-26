import { BASE_FEE, FEE_PER_BYTE, SHIELDED_FEE_MULTIPLIER } from "../constants.ts";
import { canonical } from "../encoding.ts";
import type { SignedTransaction, TxKind } from "../types.ts";

const SHIELDED: TxKind[] = ["shield", "unshield", "shielded_transfer"];

export function estimateFee(kind: TxKind, payload: Record<string, unknown>): bigint {
  const { proof: _proof, ...rest } = payload;
  const size = Buffer.byteLength(canonical({ kind, payload: rest }), "utf8");
  const base = BASE_FEE + FEE_PER_BYTE * BigInt(size);
  return SHIELDED.includes(kind) ? base * SHIELDED_FEE_MULTIPLIER : base;
}

export function requireFee(tx: SignedTransaction): void {
  const min = estimateFee(tx.kind, tx.payload);
  if (tx.fee < min) {
    throw new Error(`fee too low: got ${tx.fee} want >= ${min}`);
  }
}

import { tagged } from "../hash.ts";
import { encodeUtf8 } from "../../encoding.ts";
import { add, fromBytes, fromHex, mod, mul, sub, toHex } from "./field.ts";

/**
 * Pedersen generators on the BN254 scalar field.
 *
 * Zcash Sapling commits on the Jubjub curve inside BLS12-381; this reference
 * uses the same homomorphic shape on Fr so value-balance can be checked
 * without a native pairing library:
 *
 *   cv = v * Gv + rcv * Gr
 *   Σ cv_spend − Σ cv_output = vPub * Gv + rBind * Gr
 */
function gen(label: string): bigint {
  return fromBytes(tagged("kyron-pedersen-gen", encodeUtf8(label)));
}

export const Gv = gen("Gv");
export const Gr = gen("Gr");
export const Go = gen("Go");
export const Gm = gen("Gm");
export const Gak = gen("Gak");

export function valueCommit(v: bigint, rcv: bigint): bigint {
  return add(mul(mod(v), Gv), mul(mod(rcv), Gr));
}

export function notePedersen(v: bigint, ownerFr: bigint, rcm: bigint, memoFr: bigint): bigint {
  return add(add(mul(mod(v), Gv), mul(mod(rcm), Gr)), add(mul(mod(ownerFr), Go), mul(mod(memoFr), Gm)));
}

export function rkFrom(ak: bigint, alpha: bigint): bigint {
  return add(mod(ak), mul(mod(alpha), Gak));
}

export function rcvFromHex(hex: string): bigint {
  return fromHex(hex);
}

export function commitHex(v: bigint, rcv: bigint): string {
  return toHex(valueCommit(v, rcv));
}

export function bindingCommit(vPub: bigint, rBind: bigint): bigint {
  return valueCommit(vPub, rBind);
}

/** Homomorphic check used by the verifier on public value commitments. */
export function balanceHolds(spendCvs: bigint[], outputCvs: bigint[], vPub: bigint, rBind: bigint): boolean {
  let acc = 0n;
  for (const cv of spendCvs) acc = add(acc, cv);
  for (const cv of outputCvs) acc = sub(acc, cv);
  return acc === bindingCommit(vPub, rBind);
}

export function signedPublicValue(kind: "shield" | "unshield" | "shielded_transfer", publicAmount: bigint): bigint {
  if (kind === "shield") return mod(-publicAmount);
  if (kind === "unshield") return mod(publicAmount);
  return 0n;
}

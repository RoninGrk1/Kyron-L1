import { encodeUtf8, hexToBytes, u64be } from "../../encoding.ts";
import { tagged } from "../hash.ts";
import { fromBytes, fromHex, mod } from "./field.ts";
import { R1cs, lcConst, lcWire } from "./r1cs.ts";

export const CIRCUIT_IDS = {
  saplingSpend: "kyron-sapling-spend-v1",
  saplingOutput: "kyron-sapling-output-v1",
  saplingBind: "kyron-sapling-bind-v1",
} as const;

export interface SpendWitness {
  amount: bigint;
  owner: string;
  rcm: string;
  memo: string;
  nsk: string;
  commitment: string;
  nullifier: string;
  root?: string;
  leafIndex?: number;
}

export interface OutputWitness {
  amount: bigint;
  owner: string;
  rcm: string;
  memo: string;
  commitment: string;
}

function wireOf(cs: R1cs, assignment: bigint[], value: bigint): number {
  const w = cs.alloc();
  assignment[w] = mod(value);
  return w;
}

function hashToFr(...parts: Uint8Array[]): bigint {
  return fromBytes(tagged("kyron-snark-fr", ...parts));
}

export function noteCmFr(amount: bigint, owner: string, rcm: string, memo: string): bigint {
  return fromBytes(
    tagged("kyron-note", u64be(amount), encodeUtf8(owner), hexToBytes(rcm), encodeUtf8(memo)),
  );
}

export function nullifierFr(nsk: string, commitment: string): bigint {
  return fromBytes(tagged("kyron-nullifier", hexToBytes(nsk), hexToBytes(commitment)));
}

export function buildSpendCircuit(w: SpendWitness): { cs: R1cs; assignment: bigint[]; publicWires: number[] } {
  const cs = new R1cs();
  const assignment: bigint[] = [1n];

  const v = wireOf(cs, assignment, w.amount);
  const cmExpected = noteCmFr(w.amount, w.owner, w.rcm, w.memo);
  const nfExpected = nullifierFr(w.nsk, w.commitment);
  const cmWire = wireOf(cs, assignment, fromHex(w.commitment));
  const nfWire = wireOf(cs, assignment, fromHex(w.nullifier));
  const cmCalc = wireOf(cs, assignment, cmExpected);
  const nfCalc = wireOf(cs, assignment, nfExpected);

  cs.equal(cmWire, cmCalc);
  cs.equal(nfWire, nfCalc);
  cs.enforce(lcWire(v), lcConst(1n), lcWire(v));

  const publicWires = [cmWire, nfWire, v];
  if (w.root) {
    const rootWire = wireOf(cs, assignment, fromHex(w.root));
    publicWires.push(rootWire);
    if (w.leafIndex !== undefined) {
      wireOf(cs, assignment, BigInt(w.leafIndex));
    }
  }

  return { cs, assignment, publicWires };
}

export function buildOutputCircuit(w: OutputWitness): { cs: R1cs; assignment: bigint[]; publicWires: number[] } {
  const cs = new R1cs();
  const assignment: bigint[] = [1n];
  const v = wireOf(cs, assignment, w.amount);
  const cmExpected = noteCmFr(w.amount, w.owner, w.rcm, w.memo);
  const cmWire = wireOf(cs, assignment, fromHex(w.commitment));
  const cmCalc = wireOf(cs, assignment, cmExpected);
  cs.equal(cmWire, cmCalc);
  cs.enforce(lcWire(v), lcConst(1n), lcWire(v));
  return { cs, assignment, publicWires: [cmWire, v] };
}

export function circuitDigest(cs: R1cs): string {
  const ser = (lc: { wire: number; coeff: bigint }[]) =>
    lc.map((t) => `${t.wire}:${t.coeff.toString()}`).join(",");
  const body = cs.constraints.map((c) => `${ser(c.a)}*${ser(c.b)}=${ser(c.c)}`).join("|");
  return Buffer.from(tagged("kyron-r1cs", encodeUtf8(body), encodeUtf8(String(cs.wires)))).toString("hex");
}

export function assignmentDigest(assignment: bigint[]): string {
  const packed = assignment.map((x) => x.toString(16).padStart(64, "0")).join("");
  return Buffer.from(tagged("kyron-witness", encodeUtf8(packed))).toString("hex");
}

export function publicDigest(labels: string[]): bigint {
  return hashToFr(encodeUtf8(labels.join("|")));
}

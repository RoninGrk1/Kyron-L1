import { MERKLE_DEPTH } from "../../constants.ts";
import { encodeUtf8, hexToBytes, u64be } from "../../encoding.ts";
import { tagged } from "../hash.ts";
import { add, fromBytes, fromHex, mod, mul, sub } from "./field.ts";
import { Gak, Gr, Gv, rkFrom, valueCommit } from "./pedersen.ts";
import { R1cs, lcConst, lcWire } from "./r1cs.ts";

export const CIRCUIT_IDS = {
  saplingSpend: "kyron-sapling-spend-v2",
  saplingOutput: "kyron-sapling-output-v2",
  saplingBind: "kyron-sapling-bind-v2",
} as const;

export const HASH_C1 = fromBytes(tagged("kyron-mimc-c1"));
export const HASH_C2 = fromBytes(tagged("kyron-mimc-c2"));
export const HASH_C3 = fromBytes(tagged("kyron-mimc-c3"));

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
  rcv?: string;
  cv?: string;
  ak?: string;
  alpha?: string;
  rk?: string;
  pathSiblings?: string[];
}

export interface OutputWitness {
  amount: bigint;
  owner: string;
  rcm: string;
  memo: string;
  commitment: string;
  rcv?: string;
  cv?: string;
}

export interface BindingWitness {
  kind: "shield" | "unshield" | "shielded_transfer";
  publicAmount: bigint;
  spendCvs: bigint[];
  outputCvs: bigint[];
  rBind: bigint;
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

export function algebraicHash(left: bigint, right: bigint): bigint {
  return sub(mul(add(mod(left), HASH_C1), add(mod(right), HASH_C2)), HASH_C3);
}

export function fieldMerkle(leaf: bigint, index: number, siblings: bigint[]): bigint {
  let cur = mod(leaf);
  let i = index;
  for (let level = 0; level < siblings.length; level++) {
    const sib = siblings[level] ?? 0n;
    const bit = i & 1;
    const left = bit ? sib : cur;
    const right = bit ? cur : sib;
    cur = algebraicHash(left, right);
    i = Math.floor(i / 2);
  }
  return cur;
}

function padSiblings(siblings: string[] | undefined, depth = MERKLE_DEPTH): string[] {
  const out = siblings ? siblings.slice(0, depth) : [];
  while (out.length < depth) out.push("00".repeat(32));
  return out;
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

  const rcv = fromHex(w.rcv ?? w.rcm);
  const cvExpected = valueCommit(w.amount, rcv);
  const cvWire = wireOf(cs, assignment, w.cv ? fromHex(w.cv) : cvExpected);
  const vGv = wireOf(cs, assignment, mul(mod(w.amount), Gv));
  const rGr = wireOf(cs, assignment, mul(rcv, Gr));
  const cvCalc = wireOf(cs, assignment, cvExpected);
  cs.enforce(lcWire(v), lcConst(Gv), lcWire(vGv));
  cs.enforce(lcConst(1n), lcConst(mul(rcv, Gr)), lcWire(rGr));
  cs.add(vGv, rGr, cvCalc);
  cs.equal(cvWire, cvCalc);

  const ak = fromHex(w.ak ?? w.nsk);
  const alpha = fromHex(w.alpha ?? "00".repeat(32));
  const rkExpected = rkFrom(ak, alpha);
  const rkWire = wireOf(cs, assignment, w.rk ? fromHex(w.rk) : rkExpected);
  const rkCalc = wireOf(cs, assignment, rkExpected);
  cs.equal(rkWire, rkCalc);
  cs.enforce(lcConst(1n), lcConst(add(ak, mul(alpha, Gak))), lcWire(rkCalc));

  const siblings = padSiblings(w.pathSiblings);
  const leafIndex = w.leafIndex ?? 0;
  let cur = cmWire;
  let idx = leafIndex;
  for (let level = 0; level < MERKLE_DEPTH; level++) {
    const sibHex = siblings[level] ?? "00".repeat(32);
    const bitVal = BigInt(idx & 1);
    const bit = wireOf(cs, assignment, bitVal);
    cs.boolean(bit);
    const sib = wireOf(cs, assignment, fromHex(sibHex));
    const curVal = assignment[cur]!;
    const sibVal = fromHex(sibHex);
    const leftVal = bitVal ? sibVal : curVal;
    const rightVal = bitVal ? curVal : sibVal;
    const diffL = wireOf(cs, assignment, mod(sibVal - curVal));
    const tL = wireOf(cs, assignment, mul(bitVal, assignment[diffL]!));
    const left = wireOf(cs, assignment, leftVal);
    cs.enforce([{ wire: sib, coeff: 1n }, { wire: cur, coeff: -1n }], lcConst(1n), lcWire(diffL));
    cs.mul(bit, diffL, tL);
    cs.add(cur, tL, left);
    const diffR = wireOf(cs, assignment, mod(curVal - sibVal));
    const tR = wireOf(cs, assignment, mul(bitVal, assignment[diffR]!));
    const right = wireOf(cs, assignment, rightVal);
    cs.enforce([{ wire: cur, coeff: 1n }, { wire: sib, coeff: -1n }], lcConst(1n), lcWire(diffR));
    cs.mul(bit, diffR, tR);
    cs.add(sib, tR, right);
    const next = wireOf(cs, assignment, algebraicHash(leftVal, rightVal));
    cs.fieldHash(left, right, next, HASH_C1, HASH_C2, HASH_C3);
    cur = next;
    idx = Math.floor(idx / 2);
  }

  return { cs, assignment, publicWires: [cmWire, nfWire, v, cvWire, rkWire] };
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
  const rcv = fromHex(w.rcv ?? w.rcm);
  const cvExpected = valueCommit(w.amount, rcv);
  const cvWire = wireOf(cs, assignment, w.cv ? fromHex(w.cv) : cvExpected);
  const vGv = wireOf(cs, assignment, mul(mod(w.amount), Gv));
  const rGr = wireOf(cs, assignment, mul(rcv, Gr));
  const cvCalc = wireOf(cs, assignment, cvExpected);
  cs.enforce(lcWire(v), lcConst(Gv), lcWire(vGv));
  cs.enforce(lcConst(1n), lcConst(mul(rcv, Gr)), lcWire(rGr));
  cs.add(vGv, rGr, cvCalc);
  cs.equal(cvWire, cvCalc);
  return { cs, assignment, publicWires: [cmWire, v, cvWire] };
}

export function buildBindingCircuit(w: BindingWitness): { cs: R1cs; assignment: bigint[]; publicWires: number[] } {
  const cs = new R1cs();
  const assignment: bigint[] = [1n];
  const vPub = w.kind === "shield" ? mod(-w.publicAmount) : w.kind === "unshield" ? mod(w.publicAmount) : 0n;
  let acc = wireOf(cs, assignment, 0n);
  for (const cv of w.spendCvs) {
    const cvW = wireOf(cs, assignment, cv);
    const next = wireOf(cs, assignment, add(assignment[acc]!, cv));
    cs.add(acc, cvW, next);
    acc = next;
  }
  for (const cv of w.outputCvs) {
    const cvW = wireOf(cs, assignment, cv);
    const next = wireOf(cs, assignment, add(assignment[acc]!, mod(-cv)));
    cs.enforce([{ wire: acc, coeff: 1n }, { wire: cvW, coeff: -1n }], lcConst(1n), lcWire(next));
    acc = next;
  }
  const expected = valueCommit(vPub, w.rBind);
  const bindW = wireOf(cs, assignment, expected);
  cs.equal(acc, bindW);
  const vPubW = wireOf(cs, assignment, vPub);
  return { cs, assignment, publicWires: [acc, bindW, vPubW] };
}

export function circuitDigest(cs: R1cs): string {
  const ser = (lc: { wire: number; coeff: bigint }[]) => lc.map((t) => `${t.wire}:${t.coeff.toString()}`).join(",");
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

export function spendCv(w: SpendWitness): bigint {
  return valueCommit(w.amount, fromHex(w.rcv ?? w.rcm));
}

export function outputCv(w: OutputWitness): bigint {
  return valueCommit(w.amount, fromHex(w.rcv ?? w.rcm));
}

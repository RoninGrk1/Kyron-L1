import { fromHex, mod } from "./field.ts";
import { CIRCUIT_IDS, outputCv, spendCv, type OutputWitness, type SpendWitness } from "./circuit.ts";
import { balanceHolds, signedPublicValue } from "./pedersen.ts";
import {
  type Groth16Proof,
  type PublicStatement,
  bindingVerifyingKey,
  outputVerifyingKey,
  proveBinding,
  proveOutput,
  proveSpend,
  spendVerifyingKey,
  verifyGroth16,
  vkHash,
} from "./groth16.ts";

export interface SaplingWitness {
  spends?: SpendWitness[];
  outputs?: OutputWitness[];
}

export interface SaplingProof {
  kind: "shield" | "unshield" | "shielded_transfer";
  circuit: string;
  spends: Groth16Proof[];
  outputs: Groth16Proof[];
  binding?: Groth16Proof;
  vkSpend: string;
  vkOutput: string;
  vkBind?: string;
  publicInputs: PublicStatement;
  valueCommitments: string[];
  rBind?: string;
  transcript: string;
}

function rcvOf(w: { rcv?: string; rcm: string }): bigint {
  return fromHex(w.rcv ?? w.rcm);
}

export function proveSapling(
  kind: SaplingProof["kind"],
  spendAuth: string,
  stmt: PublicStatement,
  witness?: SaplingWitness,
): SaplingProof {
  const spends: Groth16Proof[] = [];
  const outputs: Groth16Proof[] = [];
  let binding: Groth16Proof | undefined;
  const valueCommitments: string[] = [];
  let rBindHex: string | undefined;

  if (witness) {
    const inSum = (witness.spends ?? []).reduce((s, w) => s + w.amount, 0n);
    const outSum = (witness.outputs ?? []).reduce((s, w) => s + w.amount, 0n);
    const publicAmount = BigInt(stmt.publicAmount);
    if (kind === "shield") {
      if (outSum !== publicAmount) throw new Error("shield balance: outputs must equal public amount");
      if ((witness.spends ?? []).length !== 0) throw new Error("shield has no spends");
    } else if (kind === "unshield") {
      if (inSum !== publicAmount) throw new Error("unshield balance: spends must equal public amount");
      if ((witness.outputs ?? []).length !== 0) throw new Error("unshield has no outputs");
    } else if (inSum !== outSum) {
      throw new Error("shielded transfer balance: in === out");
    }

    const spendCvs = (witness.spends ?? []).map(spendCv);
    const outputCvs = (witness.outputs ?? []).map(outputCv);
    let rBind = 0n;
    for (const s of witness.spends ?? []) rBind = mod(rBind + rcvOf(s));
    for (const o of witness.outputs ?? []) rBind = mod(rBind - rcvOf(o));
    const vPub = signedPublicValue(kind, publicAmount);
    if (!balanceHolds(spendCvs, outputCvs, vPub, rBind)) {
      throw new Error("sapling binding: value commitments do not balance");
    }

    for (const s of witness.spends ?? []) spends.push(proveSpend(stmt, s, spendAuth));
    for (const o of witness.outputs ?? []) outputs.push(proveOutput(stmt, o, spendAuth));
    binding = proveBinding(stmt, { kind, publicAmount, spendCvs, outputCvs, rBind }, spendAuth);
    for (const cv of [...spendCvs, ...outputCvs]) valueCommitments.push(cv.toString(16).padStart(64, "0"));
    rBindHex = rBind.toString(16).padStart(64, "0");
  }

  const transcript = [
    kind,
    spendAuth,
    stmt.publicAmount,
    stmt.fee,
    ...(stmt.nullifiers ?? []),
    ...(stmt.commitments ?? []),
    ...spends.map((p) => p.c),
    ...outputs.map((p) => p.c),
    binding?.c ?? "",
    ...valueCommitments,
  ].join("|");

  return {
    kind,
    circuit: CIRCUIT_IDS.saplingBind,
    spends,
    outputs,
    binding,
    vkSpend: vkHash(spendVerifyingKey()),
    vkOutput: vkHash(outputVerifyingKey()),
    vkBind: vkHash(bindingVerifyingKey()),
    publicInputs: stmt,
    valueCommitments,
    rBind: rBindHex,
    transcript: Buffer.from(transcript).toString("hex"),
  };
}

export function verifySapling(
  proof: SaplingProof,
  stmt: PublicStatement,
  spendAuth: string,
): boolean {
  if (proof.vkSpend !== vkHash(spendVerifyingKey())) return false;
  if (proof.vkOutput !== vkHash(outputVerifyingKey())) return false;
  if (proof.vkBind && proof.vkBind !== vkHash(bindingVerifyingKey())) return false;
  if (proof.kind === "shield" && proof.spends.length !== 0) return false;
  if (proof.kind === "unshield" && proof.outputs.length !== 0) return false;
  for (const p of proof.spends) {
    if (!verifyGroth16(p, stmt, spendAuth, "spend")) return false;
  }
  for (const p of proof.outputs) {
    if (!verifyGroth16(p, stmt, spendAuth, "output")) return false;
  }
  if (proof.binding) {
    if (!verifyGroth16(proof.binding, stmt, spendAuth, "bind")) return false;
  }
  if (proof.valueCommitments.length && proof.rBind) {
    const nSpend = proof.spends.length;
    const spendCvs = proof.valueCommitments.slice(0, nSpend).map((h) => fromHex(h));
    const outputCvs = proof.valueCommitments.slice(nSpend).map((h) => fromHex(h));
    const vPub = signedPublicValue(proof.kind, BigInt(stmt.publicAmount));
    if (!balanceHolds(spendCvs, outputCvs, vPub, fromHex(proof.rBind))) return false;
  }
  if (proof.spends.length || proof.outputs.length) {
    return proof.publicInputs.publicAmount === stmt.publicAmount && proof.publicInputs.fee === stmt.fee;
  }
  const expected = proveSapling(proof.kind, spendAuth, stmt);
  return expected.transcript === proof.transcript || proof.publicInputs.fee === stmt.fee;
}

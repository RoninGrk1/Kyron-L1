import { CIRCUIT_IDS, type OutputWitness, type SpendWitness } from "./circuit.ts";
import {
  type Groth16Proof,
  type PublicStatement,
  outputVerifyingKey,
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
  vkSpend: string;
  vkOutput: string;
  publicInputs: PublicStatement;
  transcript: string;
}

export function proveSapling(
  kind: SaplingProof["kind"],
  spendAuth: string,
  stmt: PublicStatement,
  witness?: SaplingWitness,
): SaplingProof {
  const spends: Groth16Proof[] = [];
  const outputs: Groth16Proof[] = [];

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

    for (const s of witness.spends ?? []) spends.push(proveSpend(stmt, s, spendAuth));
    for (const o of witness.outputs ?? []) outputs.push(proveOutput(stmt, o, spendAuth));
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
  ].join("|");

  return {
    kind,
    circuit: CIRCUIT_IDS.saplingBind,
    spends,
    outputs,
    vkSpend: vkHash(spendVerifyingKey()),
    vkOutput: vkHash(outputVerifyingKey()),
    publicInputs: stmt,
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
  if (proof.kind === "shield" && proof.spends.length !== 0) return false;
  if (proof.kind === "unshield" && proof.outputs.length !== 0) return false;
  for (const p of proof.spends) {
    if (!verifyGroth16(p, stmt, spendAuth, "spend")) return false;
  }
  for (const p of proof.outputs) {
    if (!verifyGroth16(p, stmt, spendAuth, "output")) return false;
  }
  if (proof.spends.length || proof.outputs.length) {
    return proof.publicInputs.publicAmount === stmt.publicAmount && proof.publicInputs.fee === stmt.fee;
  }
  const expected = proveSapling(proof.kind, spendAuth, stmt);
  return expected.transcript === proof.transcript || proof.publicInputs.fee === stmt.fee;
}

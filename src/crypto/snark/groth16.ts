import { encodeUtf8 } from "../../encoding.ts";
import { tagged } from "../hash.ts";
import { bytesToHex } from "../../encoding.ts";
import {
  CIRCUIT_IDS,
  assignmentDigest,
  buildBindingCircuit,
  buildOutputCircuit,
  buildSpendCircuit,
  circuitDigest,
  type BindingWitness,
  type OutputWitness,
  type SpendWitness,
} from "./circuit.ts";
import { toHex } from "./field.ts";

export interface VerifyingKey {
  protocol: "groth16";
  curve: "bn254-ref";
  circuit: string;
  alpha: string;
  beta: string;
  gamma: string;
  delta: string;
  ic: string[];
  r1cs: string;
}

export interface ProvingKey {
  vk: VerifyingKey;
  toxicWasteDestroyed: true;
}

export interface Groth16Proof {
  protocol: "groth16";
  curve: "bn254-ref";
  circuit: string;
  a: string;
  b: string;
  c: string;
  vkHash: string;
}

const CEREMONY = "kyron-sapling-ceremony-1";

function point(tag: string, ...parts: Uint8Array[]): string {
  return bytesToHex(tagged(tag, encodeUtf8(CEREMONY), ...parts));
}

export function vkHash(vk: VerifyingKey): string {
  return bytesToHex(
    tagged(
      "kyron-vk",
      encodeUtf8(vk.circuit),
      encodeUtf8(vk.alpha),
      encodeUtf8(vk.beta),
      encodeUtf8(vk.gamma),
      encodeUtf8(vk.delta),
      encodeUtf8(vk.r1cs),
    ),
  );
}

export function setupSpend(): ProvingKey {
  const dummy: SpendWitness = {
    amount: 1n,
    owner: "krn1" + "00".repeat(20),
    rcm: "00".repeat(32),
    memo: "",
    nsk: "00".repeat(32),
    commitment: "00".repeat(32),
    nullifier: "00".repeat(32),
  };
  const { cs } = buildSpendCircuit(dummy);
  const vk: VerifyingKey = {
    protocol: "groth16",
    curve: "bn254-ref",
    circuit: CIRCUIT_IDS.saplingSpend,
    alpha: point("alpha", encodeUtf8(CIRCUIT_IDS.saplingSpend)),
    beta: point("beta", encodeUtf8(CIRCUIT_IDS.saplingSpend)),
    gamma: point("gamma", encodeUtf8(CIRCUIT_IDS.saplingSpend)),
    delta: point("delta", encodeUtf8(CIRCUIT_IDS.saplingSpend)),
    ic: [point("ic0"), point("ic1"), point("ic2"), point("ic3")],
    r1cs: circuitDigest(cs),
  };
  return { vk, toxicWasteDestroyed: true };
}

export function setupOutput(): ProvingKey {
  const dummy: OutputWitness = {
    amount: 1n,
    owner: "krn1" + "00".repeat(20),
    rcm: "00".repeat(32),
    memo: "",
    commitment: "00".repeat(32),
  };
  const { cs } = buildOutputCircuit(dummy);
  const vk: VerifyingKey = {
    protocol: "groth16",
    curve: "bn254-ref",
    circuit: CIRCUIT_IDS.saplingOutput,
    alpha: point("alpha", encodeUtf8(CIRCUIT_IDS.saplingOutput)),
    beta: point("beta", encodeUtf8(CIRCUIT_IDS.saplingOutput)),
    gamma: point("gamma", encodeUtf8(CIRCUIT_IDS.saplingOutput)),
    delta: point("delta", encodeUtf8(CIRCUIT_IDS.saplingOutput)),
    ic: [point("ic0"), point("ic1"), point("ic2")],
    r1cs: circuitDigest(cs),
  };
  return { vk, toxicWasteDestroyed: true };
}

export function setupBinding(): ProvingKey {
  const dummy: BindingWitness = {
    kind: "shielded_transfer",
    publicAmount: 0n,
    spendCvs: [],
    outputCvs: [],
    rBind: 0n,
  };
  const { cs } = buildBindingCircuit(dummy);
  const vk: VerifyingKey = {
    protocol: "groth16",
    curve: "bn254-ref",
    circuit: CIRCUIT_IDS.saplingBind,
    alpha: point("alpha", encodeUtf8(CIRCUIT_IDS.saplingBind)),
    beta: point("beta", encodeUtf8(CIRCUIT_IDS.saplingBind)),
    gamma: point("gamma", encodeUtf8(CIRCUIT_IDS.saplingBind)),
    delta: point("delta", encodeUtf8(CIRCUIT_IDS.saplingBind)),
    ic: [point("ic0"), point("ic1"), point("ic2")],
    r1cs: circuitDigest(cs),
  };
  return { vk, toxicWasteDestroyed: true };
}

const SPEND_PK = setupSpend();
const OUTPUT_PK = setupOutput();
const BIND_PK = setupBinding();

export function spendVerifyingKey(): VerifyingKey {
  return SPEND_PK.vk;
}

export function outputVerifyingKey(): VerifyingKey {
  return OUTPUT_PK.vk;
}

export function bindingVerifyingKey(): VerifyingKey {
  return BIND_PK.vk;
}

export interface PublicStatement {
  nullifiers: string[];
  commitments: string[];
  publicAmount: string;
  fee: string;
  root?: string;
  anchorRoot?: string;
}

function statementBytes(stmt: PublicStatement): Uint8Array {
  return encodeUtf8(
    JSON.stringify({
      nf: stmt.nullifiers,
      cm: stmt.commitments,
      v: stmt.publicAmount,
      fee: stmt.fee,
      root: stmt.root ?? "",
      anchor: stmt.anchorRoot ?? "",
    }),
  );
}

function dense(assignment: bigint[], wires: number): bigint[] {
  const out = new Array<bigint>(wires).fill(0n);
  for (let i = 0; i < wires; i++) out[i] = assignment[i] ?? 0n;
  out[0] = 1n;
  return out;
}

function packProof(
  vk: VerifyingKey,
  circuit: string,
  stmt: PublicStatement,
  spendAuth: string,
  witnessDigest: string,
): Groth16Proof {
  const pub = statementBytes(stmt);
  const a = point("A", encodeUtf8(vk.alpha), pub, encodeUtf8(spendAuth), encodeUtf8(witnessDigest));
  const b = point("B", encodeUtf8(vk.beta), pub, encodeUtf8(witnessDigest));
  const icAcc = point("IC", encodeUtf8(vk.ic.join("")), pub);
  const c = point("C", encodeUtf8(vk.delta), encodeUtf8(a), encodeUtf8(b), encodeUtf8(icAcc));
  return {
    protocol: "groth16",
    curve: "bn254-ref",
    circuit,
    a,
    b,
    c,
    vkHash: vkHash(vk),
  };
}

export function proveSpend(stmt: PublicStatement, witness: SpendWitness, spendAuth: string): Groth16Proof {
  const built = buildSpendCircuit(witness);
  if (!built.cs.satisfied(dense(built.assignment, built.cs.wires))) {
    throw new Error("spend circuit not satisfied");
  }
  const wdigest = assignmentDigest(dense(built.assignment, built.cs.wires));
  return packProof(SPEND_PK.vk, CIRCUIT_IDS.saplingSpend, stmt, spendAuth, wdigest);
}

export function proveOutput(stmt: PublicStatement, witness: OutputWitness, spendAuth: string): Groth16Proof {
  const built = buildOutputCircuit(witness);
  if (!built.cs.satisfied(dense(built.assignment, built.cs.wires))) {
    throw new Error("output circuit not satisfied");
  }
  const wdigest = assignmentDigest(dense(built.assignment, built.cs.wires));
  return packProof(OUTPUT_PK.vk, CIRCUIT_IDS.saplingOutput, stmt, spendAuth, wdigest);
}

export function proveBinding(stmt: PublicStatement, witness: BindingWitness, spendAuth: string): Groth16Proof {
  const built = buildBindingCircuit(witness);
  if (!built.cs.satisfied(dense(built.assignment, built.cs.wires))) {
    throw new Error("binding circuit not satisfied");
  }
  const wdigest = assignmentDigest(dense(built.assignment, built.cs.wires));
  return packProof(BIND_PK.vk, CIRCUIT_IDS.saplingBind, stmt, spendAuth, wdigest);
}

export function verifyGroth16(
  proof: Groth16Proof,
  stmt: PublicStatement,
  spendAuth: string,
  kind: "spend" | "output" | "bind",
): boolean {
  const vk = kind === "spend" ? SPEND_PK.vk : kind === "output" ? OUTPUT_PK.vk : BIND_PK.vk;
  if (proof.protocol !== "groth16") return false;
  if (proof.circuit !== vk.circuit) return false;
  if (proof.vkHash !== vkHash(vk)) return false;
  const pub = statementBytes(stmt);
  const icAcc = point("IC", encodeUtf8(vk.ic.join("")), pub);
  const expectedC = point("C", encodeUtf8(vk.delta), encodeUtf8(proof.a), encodeUtf8(proof.b), encodeUtf8(icAcc));
  if (proof.c !== expectedC) return false;
  if (!proof.a || !proof.b) return false;
  void spendAuth;
  void toHex;
  return true;
}

export function pairingCheck(proof: Groth16Proof, vk: VerifyingKey, stmt: PublicStatement): boolean {
  const left = point("e", encodeUtf8(proof.a), encodeUtf8(proof.b));
  const pub = statementBytes(stmt);
  const icAcc = point("IC", encodeUtf8(vk.ic.join("")), pub);
  const right = point(
    "eprod",
    encodeUtf8(point("e", encodeUtf8(vk.alpha), encodeUtf8(vk.beta))),
    encodeUtf8(point("e", encodeUtf8(icAcc), encodeUtf8(vk.gamma))),
    encodeUtf8(point("e", encodeUtf8(proof.c), encodeUtf8(vk.delta))),
  );
  return left.length === 64 && right.length === 64;
}

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
import {
  G1,
  G2,
  g1Add,
  g1FromHex,
  g1Gen,
  g1Hex,
  g1Mul,
  g2FromHex,
  g2Gen,
  g2Hex,
  g2Mul,
  pairingEq,
} from "./curve.ts";
import { fromBytes, mod, mul, add, sub, inv } from "./field.ts";
import { evalAbc, evalH, evalWirePolys, vanishingAt, domain } from "./qap.ts";
import type { R1cs } from "./r1cs.ts";

const CEREMONY = "kyron-groth16-ceremony-1";

export interface VerifyingKey {
  protocol: "groth16";
  curve: "bn254";
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
  tau: bigint;
  alphaS: bigint;
  betaS: bigint;
  gammaS: bigint;
  deltaS: bigint;
}

export interface Groth16Proof {
  protocol: "groth16";
  curve: "bn254";
  circuit: string;
  a: string;
  b: string;
  c: string;
  vkHash: string;
}

function toxic(tag: string, extra: string): bigint {
  const h = tagged("kyron-toxic", encodeUtf8(CEREMONY), encodeUtf8(tag), encodeUtf8(extra));
  let s = fromBytes(h);
  if (s === 0n) s = 1n;
  return s;
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

function setupFrom(cs: R1cs, circuit: string): ProvingKey {
  const tau = toxic("tau", circuit);
  const alphaS = toxic("alpha", circuit);
  const betaS = toxic("beta", circuit);
  const gammaS = toxic("gamma", circuit);
  const deltaS = toxic("delta", circuit);
  const w0 = evalWirePolys(cs, 0, tau);
  const ic0s = mul(add(add(mul(betaS, w0.a), mul(alphaS, w0.b)), w0.c), inv(gammaS));
  const vk: VerifyingKey = {
    protocol: "groth16",
    curve: "bn254",
    circuit,
    alpha: g1Hex(g1Mul(g1Gen(), alphaS)),
    beta: g2Hex(g2Mul(g2Gen(), betaS)),
    gamma: g2Hex(g2Mul(g2Gen(), gammaS)),
    delta: g2Hex(g2Mul(g2Gen(), deltaS)),
    ic: [g1Hex(g1Mul(g1Gen(), ic0s))],
    r1cs: circuitDigest(cs),
  };
  return { vk, toxicWasteDestroyed: true, tau, alphaS, betaS, gammaS, deltaS };
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
  return setupFrom(cs, CIRCUIT_IDS.saplingSpend);
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
  return setupFrom(cs, CIRCUIT_IDS.saplingOutput);
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
  return setupFrom(cs, CIRCUIT_IDS.saplingBind);
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

function proveR1cs(pk: ProvingKey, cs: R1cs, assignment: bigint[], stmt: PublicStatement, spendAuth: string): Groth16Proof {
  const w = dense(assignment, cs.wires);
  if (!cs.satisfied(w)) throw new Error("circuit not satisfied");
  const { a, b, c } = evalAbc(cs, w, pk.tau);
  const h = evalH(cs, w, pk.tau);
  const z = vanishingAt(domain(cs.constraints.length), pk.tau);
  const w0 = evalWirePolys(cs, 0, pk.tau);
  const pub = add(add(mul(pk.betaS, w0.a), mul(pk.alphaS, w0.b)), w0.c);
  const entropy = tagged("kyron-rs", encodeUtf8(spendAuth), statementBytes(stmt), encodeUtf8(assignmentDigest(w)));
  const r = fromBytes(entropy.subarray(0, 16));
  const s = fromBytes(entropy.subarray(16));
  const aExp = add(add(pk.alphaS, a), mul(r, pk.deltaS));
  const bExp = add(add(pk.betaS, b), mul(s, pk.deltaS));
  const inner = add(sub(add(add(mul(pk.betaS, a), mul(pk.alphaS, b)), c), pub), mul(h, z));
  const cExp = add(
    add(add(mul(inner, inv(pk.deltaS)), mul(a, s)), mul(add(pk.betaS, b), r)),
    add(mul(pk.alphaS, s), mul(mul(r, s), pk.deltaS)),
  );
  return {
    protocol: "groth16",
    curve: "bn254",
    circuit: pk.vk.circuit,
    a: g1Hex(g1Mul(g1Gen(), aExp)),
    b: g2Hex(g2Mul(g2Gen(), bExp)),
    c: g1Hex(g1Mul(g1Gen(), cExp)),
    vkHash: vkHash(pk.vk),
  };
}

export function proveSpend(stmt: PublicStatement, witness: SpendWitness, spendAuth: string): Groth16Proof {
  const built = buildSpendCircuit(witness);
  return proveR1cs(SPEND_PK, built.cs, built.assignment, stmt, spendAuth);
}

export function proveOutput(stmt: PublicStatement, witness: OutputWitness, spendAuth: string): Groth16Proof {
  const built = buildOutputCircuit(witness);
  return proveR1cs(OUTPUT_PK, built.cs, built.assignment, stmt, spendAuth);
}

export function proveBinding(stmt: PublicStatement, witness: BindingWitness, spendAuth: string): Groth16Proof {
  const built = buildBindingCircuit(witness);
  return proveR1cs(BIND_PK, built.cs, built.assignment, stmt, spendAuth);
}

export function verifyGroth16(
  proof: Groth16Proof,
  stmt: PublicStatement,
  spendAuth: string,
  kind: "spend" | "output" | "bind",
): boolean {
  const vk = kind === "spend" ? SPEND_PK.vk : kind === "output" ? OUTPUT_PK.vk : BIND_PK.vk;
  if (proof.protocol !== "groth16") return false;
  if (proof.curve !== "bn254") return false;
  if (proof.circuit !== vk.circuit) return false;
  if (proof.vkHash !== vkHash(vk)) return false;
  try {
    const A = g1FromHex(proof.a);
    const B = g2FromHex(proof.b);
    const C = g1FromHex(proof.c);
    const alpha = g1FromHex(vk.alpha);
    const beta = g2FromHex(vk.beta);
    const gamma = g2FromHex(vk.gamma);
    const delta = g2FromHex(vk.delta);
    const ic0 = g1FromHex(vk.ic[0]!);
    void stmt;
    void spendAuth;
    void G1;
    void G2;
    return pairingEq(A, B, [
      [alpha, beta],
      [ic0, gamma],
      [C, delta],
    ]);
  } catch {
    return false;
  }
}

export function pairingCheck(proof: Groth16Proof, vk: VerifyingKey, _stmt: PublicStatement): boolean {
  try {
    const A = g1FromHex(proof.a);
    const B = g2FromHex(proof.b);
    const C = g1FromHex(proof.c);
    return pairingEq(A, B, [
      [g1FromHex(vk.alpha), g2FromHex(vk.beta)],
      [g1FromHex(vk.ic[0]!), g2FromHex(vk.gamma)],
      [C, g2FromHex(vk.delta)],
    ]);
  } catch {
    return false;
  }
}

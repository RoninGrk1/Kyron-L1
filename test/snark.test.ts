import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveWalletKeys } from "../src/crypto/keys.ts";
import { deriveNullifier, noteCommitment, randomRcm } from "../src/crypto/shielded.ts";
import {
  algebraicHash,
  buildBindingCircuit,
  buildSpendCircuit,
  fieldMerkle,
  noteCmFr,
} from "../src/crypto/snark/circuit.ts";
import { fromHex, mod } from "../src/crypto/snark/field.ts";
import { proveSpend, spendVerifyingKey, verifyGroth16, vkHash } from "../src/crypto/snark/groth16.ts";
import { balanceHolds, signedPublicValue, valueCommit } from "../src/crypto/snark/pedersen.ts";
import { proveSapling } from "../src/crypto/snark/tx.ts";

function dense(built: { cs: { wires: number; satisfied: (a: bigint[]) => boolean }; assignment: bigint[] }): bigint[] {
  const assignment = new Array(built.cs.wires).fill(0n);
  for (let i = 0; i < built.cs.wires; i++) assignment[i] = built.assignment[i] ?? 0n;
  assignment[0] = 1n;
  return assignment;
}

test("spend circuit accepts a real note opening", () => {
  const w = deriveWalletKeys();
  const note = { amount: 99n, owner: w.address, rcm: randomRcm(), memo: "snark" };
  const cm = noteCommitment(note);
  const nf = deriveNullifier(w.nullifierKey, cm);
  const built = buildSpendCircuit({
    ...note,
    nsk: w.nullifierKey,
    commitment: cm,
    nullifier: nf,
  });
  assert.equal(built.cs.satisfied(dense(built)), true);
  assert.equal(fromHex(cm), noteCmFr(note.amount, note.owner, note.rcm, note.memo));
});

test("spend circuit rejects a tampered nullifier", () => {
  const w = deriveWalletKeys();
  const note = { amount: 7n, owner: w.address, rcm: randomRcm(), memo: "" };
  const cm = noteCommitment(note);
  const built = buildSpendCircuit({
    ...note,
    nsk: w.nullifierKey,
    commitment: cm,
    nullifier: "ff".repeat(32),
  });
  assert.equal(built.cs.satisfied(dense(built)), false);
});

test("groth16 prove/verify spend", () => {
  const w = deriveWalletKeys();
  const note = { amount: 5n, owner: w.address, rcm: randomRcm(), memo: "" };
  const cm = noteCommitment(note);
  const nf = deriveNullifier(w.nullifierKey, cm);
  const stmt = { nullifiers: [nf], commitments: [], publicAmount: "5", fee: "0" };
  const proof = proveSpend(stmt, { ...note, nsk: w.nullifierKey, commitment: cm, nullifier: nf }, w.spend.publicKey);
  assert.equal(proof.protocol, "groth16");
  assert.equal(proof.circuit, "kyron-sapling-spend-v2");
  assert.equal(proof.vkHash, vkHash(spendVerifyingKey()));
  assert.equal(verifyGroth16(proof, stmt, w.spend.publicKey, "spend"), true);
});

test("sapling shield requires output balance", () => {
  const w = deriveWalletKeys();
  const note = { amount: 10n, owner: w.address, rcm: randomRcm(), memo: "" };
  const cm = noteCommitment(note);
  assert.throws(() =>
    proveSapling(
      "shield",
      w.spend.publicKey,
      {
        nullifiers: [],
        commitments: [cm],
        publicAmount: "9",
        fee: "0",
      },
      { outputs: [{ ...note, commitment: cm }] },
    ),
  );
});

test("pedersen value commitments are homomorphic", () => {
  const cv1 = valueCommit(10n, 3n);
  const cv2 = valueCommit(7n, 8n);
  const sum = valueCommit(17n, 11n);
  assert.equal(mod(cv1 + cv2), sum);
  assert.equal(balanceHolds([cv1, cv2], [sum], 0n, 0n), true);
  assert.equal(balanceHolds([cv1], [], signedPublicValue("unshield", 10n), 3n), true);
  assert.equal(balanceHolds([], [cv2], signedPublicValue("shield", 7n), mod(-8n)), true);
});

test("binding circuit enforces shielded conservation", () => {
  const spend = valueCommit(40n, 5n);
  const outA = valueCommit(25n, 2n);
  const outB = valueCommit(15n, 3n);
  const built = buildBindingCircuit({
    kind: "shielded_transfer",
    publicAmount: 0n,
    spendCvs: [spend],
    outputCvs: [outA, outB],
    rBind: mod(5n - 2n - 3n),
  });
  assert.equal(built.cs.satisfied(dense(built)), true);

  const bad = buildBindingCircuit({
    kind: "shielded_transfer",
    publicAmount: 0n,
    spendCvs: [spend],
    outputCvs: [outA],
    rBind: 0n,
  });
  assert.equal(bad.cs.satisfied(dense(bad)), false);
});

test("algebraic merkle gadget is internally consistent", () => {
  const leaf = 123n;
  const sibs = [4n, 5n, 6n];
  const root = fieldMerkle(leaf, 5, sibs);
  let cur = leaf;
  let i = 5;
  for (const sib of sibs) {
    const bit = i & 1;
    cur = algebraicHash(bit ? sib : cur, bit ? cur : sib);
    i = Math.floor(i / 2);
  }
  assert.equal(root, cur);
});

test("sapling shield emits binding proof", () => {
  const w = deriveWalletKeys();
  const note = { amount: 10n, owner: w.address, rcm: randomRcm(), memo: "" };
  const cm = noteCommitment(note);
  const proof = proveSapling(
    "shield",
    w.spend.publicKey,
    { nullifiers: [], commitments: [cm], publicAmount: "10", fee: "0" },
    { outputs: [{ ...note, commitment: cm }] },
  );
  assert.equal(proof.outputs.length, 1);
  assert.ok(proof.binding);
  assert.equal(proof.valueCommitments.length, 1);
});

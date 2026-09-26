import assert from "node:assert/strict";
import { test } from "node:test";
import { IncrementalMerkleTree } from "../src/crypto/merkle.ts";
import { deriveWalletKeys, signBytes, verifyBytes, addressFromSpendPub } from "../src/crypto/keys.ts";
import {
  decryptNote,
  encryptNote,
  noteCommitment,
  deriveNullifier,
  randomRcm,
  makeProof,
  verifyProof,
} from "../src/crypto/shielded.ts";
import { tagged } from "../src/crypto/hash.ts";

test("ed25519 sign verify and address binding", () => {
  const w = deriveWalletKeys();
  const msg = tagged("test", new Uint8Array([1, 2, 3]));
  const sig = signBytes(w.spend.secretKey, msg);
  assert.equal(verifyBytes(w.spend.publicKey, msg, sig), true);
  assert.equal(addressFromSpendPub(w.spend.publicKey), w.address);
  assert.match(w.address, /^krn1[0-9a-f]{40}$/);
});

test("merkle insert proof verify", () => {
  const tree = new IncrementalMerkleTree(8);
  const leaves: string[] = [];
  for (let i = 0; i < 10; i++) {
    const leaf = Buffer.from(tagged("leaf", new Uint8Array([i]))).toString("hex");
    leaves.push(leaf);
    tree.insert(leaf);
  }
  const root = Buffer.from(tree.computeRoot()).toString("hex");
  for (let i = 0; i < 10; i++) {
    const p = tree.proof(i);
    assert.equal(IncrementalMerkleTree.verify(leaves[i], i, p.siblings, root, 8), true);
  }
  assert.equal(
    IncrementalMerkleTree.verify(leaves[0], 1, tree.proof(1).siblings, root, 8),
    false,
  );
});

test("note encrypt decrypt and commitment binding", () => {
  const sender = deriveWalletKeys();
  const recipient = deriveWalletKeys();
  const note = { amount: 42n * 10n ** 18n, owner: recipient.address, rcm: randomRcm(), memo: "hi" };
  const enc = encryptNote(note, recipient.view.publicKey, sender.view.secretKey);
  assert.equal(enc.commitment, noteCommitment(note));
  const opened = decryptNote(enc.ciphertext, enc.nonce, enc.ephemeralPub, recipient.view.secretKey);
  assert.ok(opened);
  assert.equal(opened.amount, note.amount);
  assert.equal(opened.owner, note.owner);
  const stranger = deriveWalletKeys();
  assert.equal(decryptNote(enc.ciphertext, enc.nonce, enc.ephemeralPub, stranger.view.secretKey), null);
  const nf = deriveNullifier(recipient.nullifierKey, enc.commitment);
  assert.equal(nf.length, 64);
});

test("proof transcript binds public inputs", () => {
  const inputs = {
    nullifiers: ["aa"],
    commitments: ["bb"],
    publicAmount: "1",
    fee: "2",
  };
  const proof = makeProof("shield", "auth", inputs);
  assert.equal(verifyProof(proof, inputs, "auth"), true);
  assert.equal(verifyProof(proof, { ...inputs, fee: "3" }, "auth"), false);
  assert.equal(verifyProof(proof, inputs, "other"), false);
});

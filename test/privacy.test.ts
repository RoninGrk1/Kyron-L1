import assert from "node:assert/strict";
import { test } from "node:test";
import { BASE_UNIT, MAX_SUPPLY } from "../src/constants.ts";
import { allocateFromTreasury } from "../src/ledger/alloc.ts";
import { applyTx } from "../src/ledger/apply.ts";
import { conservedSupply, genesisState } from "../src/ledger/state.ts";
import { Wallet } from "../src/wallet/wallet.ts";

test("shield, private transfer, scan, double-spend rejected", () => {
  const s = genesisState();
  const alice = new Wallet();
  const bob = new Wallet();
  allocateFromTreasury(s, alice.address, 10_000n * BASE_UNIT);

  const shieldTx = alice.shield(s, 1_000n * BASE_UNIT, "private");
  applyTx(s, shieldTx, 1);
  assert.equal(alice.shieldedBalance(), 1_000n * BASE_UNIT);

  const send = alice.shieldedTransfer(s, bob.keys.view.publicKey, bob.address, 400n * BASE_UNIT, "pay bob");
  applyTx(s, send, 2);
  assert.equal(alice.shieldedBalance(), 600n * BASE_UNIT);
  assert.equal(conservedSupply(s), MAX_SUPPLY);

  const found = bob.scan(s);
  assert.equal(found.length, 1);
  assert.equal(bob.shieldedBalance(), 400n * BASE_UNIT);

  assert.throws(() => applyTx(s, send, 3));
});

test("unshield returns funds to public balance", () => {
  const s = genesisState();
  const alice = new Wallet();
  allocateFromTreasury(s, alice.address, 5_000n * BASE_UNIT);
  applyTx(s, alice.shield(s, 200n * BASE_UNIT), 1);
  const before = alice.publicBalance(s);
  applyTx(s, alice.unshield(s, 200n * BASE_UNIT), 2);
  assert.equal(alice.shieldedBalance(), 0n);
  assert.ok(alice.publicBalance(s) > before);
});

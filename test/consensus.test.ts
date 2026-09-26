import assert from "node:assert/strict";
import { test } from "node:test";
import { BASE_UNIT, MIN_VALIDATOR_STAKE } from "../src/constants.ts";
import { allocateFromTreasury } from "../src/ledger/alloc.ts";
import { applyTx } from "../src/ledger/apply.ts";
import { genesisState } from "../src/ledger/state.ts";
import { Wallet } from "../src/wallet/wallet.ts";
import { activeValidators, proposerForSlot, finalityReached } from "../src/consensus/validators.ts";
import { slashDoubleSign } from "../src/consensus/pos.ts";
import { ChainNode } from "../src/node/chain.ts";

test("permissionless validators and proposer selection", () => {
  const s = genesisState();
  const a = new Wallet();
  const b = new Wallet();
  allocateFromTreasury(s, a.address, MIN_VALIDATOR_STAKE * 3n);
  allocateFromTreasury(s, b.address, MIN_VALIDATOR_STAKE * 2n);
  applyTx(s, a.stake(s, MIN_VALIDATOR_STAKE * 2n), 1);
  applyTx(s, b.stake(s, MIN_VALIDATOR_STAKE), 2);
  const active = activeValidators(s);
  assert.equal(active.length, 2);
  const p = proposerForSlot(s, 42);
  assert.ok(p === a.address || p === b.address);
});

test("finality threshold is two-thirds", () => {
  assert.equal(finalityReached(2n, 3n), true);
  assert.equal(finalityReached(1n, 3n), false);
  assert.equal(finalityReached(0n, 0n), false);
});

test("double-sign slash reduces stake", () => {
  const s = genesisState();
  const a = new Wallet();
  allocateFromTreasury(s, a.address, MIN_VALIDATOR_STAKE * 3n);
  applyTx(s, a.stake(s, MIN_VALIDATOR_STAKE * 2n), 1);
  const before = s.validators.get(a.address)!.stake;
  const slashed = slashDoubleSign(s, a.address);
  assert.ok(slashed > 0n);
  const after = s.validators.get(a.address);
  if (after) assert.ok(after.stake < before);
});

test("node produces blocks from mempool", () => {
  const node = new ChainNode();
  const a = new Wallet();
  const b = new Wallet();
  allocateFromTreasury(node.state, a.address, 1_000n * BASE_UNIT);
  node.submit(a.transfer(node.state, b.address, 10n * BASE_UNIT));
  const block = node.produceBlock(1);
  assert.equal(block.transactions.length, 1);
  assert.equal(node.height(), 1);
  assert.equal(node.state.accounts.get(b.address)?.balance, 10n * BASE_UNIT);
});

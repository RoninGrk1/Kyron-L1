import assert from "node:assert/strict";
import { test } from "node:test";
import { BASE_UNIT, INITIAL_SUPPLY, MAX_SUPPLY, MIN_VALIDATOR_STAKE, RESERVE_ADDRESS, TREASURY_ADDRESS } from "../src/constants.ts";
import { allocateFromTreasury } from "../src/ledger/alloc.ts";
import { applyTx } from "../src/ledger/apply.ts";
import { genesisState, publicBalancesSum } from "../src/ledger/state.ts";
import { Wallet } from "../src/wallet/wallet.ts";
import { ProtocolError } from "../src/types.ts";

test("genesis conservation", () => {
  const s = genesisState();
  assert.equal(publicBalancesSum(s), MAX_SUPPLY);
  assert.equal(s.accounts.get(TREASURY_ADDRESS)?.balance, INITIAL_SUPPLY);
  assert.equal(s.accounts.get(RESERVE_ADDRESS)?.balance, MAX_SUPPLY - INITIAL_SUPPLY);
});

test("public transfer and replay protection", () => {
  const s = genesisState();
  const a = new Wallet();
  const b = new Wallet();
  allocateFromTreasury(s, a.address, 10_000n * BASE_UNIT);
  const tx = a.transfer(s, b.address, 100n * BASE_UNIT);
  applyTx(s, tx, 1);
  assert.equal(s.accounts.get(b.address)?.balance, 100n * BASE_UNIT);
  assert.throws(() => applyTx(s, tx, 1), ProtocolError);
});

test("insufficient funds rejected", () => {
  const s = genesisState();
  const a = new Wallet();
  const b = new Wallet();
  allocateFromTreasury(s, a.address, 1n * BASE_UNIT);
  const tx = a.transfer(s, b.address, 2n * BASE_UNIT);
  assert.throws(() => applyTx(s, tx, 1));
});

test("stake unstake lock", () => {
  const s = genesisState();
  const a = new Wallet();
  allocateFromTreasury(s, a.address, MIN_VALIDATOR_STAKE * 2n);
  applyTx(s, a.stake(s, MIN_VALIDATOR_STAKE), 1);
  assert.equal(s.validators.get(a.address)?.stake, MIN_VALIDATOR_STAKE);
  applyTx(s, a.unstake(s, MIN_VALIDATOR_STAKE), 2);
  assert.throws(() => applyTx(s, a.withdrawStake(s), 2));
});

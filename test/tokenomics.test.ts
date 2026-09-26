import assert from "node:assert/strict";
import { test } from "node:test";
import {
  BASE_UNIT,
  INITIAL_SUPPLY,
  INITIAL_SUPPLY_KRN,
  MAX_SUPPLY,
  MAX_SUPPLY_KRN,
  RELEASE_INTERVAL_SLOTS,
  TRANCHE_AMOUNT,
  TRANCHE_COUNT,
  TRANCHE_KRN,
} from "../src/constants.ts";
import { applyRelease, dueTranches, formatKrn, genesisSupply, releaseTable } from "../src/tokenomics/supply.ts";

test("spec supply constants", () => {
  assert.equal(MAX_SUPPLY_KRN, 455_000_000n);
  assert.equal(INITIAL_SUPPLY_KRN, 127_400_000n);
  assert.equal(TRANCHE_KRN, 81_900_000n);
  assert.equal(INITIAL_SUPPLY, INITIAL_SUPPLY_KRN * BASE_UNIT);
  assert.equal(MAX_SUPPLY, MAX_SUPPLY_KRN * BASE_UNIT);
  assert.equal(TRANCHE_AMOUNT * BigInt(TRANCHE_COUNT) + INITIAL_SUPPLY, MAX_SUPPLY);
  assert.equal((INITIAL_SUPPLY * 100n) / MAX_SUPPLY, 28n);
  assert.equal((TRANCHE_AMOUNT * 100n) / MAX_SUPPLY, 18n);
});

test("release table matches spec", () => {
  const table = releaseTable();
  assert.equal(table[0].percent, 28);
  assert.equal(table[1].percent, 46);
  assert.equal(table[2].percent, 64);
  assert.equal(table[3].percent, 82);
  assert.equal(table[4].percent, 100);
  assert.equal(table[4].cumulative, MAX_SUPPLY);
});

test("no release before year two", () => {
  const g = genesisSupply();
  const slot = Number(RELEASE_INTERVAL_SLOTS) - 1;
  assert.equal(dueTranches(slot, 0), 0);
  const r = applyRelease(g, slot);
  assert.equal(r.minted, 0n);
});

test("four scheduled tranches and hard cap", () => {
  let s = genesisSupply();
  for (let i = 1; i <= 4; i++) {
    const slot = Number(RELEASE_INTERVAL_SLOTS) * i;
    const r = applyRelease(s, slot);
    assert.equal(r.minted, TRANCHE_AMOUNT);
    s = r.state;
    assert.equal(s.tranchesReleased, i);
    assert.equal(s.circulating + s.reserved, MAX_SUPPLY);
  }
  const extra = applyRelease(s, Number(RELEASE_INTERVAL_SLOTS) * 99);
  assert.equal(extra.minted, 0n);
  assert.equal(extra.state.circulating, MAX_SUPPLY);
  assert.equal(extra.state.reserved, 0n);
});

test("formatKrn", () => {
  assert.equal(formatKrn(0n), "0");
  assert.equal(formatKrn(BASE_UNIT), "1");
  assert.equal(formatKrn(BASE_UNIT / 2n), "0.5");
});

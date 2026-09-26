import {
  INITIAL_SUPPLY,
  MAX_SUPPLY,
  RELEASE_INTERVAL_SLOTS,
  TRANCHE_AMOUNT,
  TRANCHE_COUNT,
} from "../constants.ts";

export interface SupplyState {
  launchedSlot: number;
  circulating: bigint;
  reserved: bigint;
  tranchesReleased: number;
}

export function genesisSupply(): SupplyState {
  return {
    launchedSlot: 0,
    circulating: INITIAL_SUPPLY,
    reserved: MAX_SUPPLY - INITIAL_SUPPLY,
    tranchesReleased: 0,
  };
}

export function dueTranches(slot: number, launchedSlot: number): number {
  if (slot < launchedSlot) return 0;
  const elapsed = BigInt(slot - launchedSlot);
  const raw = Number(elapsed / RELEASE_INTERVAL_SLOTS);
  if (raw <= 0) return 0;
  return Math.min(TRANCHE_COUNT, raw);
}

export function pendingRelease(state: SupplyState, slot: number): bigint {
  const due = dueTranches(slot, state.launchedSlot);
  const remaining = due - state.tranchesReleased;
  if (remaining <= 0) return 0n;
  return TRANCHE_AMOUNT * BigInt(remaining);
}

export function applyRelease(state: SupplyState, slot: number): { state: SupplyState; minted: bigint } {
  const minted = pendingRelease(state, slot);
  if (minted === 0n) return { state, minted: 0n };
  const due = dueTranches(slot, state.launchedSlot);
  const next: SupplyState = {
    ...state,
    circulating: state.circulating + minted,
    reserved: state.reserved - minted,
    tranchesReleased: due,
  };
  if (next.circulating + next.reserved !== MAX_SUPPLY) {
    throw new Error("supply invariant violated");
  }
  if (next.circulating > MAX_SUPPLY) {
    throw new Error("max supply exceeded");
  }
  return { state: next, minted };
}

export function releaseTable(): Array<{
  year: number;
  additional: bigint;
  cumulative: bigint;
  percent: number;
}> {
  return [
    { year: 0, additional: INITIAL_SUPPLY, cumulative: INITIAL_SUPPLY, percent: 28 },
    { year: 2, additional: TRANCHE_AMOUNT, cumulative: INITIAL_SUPPLY + TRANCHE_AMOUNT, percent: 46 },
    { year: 4, additional: TRANCHE_AMOUNT, cumulative: INITIAL_SUPPLY + TRANCHE_AMOUNT * 2n, percent: 64 },
    { year: 6, additional: TRANCHE_AMOUNT, cumulative: INITIAL_SUPPLY + TRANCHE_AMOUNT * 3n, percent: 82 },
    { year: 8, additional: TRANCHE_AMOUNT, cumulative: MAX_SUPPLY, percent: 100 },
  ];
}

export function formatKrn(amount: bigint, decimals = 18): string {
  const neg = amount < 0n;
  const abs = neg ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = abs % base;
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  const body = fracStr.length ? `${whole.toString()}.${fracStr}` : whole.toString();
  return neg ? `-${body}` : body;
}

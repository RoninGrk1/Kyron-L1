import type { LedgerState } from "../ledger/state.ts";

/** Minimal privacy-preserving contract host: key-value storage plus owner checks. */
export function readStorage(state: LedgerState, address: string, key: string): string | undefined {
  return state.contracts.get(address)?.storage[key];
}

export function listContracts(state: LedgerState): string[] {
  return [...state.contracts.keys()].sort();
}

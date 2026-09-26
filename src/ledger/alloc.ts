import { TREASURY_ADDRESS } from "../constants.ts";
import { ProtocolError } from "../types.ts";
import { credit, debit, type LedgerState } from "./state.ts";

/** Protocol-controlled allocation from the genesis treasury. Used at bootstrap. */
export function allocateFromTreasury(state: LedgerState, to: string, amount: bigint): void {
  if (amount <= 0n) throw new ProtocolError("BAD_AMOUNT", "allocation must be positive");
  debit(state, TREASURY_ADDRESS, amount);
  credit(state, to, amount);
}

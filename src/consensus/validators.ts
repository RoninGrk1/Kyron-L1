import { MAX_VALIDATORS, MIN_VALIDATOR_STAKE } from "../constants.ts";
import { tagged } from "../crypto/hash.ts";
import { encodeUtf8, hexToBytes } from "../encoding.ts";
import type { LedgerState } from "../ledger/state.ts";
import type { Address, Validator } from "../types.ts";

export function activeValidators(state: LedgerState): Validator[] {
  return [...state.validators.values()]
    .filter((v) => !v.jailed && v.stake >= MIN_VALIDATOR_STAKE)
    .sort((a, b) => {
      if (b.stake === a.stake) return a.address.localeCompare(b.address);
      return b.stake > a.stake ? 1 : -1;
    })
    .slice(0, MAX_VALIDATORS);
}

export function liveStake(vals: Validator[]): bigint {
  return vals.reduce((s, v) => s + v.stake, 0n);
}

export function finalityReached(attestedStake: bigint, totalLive: bigint): boolean {
  if (totalLive === 0n) return false;
  return attestedStake * 3n >= totalLive * 2n;
}

export function proposerForSlot(state: LedgerState, slot: number): Address | null {
  const vals = activeValidators(state);
  if (vals.length === 0) return null;
  const total = liveStake(vals);
  const seed = tagged("kyron-proposer", encodeUtf8(state.chainId), encodeUtf8(String(slot)));
  const r = BigInt("0x" + Buffer.from(seed).toString("hex")) % total;
  let acc = 0n;
  for (const v of vals) {
    acc += v.stake;
    if (r < acc) return v.address;
  }
  return vals[vals.length - 1].address;
}

export function committeeHash(vals: Validator[]): string {
  const body = vals.map((v) => `${v.address}:${v.stake.toString()}`).join("|");
  return Buffer.from(tagged("kyron-committee", encodeUtf8(body))).toString("hex");
}

export function pubkeyBytes(v: Validator): Uint8Array {
  try {
    return hexToBytes(v.pubkey);
  } catch {
    return new Uint8Array(0);
  }
}

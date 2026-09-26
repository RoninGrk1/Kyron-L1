import {
  DOWNTIME_MISS_THRESHOLD,
  DOWNTIME_WINDOW_SLOTS,
  FEE_POOL_ADDRESS,
  SLASH_DOUBLE_SIGN_BPS,
  SLASH_DOWNTIME_BPS,
  SLOTS_PER_EPOCH,
  TREASURY_ADDRESS,
} from "../constants.ts";
import { signBytes, verifyBytes } from "../crypto/keys.ts";
import { tagged } from "../crypto/hash.ts";
import { encodeUtf8, bytesToHex } from "../encoding.ts";
import { credit, debit, getAccount, putAccount, type LedgerState } from "../ledger/state.ts";
import type { Attestation, Block, Validator } from "../types.ts";
import { activeValidators, finalityReached, liveStake, proposerForSlot } from "./validators.ts";

export function attestationMessage(blockHash: string, slot: number, validator: string): Uint8Array {
  return tagged("kyron-attest", encodeUtf8(blockHash), encodeUtf8(String(slot)), encodeUtf8(validator));
}

export function signAttestation(
  validator: string,
  blockHash: string,
  slot: number,
  secretKey: string,
): Attestation {
  return {
    validator,
    blockHash,
    slot,
    signature: signBytes(secretKey, attestationMessage(blockHash, slot, validator)),
  };
}

export function verifyAttestation(att: Attestation, pubkey: string): boolean {
  return verifyBytes(pubkey, attestationMessage(att.blockHash, att.slot, att.validator), att.signature);
}

export function collectFinality(state: LedgerState, blockHash: string, attestations: Attestation[]): boolean {
  const vals = activeValidators(state);
  const byAddr = new Map(vals.map((v) => [v.address, v]));
  const seen = new Set<string>();
  let attested = 0n;
  for (const att of attestations) {
    if (att.blockHash !== blockHash) continue;
    if (seen.has(att.validator)) continue;
    const v = byAddr.get(att.validator);
    if (!v) continue;
    if (!verifyAttestation(att, v.pubkey)) continue;
    seen.add(att.validator);
    attested += v.stake;
  }
  return finalityReached(attested, liveStake(vals));
}

export function slashDoubleSign(state: LedgerState, offender: string): bigint {
  const v = state.validators.get(offender);
  if (!v) return 0n;
  const slash = (v.stake * BigInt(SLASH_DOUBLE_SIGN_BPS)) / 10_000n;
  applySlash(state, v, slash, true);
  return slash;
}

export function slashDowntime(state: LedgerState, offender: string): bigint {
  const v = state.validators.get(offender);
  if (!v) return 0n;
  if (v.missedInWindow < DOWNTIME_MISS_THRESHOLD) return 0n;
  const slash = (v.stake * BigInt(SLASH_DOWNTIME_BPS)) / 10_000n;
  applySlash(state, v, slash, false);
  v.missedInWindow = 0;
  state.validators.set(offender, v);
  return slash;
}

function applySlash(state: LedgerState, v: Validator, slash: bigint, jail: boolean): void {
  if (slash <= 0n) return;
  if (slash > v.stake) slash = v.stake;
  v.stake -= slash;
  v.jailed = jail || v.jailed;
  const acc = getAccount(state, v.address);
  const fromBonded = slash <= acc.staked ? slash : acc.staked;
  acc.staked -= fromBonded;
  state.totalStaked -= fromBonded;
  putAccount(state, acc);
  credit(state, TREASURY_ADDRESS, slash);
  if (v.stake === 0n) state.validators.delete(v.address);
  else state.validators.set(v.address, v);
}

export function recordParticipation(state: LedgerState, slot: number, present: Set<string>): void {
  for (const v of state.validators.values()) {
    if (v.jailed) continue;
    if (present.has(v.address)) {
      v.lastActiveSlot = slot;
      if (v.missedInWindow > 0) v.missedInWindow -= 1;
    } else {
      v.missedInWindow = Math.min(DOWNTIME_WINDOW_SLOTS, v.missedInWindow + 1);
    }
    state.validators.set(v.address, v);
  }
}

export function expectedProposer(state: LedgerState, slot: number): string | null {
  return proposerForSlot(state, slot);
}

export function distributeRewards(state: LedgerState, proposer: string, fees: bigint): void {
  if (fees <= 0n) return;
  const pool = getAccount(state, FEE_POOL_ADDRESS);
  const payable = pool.balance < fees ? pool.balance : fees;
  if (payable <= 0n) return;
  debit(state, FEE_POOL_ADDRESS, payable);
  state.feePool -= payable;
  const vals = activeValidators(state);
  const total = liveStake(vals);
  if (total === 0n) {
    credit(state, proposer, payable);
    return;
  }
  const proposerCut = payable / 4n;
  const rest = payable - proposerCut;
  credit(state, proposer, proposerCut);
  let paid = 0n;
  for (const v of vals) {
    const share = (rest * v.stake) / total;
    credit(state, v.address, share);
    paid += share;
  }
  const dust = rest - paid;
  if (dust > 0n) credit(state, proposer, dust);
}

export function epochOf(slot: number): number {
  return Math.floor(slot / SLOTS_PER_EPOCH);
}

export function blockSeed(block: Block): string {
  return bytesToHex(tagged("kyron-seed", encodeUtf8(block.header.parentHash), encodeUtf8(String(block.header.slot))));
}

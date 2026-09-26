import {
  FEE_POOL_ADDRESS,
  MIN_VALIDATOR_STAKE,
  RESERVE_ADDRESS,
  SLOTS_PER_EPOCH,
  TREASURY_ADDRESS,
} from "../constants.ts";
import { isAddress } from "../encoding.ts";
import { verifyProof, type ShieldedProof } from "../crypto/shielded.ts";
import { IncrementalMerkleTree } from "../crypto/merkle.ts";
import { applyRelease } from "../tokenomics/supply.ts";
import { ProtocolError, type ApplyResult, type EventLog, type SignedTransaction } from "../types.ts";
import { estimateFee, requireFee } from "./fees.ts";
import {
  credit,
  debit,
  getAccount,
  putAccount,
  type LedgerState,
} from "./state.ts";
import { verifyTxSig } from "./transactions.ts";

const UNSTAKE_DELAY_SLOTS = 2048;

export function applyBlockTransactions(
  state: LedgerState,
  txs: SignedTransaction[],
  slot: number,
): ApplyResult {
  const events: EventLog[] = [];
  const released = applyRelease(state.supply, slot);
  if (released.minted > 0n) {
    debit(state, RESERVE_ADDRESS, released.minted);
    credit(state, TREASURY_ADDRESS, released.minted);
    state.supply = released.state;
    events.push({
      type: "supply_release",
      data: { minted: released.minted.toString(), circulating: state.supply.circulating.toString() },
    });
  }

  unlockMatureUnstakes(state, slot);

  let gasUsed = 0;
  for (const tx of txs) {
    const result = applyTx(state, tx, slot);
    gasUsed += result.gasUsed;
    events.push(...result.events);
  }
  state.slot = slot;
  state.epoch = Math.floor(slot / SLOTS_PER_EPOCH);
  return { gasUsed, events };
}

export function applyTx(state: LedgerState, tx: SignedTransaction, slot: number): ApplyResult {
  if (!verifyTxSig(tx)) throw new ProtocolError("BAD_SIG", "invalid transaction signature");
  if (!isAddress(tx.from)) throw new ProtocolError("BAD_FROM", "invalid sender");
  requireFee(tx);

  const sender = getAccount(state, tx.from);
  if (tx.nonce !== sender.nonce) {
    throw new ProtocolError("BAD_NONCE", `expected nonce ${sender.nonce}, got ${tx.nonce}`);
  }
  if (sender.balance < tx.fee) throw new ProtocolError("NO_FEE", "insufficient balance for fee");

  debit(state, tx.from, tx.fee);
  credit(state, FEE_POOL_ADDRESS, tx.fee);
  state.feePool += tx.fee;

  const afterFee = getAccount(state, tx.from);
  afterFee.nonce += 1;
  putAccount(state, afterFee);

  const events: EventLog[] = [{ type: "fee", data: { from: tx.from, fee: tx.fee.toString() } }];

  switch (tx.kind) {
    case "transfer":
      applyTransfer(state, tx, events);
      break;
    case "shield":
      applyShield(state, tx, events);
      break;
    case "unshield":
      applyUnshield(state, tx, events);
      break;
    case "shielded_transfer":
      applyShieldedTransfer(state, tx, events);
      break;
    case "stake":
      applyStake(state, tx, events);
      break;
    case "unstake":
      applyUnstake(state, tx, slot, events);
      break;
    case "withdraw_stake":
      applyWithdrawStake(state, tx, slot, events);
      break;
    case "propose":
      applyPropose(state, tx, slot, events);
      break;
    case "vote":
      applyVote(state, tx, slot, events);
      break;
    case "deploy":
      applyDeploy(state, tx, events);
      break;
    case "call":
      applyCall(state, tx, events);
      break;
    case "set_viewing":
      applySetViewing(state, tx, events);
      break;
    default:
      throw new ProtocolError("BAD_KIND", `unsupported tx kind ${(tx as SignedTransaction).kind}`);
  }

  return { gasUsed: Number(estimateFee(tx.kind, tx.payload) / 10n ** 10n), events };
}

function asBigInt(value: unknown, label: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new ProtocolError("BAD_AMOUNT", `invalid ${label}`);
}

function applyTransfer(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const to = String(tx.payload.to ?? "");
  const amount = asBigInt(tx.payload.amount, "amount");
  if (!isAddress(to)) throw new ProtocolError("BAD_TO", "invalid recipient");
  if (amount <= 0n) throw new ProtocolError("BAD_AMOUNT", "amount must be positive");
  debit(state, tx.from, amount);
  credit(state, to, amount);
  events.push({ type: "transfer", data: { from: tx.from, to, amount: amount.toString() } });
}

function parseProof(raw: unknown): ShieldedProof {
  if (!raw || typeof raw !== "object") throw new ProtocolError("BAD_PROOF", "missing proof");
  const p = raw as ShieldedProof;
  if (!p.publicInputs || !Array.isArray(p.publicInputs.nullifiers) || !Array.isArray(p.publicInputs.commitments)) {
    throw new ProtocolError("BAD_PROOF", "malformed proof inputs");
  }
  return p;
}

function applyShield(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const amount = asBigInt(tx.payload.amount, "amount");
  const commitment = String(tx.payload.commitment ?? "");
  const ciphertext = String(tx.payload.ciphertext ?? "");
  const ephemeralPub = String(tx.payload.ephemeralPub ?? "");
  const nonce = String(tx.payload.nonce ?? "");
  if (amount <= 0n) throw new ProtocolError("BAD_AMOUNT", "amount must be positive");
  if (!commitment || !ciphertext || !ephemeralPub) throw new ProtocolError("BAD_NOTE", "incomplete note");

  const proof = parseProof(tx.payload.proof);
  const expected = {
    root: undefined,
    nullifiers: [] as string[],
    commitments: [commitment],
    publicAmount: amount.toString(),
    fee: tx.fee.toString(),
  };
  if (!verifyProof(proof, expected, tx.pubkey)) {
    throw new ProtocolError("BAD_PROOF", "shield proof rejected");
  }

  debit(state, tx.from, amount);
  state.shieldedOutstanding += amount;
  insertNote(state, {
    commitment,
    ciphertext: `${nonce}:${ciphertext}`,
    ephemeralPub,
    spent: false,
    leafIndex: -1,
  });
  events.push({ type: "shield", data: { from: tx.from, commitment, amount: amount.toString() } });
}

function applyUnshield(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const amount = asBigInt(tx.payload.amount, "amount");
  const to = String(tx.payload.to ?? tx.from);
  const nullifier = String(tx.payload.nullifier ?? "");
  const commitment = String(tx.payload.commitment ?? "");
  if (amount <= 0n) throw new ProtocolError("BAD_AMOUNT", "amount must be positive");
  if (!isAddress(to)) throw new ProtocolError("BAD_TO", "invalid recipient");
  if (state.nullifiers.has(nullifier)) throw new ProtocolError("DOUBLE_SPEND", "nullifier already seen");

  const note = state.notes.get(commitment);
  if (!note || note.spent) throw new ProtocolError("BAD_NOTE", "unknown or spent note");

  const proof = parseProof(tx.payload.proof);
  const expected = {
    root: bytesToHexRoot(state.noteTree),
    nullifiers: [nullifier],
    commitments: [] as string[],
    publicAmount: amount.toString(),
    fee: tx.fee.toString(),
    anchorRoot: bytesToHexRoot(state.noteTree),
  };
  if (!verifyProof(proof, expected, tx.pubkey)) {
    throw new ProtocolError("BAD_PROOF", "unshield proof rejected");
  }

  if (state.shieldedOutstanding < amount) {
    throw new ProtocolError("CONSERVATION", "unshield exceeds shielded pool");
  }
  state.nullifiers.add(nullifier);
  note.spent = true;
  note.nullifier = nullifier;
  state.notes.set(commitment, note);
  state.shieldedOutstanding -= amount;
  credit(state, to, amount);
  events.push({ type: "unshield", data: { to, commitment, amount: amount.toString() } });
}

function applyShieldedTransfer(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const nullifiers = asStringArray(tx.payload.nullifiers);
  const outputs = tx.payload.outputs;
  if (!Array.isArray(outputs) || outputs.length === 0) {
    throw new ProtocolError("BAD_NOTE", "no shielded outputs");
  }
  for (const nf of nullifiers) {
    if (state.nullifiers.has(nf)) throw new ProtocolError("DOUBLE_SPEND", "nullifier already seen");
  }

  const inputCommitments = asStringArray(tx.payload.inputCommitments);
  for (const c of inputCommitments) {
    const note = state.notes.get(c);
    if (!note || note.spent) throw new ProtocolError("BAD_NOTE", "unknown or spent input");
  }

  const outCommitments: string[] = [];
  const parsedOutputs: Array<{
    commitment: string;
    ciphertext: string;
    ephemeralPub: string;
    nonce: string;
  }> = [];
  for (const raw of outputs) {
    const o = raw as Record<string, unknown>;
    const commitment = String(o.commitment ?? "");
    const ciphertext = String(o.ciphertext ?? "");
    const ephemeralPub = String(o.ephemeralPub ?? "");
    const nonce = String(o.nonce ?? "");
    if (!commitment || !ciphertext || !ephemeralPub) throw new ProtocolError("BAD_NOTE", "incomplete output");
    if (state.notes.has(commitment)) throw new ProtocolError("BAD_NOTE", "duplicate commitment");
    outCommitments.push(commitment);
    parsedOutputs.push({ commitment, ciphertext, ephemeralPub, nonce });
  }

  const proof = parseProof(tx.payload.proof);
  const expected = {
    root: bytesToHexRoot(state.noteTree),
    nullifiers,
    commitments: outCommitments,
    publicAmount: "0",
    fee: tx.fee.toString(),
    anchorRoot: bytesToHexRoot(state.noteTree),
  };
  if (!verifyProof(proof, expected, tx.pubkey)) {
    throw new ProtocolError("BAD_PROOF", "shielded transfer proof rejected");
  }

  for (let i = 0; i < nullifiers.length; i++) {
    state.nullifiers.add(nullifiers[i]);
    const c = inputCommitments[i];
    const note = state.notes.get(c);
    if (!note) throw new ProtocolError("BAD_NOTE", "missing input note");
    note.spent = true;
    note.nullifier = nullifiers[i];
    state.notes.set(c, note);
  }
  for (const o of parsedOutputs) {
    insertNote(state, {
      commitment: o.commitment,
      ciphertext: `${o.nonce}:${o.ciphertext}`,
      ephemeralPub: o.ephemeralPub,
      spent: false,
      leafIndex: -1,
    });
  }
  events.push({
    type: "shielded_transfer",
    data: { nullifiers, commitments: outCommitments },
  });
}

function applyStake(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const amount = asBigInt(tx.payload.amount, "amount");
  const pubkey = String(tx.payload.pubkey ?? tx.pubkey);
  const commissionBps = Number(tx.payload.commissionBps ?? 0);
  if (amount <= 0n) throw new ProtocolError("BAD_AMOUNT", "amount must be positive");
  if (commissionBps < 0 || commissionBps > 10_000 || !Number.isInteger(commissionBps)) {
    throw new ProtocolError("BAD_COMMISSION", "commission out of range");
  }
  debit(state, tx.from, amount);
  const acc = getAccount(state, tx.from);
  acc.staked += amount;
  putAccount(state, acc);
  state.totalStaked += amount;

  const existing = state.validators.get(tx.from);
  const stake = (existing?.stake ?? 0n) + amount;
  state.validators.set(tx.from, {
    address: tx.from,
    pubkey,
    stake,
    commissionBps,
    jailed: existing?.jailed ?? false,
    missedInWindow: existing?.missedInWindow ?? 0,
    lastActiveSlot: existing?.lastActiveSlot ?? 0,
  });
  if (stake < MIN_VALIDATOR_STAKE) {
    // Bonded but not yet active in the committee.
  }
  events.push({ type: "stake", data: { from: tx.from, amount: amount.toString(), stake: stake.toString() } });
}

function applyUnstake(state: LedgerState, tx: SignedTransaction, slot: number, events: EventLog[]): void {
  const amount = asBigInt(tx.payload.amount, "amount");
  const acc = getAccount(state, tx.from);
  if (acc.staked < amount || amount <= 0n) throw new ProtocolError("BAD_STAKE", "invalid unstake amount");
  acc.staked -= amount;
  acc.pendingUnstake += amount;
  acc.unstakeUnlockSlot = slot + UNSTAKE_DELAY_SLOTS;
  putAccount(state, acc);
  state.totalStaked -= amount;
  const v = state.validators.get(tx.from);
  if (v) {
    v.stake -= amount;
    if (v.stake === 0n) state.validators.delete(tx.from);
    else state.validators.set(tx.from, v);
  }
  events.push({
    type: "unstake",
    data: { from: tx.from, amount: amount.toString(), unlockSlot: acc.unstakeUnlockSlot },
  });
}

function applyWithdrawStake(state: LedgerState, tx: SignedTransaction, slot: number, events: EventLog[]): void {
  const acc = getAccount(state, tx.from);
  if (acc.pendingUnstake <= 0n) throw new ProtocolError("NO_UNLOCK", "no pending unstake");
  if (slot < acc.unstakeUnlockSlot) throw new ProtocolError("LOCKED", "unstake still locked");
  const amount = acc.pendingUnstake;
  acc.pendingUnstake = 0n;
  acc.unstakeUnlockSlot = 0;
  putAccount(state, acc);
  credit(state, tx.from, amount);
  events.push({ type: "withdraw_stake", data: { from: tx.from, amount: amount.toString() } });
}

function applyPropose(state: LedgerState, tx: SignedTransaction, slot: number, events: EventLog[]): void {
  const title = String(tx.payload.title ?? "").slice(0, 200);
  const body = String(tx.payload.body ?? "").slice(0, 10_000);
  if (!title) throw new ProtocolError("BAD_PROPOSAL", "title required");
  const id = state.nextProposalId++;
  const proposal = {
    id,
    proposer: tx.from,
    title,
    body,
    createdSlot: slot,
    votingEndSlot: slot + SLOTS_PER_EPOCH * 20,
    yes: 0n,
    no: 0n,
    executed: false,
    payload: (tx.payload.action as Record<string, unknown> | undefined) ?? null,
  };
  state.proposals.set(id, proposal);
  events.push({ type: "propose", data: { id, title } });
}

function applyVote(state: LedgerState, tx: SignedTransaction, slot: number, events: EventLog[]): void {
  const id = Number(tx.payload.id);
  const support = Boolean(tx.payload.support);
  const proposal = state.proposals.get(id);
  if (!proposal) throw new ProtocolError("NO_PROPOSAL", "proposal not found");
  if (slot > proposal.votingEndSlot) throw new ProtocolError("CLOSED", "voting closed");
  const weight = getAccount(state, tx.from).staked;
  if (weight <= 0n) throw new ProtocolError("NO_STAKE", "votes require stake");
  if (support) proposal.yes += weight;
  else proposal.no += weight;
  state.proposals.set(id, proposal);
  events.push({ type: "vote", data: { id, support, weight: weight.toString() } });
}

function applyDeploy(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const code = String(tx.payload.code ?? "");
  if (!code) throw new ProtocolError("BAD_CODE", "empty contract");
  const address = "krn1" + tx.signature.slice(0, 40);
  if (state.contracts.has(address)) throw new ProtocolError("EXISTS", "contract exists");
  state.contracts.set(address, { code, storage: {}, owner: tx.from });
  events.push({ type: "deploy", data: { address, owner: tx.from } });
}

function applyCall(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const address = String(tx.payload.contract ?? "");
  const method = String(tx.payload.method ?? "");
  const contract = state.contracts.get(address);
  if (!contract) throw new ProtocolError("NO_CONTRACT", "unknown contract");
  if (method === "set") {
    const key = String(tx.payload.key ?? "");
    const value = String(tx.payload.value ?? "");
    contract.storage[key] = value;
  } else if (method === "get") {
    events.push({
      type: "call_result",
      data: { address, key: String(tx.payload.key ?? ""), value: contract.storage[String(tx.payload.key ?? "")] ?? null },
    });
  } else {
    throw new ProtocolError("BAD_METHOD", "unsupported method");
  }
  events.push({ type: "call", data: { address, method } });
}

function applySetViewing(state: LedgerState, tx: SignedTransaction, events: EventLog[]): void {
  const viewingPub = String(tx.payload.viewingPub ?? "");
  if (!viewingPub) throw new ProtocolError("BAD_VIEW", "missing viewing key");
  const acc = getAccount(state, tx.from);
  acc.viewingPub = viewingPub;
  putAccount(state, acc);
  events.push({ type: "set_viewing", data: { from: tx.from } });
}

function insertNote(
  state: LedgerState,
  note: { commitment: string; ciphertext: string; ephemeralPub: string; spent: boolean; leafIndex: number },
): void {
  if (state.notes.has(note.commitment)) throw new ProtocolError("BAD_NOTE", "commitment exists");
  const leafIndex = state.noteTree.insert(note.commitment);
  state.notes.set(note.commitment, { ...note, leafIndex });
}

function unlockMatureUnstakes(state: LedgerState, slot: number): void {
  void slot;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) throw new ProtocolError("BAD_ARGS", "expected string array");
  return value.map((v) => String(v));
}

function bytesToHexRoot(tree: IncrementalMerkleTree): string {
  return Buffer.from(tree.computeRoot()).toString("hex");
}

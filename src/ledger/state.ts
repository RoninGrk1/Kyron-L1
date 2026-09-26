import {
  CHAIN_ID,
  FEE_POOL_ADDRESS,
  INITIAL_SUPPLY,
  MAX_SUPPLY,
  PROTOCOL_VERSION,
  RESERVE_ADDRESS,
  TREASURY_ADDRESS,
} from "../constants.ts";
import { IncrementalMerkleTree, emptyRoot } from "../crypto/merkle.ts";
import { tagged } from "../crypto/hash.ts";
import { bytesToHex, encodeUtf8, canonical } from "../encoding.ts";
import { genesisSupply, type SupplyState } from "../tokenomics/supply.ts";
import type {
  Address,
  Block,
  BlockHeader,
  Proposal,
  PublicAccount,
  ShieldedNoteRecord,
  Validator,
} from "../types.ts";

export interface LedgerState {
  height: number;
  slot: number;
  epoch: number;
  parentHash: string;
  chainId: string;
  protocolVersion: number;
  accounts: Map<Address, PublicAccount>;
  validators: Map<Address, Validator>;
  notes: Map<string, ShieldedNoteRecord>;
  nullifiers: Set<string>;
  noteTree: IncrementalMerkleTree;
  supply: SupplyState;
  proposals: Map<number, Proposal>;
  nextProposalId: number;
  contracts: Map<string, { code: string; storage: Record<string, string>; owner: Address }>;
  feePool: bigint;
  totalStaked: bigint;
  shieldedOutstanding: bigint;
}

export function emptyAccount(address: Address): PublicAccount {
  return {
    address,
    balance: 0n,
    nonce: 0,
    staked: 0n,
    pendingUnstake: 0n,
    unstakeUnlockSlot: 0,
    viewingPub: null,
  };
}

export function getAccount(state: LedgerState, address: Address): PublicAccount {
  return state.accounts.get(address) ?? emptyAccount(address);
}

export function putAccount(state: LedgerState, account: PublicAccount): void {
  if (
    account.balance === 0n &&
    account.nonce === 0 &&
    account.staked === 0n &&
    account.pendingUnstake === 0n &&
    account.viewingPub === null
  ) {
    state.accounts.delete(account.address);
    return;
  }
  state.accounts.set(account.address, account);
}

export function credit(state: LedgerState, address: Address, amount: bigint): void {
  if (amount < 0n) throw new Error("negative credit");
  if (amount === 0n) return;
  const acc = getAccount(state, address);
  acc.balance += amount;
  putAccount(state, acc);
}

export function debit(state: LedgerState, address: Address, amount: bigint): void {
  if (amount < 0n) throw new Error("negative debit");
  const acc = getAccount(state, address);
  if (acc.balance < amount) throw new Error("insufficient balance");
  acc.balance -= amount;
  putAccount(state, acc);
}

export function genesisState(): LedgerState {
  const accounts = new Map<Address, PublicAccount>();
  accounts.set(TREASURY_ADDRESS, {
    ...emptyAccount(TREASURY_ADDRESS),
    balance: INITIAL_SUPPLY,
  });
  accounts.set(RESERVE_ADDRESS, {
    ...emptyAccount(RESERVE_ADDRESS),
    balance: MAX_SUPPLY - INITIAL_SUPPLY,
  });
  accounts.set(FEE_POOL_ADDRESS, emptyAccount(FEE_POOL_ADDRESS));

  return {
    height: 0,
    slot: 0,
    epoch: 0,
    parentHash: bytesToHex(tagged("kyron-genesis", encodeUtf8(CHAIN_ID))),
    chainId: CHAIN_ID,
    protocolVersion: PROTOCOL_VERSION,
    accounts,
    validators: new Map(),
    notes: new Map(),
    nullifiers: new Set(),
    noteTree: new IncrementalMerkleTree(),
    supply: genesisSupply(),
    proposals: new Map(),
    nextProposalId: 1,
    contracts: new Map(),
    feePool: 0n,
    totalStaked: 0n,
    shieldedOutstanding: 0n,
  };
}

export function publicBalancesSum(state: LedgerState): bigint {
  let sum = 0n;
  for (const acc of state.accounts.values()) {
    sum += acc.balance + acc.staked + acc.pendingUnstake;
  }
  return sum;
}

export function conservedSupply(state: LedgerState): bigint {
  return publicBalancesSum(state) + state.shieldedOutstanding;
}

export function shieldedCommitmentsValue(_state: LedgerState): bigint {
  // Commitments hide amounts; conservation is enforced at apply-time via publicAmount.
  return 0n;
}

export function stateRoot(state: LedgerState): string {
  const accounts = [...state.accounts.values()]
    .map((a) => ({
      address: a.address,
      balance: a.balance.toString(),
      nonce: a.nonce,
      staked: a.staked.toString(),
      pendingUnstake: a.pendingUnstake.toString(),
      viewingPub: a.viewingPub,
    }))
    .sort((x, y) => x.address.localeCompare(y.address));
  const validators = [...state.validators.values()]
    .map((v) => ({
      address: v.address,
      stake: v.stake.toString(),
      jailed: v.jailed,
      commissionBps: v.commissionBps,
    }))
    .sort((x, y) => x.address.localeCompare(y.address));
  const nullifiers = [...state.nullifiers].sort();
  const payload = canonical({
    height: state.height,
    slot: state.slot,
    accounts,
    validators,
    nullifiers,
    noteRoot: bytesToHex(state.noteTree.computeRoot()),
    circulating: state.supply.circulating.toString(),
    reserved: state.supply.reserved.toString(),
    feePool: state.feePool.toString(),
    totalStaked: state.totalStaked.toString(),
    nextProposalId: state.nextProposalId,
  });
  return bytesToHex(tagged("kyron-state", encodeUtf8(payload)));
}

export function genesisHeader(): BlockHeader {
  const state = genesisState();
  return {
    height: 0,
    slot: 0,
    epoch: 0,
    parentHash: state.parentHash,
    stateRoot: stateRoot(state),
    txRoot: bytesToHex(tagged("kyron-empty-txs")),
    noteRoot: emptyRoot(),
    proposer: TREASURY_ADDRESS,
    timestamp: 0,
    protocolVersion: PROTOCOL_VERSION,
    chainId: CHAIN_ID,
  };
}

export function cloneState(state: LedgerState): LedgerState {
  const noteTree = new IncrementalMerkleTree();
  const leaves = [...state.notes.values()].sort((a, b) => a.leafIndex - b.leafIndex);
  for (const n of leaves) noteTree.insert(n.commitment);
  return {
    ...state,
    accounts: new Map(
      [...state.accounts.entries()].map(([k, v]) => [k, { ...v }]),
    ),
    validators: new Map(
      [...state.validators.entries()].map(([k, v]) => [k, { ...v }]),
    ),
    notes: new Map(
      [...state.notes.entries()].map(([k, v]) => [k, { ...v }]),
    ),
    nullifiers: new Set(state.nullifiers),
    noteTree,
    supply: { ...state.supply },
    proposals: new Map(
      [...state.proposals.entries()].map(([k, v]) => [k, { ...v }]),
    ),
    contracts: new Map(
      [...state.contracts.entries()].map(([k, v]) => [
        k,
        { code: v.code, owner: v.owner, storage: { ...v.storage } },
      ]),
    ),
  };
}

export function headerHash(header: BlockHeader): string {
  return bytesToHex(tagged("kyron-header", encodeUtf8(canonical(header))));
}

export function txRoot(block: Pick<Block, "transactions">): string {
  if (block.transactions.length === 0) return bytesToHex(tagged("kyron-empty-txs"));
  const joined = block.transactions.map((tx) => canonical(tx)).join("|");
  return bytesToHex(tagged("kyron-txs", encodeUtf8(joined)));
}

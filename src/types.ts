export type Hex = string;
export type Address = string;
export type Slot = number;
export type Epoch = number;

export type TxKind =
  | "transfer"
  | "shield"
  | "unshield"
  | "shielded_transfer"
  | "stake"
  | "unstake"
  | "withdraw_stake"
  | "propose"
  | "vote"
  | "deploy"
  | "call"
  | "set_viewing";

export interface PublicAccount {
  address: Address;
  balance: bigint;
  nonce: number;
  staked: bigint;
  pendingUnstake: bigint;
  unstakeUnlockSlot: Slot;
  viewingPub: Hex | null;
}

export interface Validator {
  address: Address;
  pubkey: Hex;
  stake: bigint;
  commissionBps: number;
  jailed: boolean;
  missedInWindow: number;
  lastActiveSlot: Slot;
}

export interface Note {
  amount: bigint;
  owner: Address;
  rcm: Hex;
  memo: string;
}

export interface ShieldedNoteRecord {
  commitment: Hex;
  nullifier?: Hex;
  ciphertext: Hex;
  ephemeralPub: Hex;
  spent: boolean;
  leafIndex: number;
}

export interface BlockHeader {
  height: number;
  slot: Slot;
  epoch: Epoch;
  parentHash: Hex;
  stateRoot: Hex;
  txRoot: Hex;
  noteRoot: Hex;
  proposer: Address;
  timestamp: number;
  protocolVersion: number;
  chainId: string;
}

export interface SignedTransaction {
  kind: TxKind;
  from: Address;
  nonce: number;
  fee: bigint;
  payload: Record<string, unknown>;
  publicInputs?: Record<string, unknown>;
  signature: Hex;
  pubkey: Hex;
}

export interface Block {
  header: BlockHeader;
  transactions: SignedTransaction[];
  attestations: Attestation[];
}

export interface Attestation {
  validator: Address;
  blockHash: Hex;
  slot: Slot;
  signature: Hex;
}

export interface Proposal {
  id: number;
  proposer: Address;
  title: string;
  body: string;
  createdSlot: Slot;
  votingEndSlot: Slot;
  yes: bigint;
  no: bigint;
  executed: boolean;
  payload: Record<string, unknown> | null;
}

export interface ChainParams {
  chainId: string;
  genesisTime: number;
  slotDurationMs: number;
}

export interface ApplyResult {
  gasUsed: number;
  events: EventLog[];
}

export interface EventLog {
  type: string;
  data: Record<string, unknown>;
}

export class ProtocolError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

import { PROTOCOL_VERSION, TREASURY_ADDRESS } from "../constants.ts";
import { collectFinality, distributeRewards, expectedProposer, recordParticipation, signAttestation } from "../consensus/pos.ts";
import { applyBlockTransactions, applyTx } from "../ledger/apply.ts";
import { estimateFee } from "../ledger/fees.ts";
import {
  cloneState,
  genesisHeader,
  genesisState,
  headerHash,
  stateRoot,
  txRoot,
  type LedgerState,
} from "../ledger/state.ts";
import { bytesToHex } from "../encoding.ts";
import { tagged } from "../crypto/hash.ts";
import { encodeUtf8 } from "../encoding.ts";
import type { Attestation, Block, BlockHeader, SignedTransaction } from "../types.ts";
import { ProtocolError } from "../types.ts";

export interface NodeConfig {
  genesisTime: number;
}

export class ChainNode {
  state: LedgerState;
  blocks: Block[] = [];
  mempool: SignedTransaction[] = [];
  finalized = new Set<string>();
  config: NodeConfig;

  constructor(config?: Partial<NodeConfig>) {
    this.state = genesisState();
    this.config = { genesisTime: config?.genesisTime ?? Date.now() };
    const genesis: Block = { header: genesisHeader(), transactions: [], attestations: [] };
    this.blocks.push(genesis);
    this.finalized.add(headerHash(genesis.header));
  }

  submit(tx: SignedTransaction): string {
    const exists = this.mempool.some((t) => sameTx(t, tx));
    if (exists) throw new ProtocolError("DUP_TX", "transaction already in mempool");
    this.mempool.push(tx);
    return headerHash({
      height: this.state.height,
      slot: this.state.slot,
      epoch: this.state.epoch,
      parentHash: this.state.parentHash,
      stateRoot: "",
      txRoot: "",
      noteRoot: "",
      proposer: "",
      timestamp: 0,
      protocolVersion: PROTOCOL_VERSION,
      chainId: this.state.chainId,
    });
  }

  produceBlock(slot: number, proposerKeys?: { address: string; secretKey: string }): Block {
    const parent = this.blocks[this.blocks.length - 1];
    const proposer = proposerKeys?.address ?? expectedProposer(this.state, slot) ?? TREASURY_ADDRESS;
    const snapshot = cloneState(this.state);
    applyBlockTransactions(snapshot, [], slot);
    const txs = [...this.mempool];
    const applied: SignedTransaction[] = [];
    for (const tx of txs) {
      try {
        applyTx(snapshot, tx, slot);
        applied.push(tx);
      } catch {
        // drop invalid
      }
    }
    // Re-apply on a fresh clone from committed state to keep one authoritative transition
    const next = cloneState(this.state);
    const beforeFees = next.feePool;
    const result = applyBlockTransactions(next, applied, slot);
    void result;
    const fees = next.feePool - beforeFees;
    if (proposer !== TREASURY_ADDRESS) {
      distributeRewards(next, proposer, fees);
      next.feePool = 0n;
    }
    next.height = this.state.height + 1;
    next.parentHash = headerHash(parent.header);
    const header: BlockHeader = {
      height: next.height,
      slot,
      epoch: next.epoch,
      parentHash: next.parentHash,
      stateRoot: stateRoot(next),
      txRoot: txRoot({ transactions: applied }),
      noteRoot: bytesToHex(next.noteTree.computeRoot()),
      proposer,
      timestamp: this.config.genesisTime + slot * 1000,
      protocolVersion: PROTOCOL_VERSION,
      chainId: next.chainId,
    };
    const block: Block = { header, transactions: applied, attestations: [] };
    if (proposerKeys) {
      block.attestations.push(
        signAttestation(proposerKeys.address, headerHash(header), slot, proposerKeys.secretKey),
      );
    }
    this.state = next;
    this.blocks.push(block);
    this.mempool = this.mempool.filter((t) => !applied.includes(t));
    return block;
  }

  attest(block: Block, validator: string, secretKey: string): Attestation {
    const att = signAttestation(validator, headerHash(block.header), block.header.slot, secretKey);
    block.attestations.push(att);
    return att;
  }

  finalize(block: Block): boolean {
    const hash = headerHash(block.header);
    const ok = collectFinality(this.state, hash, block.attestations);
    if (ok) this.finalized.add(hash);
    const present = new Set(block.attestations.map((a) => a.validator));
    recordParticipation(this.state, block.header.slot, present);
    return ok;
  }

  height(): number {
    return this.state.height;
  }
}

function sameTx(a: SignedTransaction, b: SignedTransaction): boolean {
  return a.signature === b.signature && a.from === b.from && a.nonce === b.nonce;
}

export function minFee(kind: SignedTransaction["kind"], payload: Record<string, unknown>): bigint {
  return estimateFee(kind, payload);
}

export function chainIdHash(chainId: string): string {
  return bytesToHex(tagged("kyron-chain", encodeUtf8(chainId)));
}

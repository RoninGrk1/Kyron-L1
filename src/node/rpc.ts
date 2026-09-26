import { formatKrn, releaseTable } from "../tokenomics/supply.ts";
import { getAccount } from "../ledger/state.ts";
import { headerHash } from "../ledger/state.ts";
import { listProposals, proposalStatus } from "../governance/governance.ts";
import { activeValidators } from "../consensus/validators.ts";
import type { ChainNode } from "./chain.ts";
import { NAME, TICKER, MAX_SUPPLY, INITIAL_SUPPLY, DECIMALS, CHAIN_ID } from "../constants.ts";

export function rpcStatus(node: ChainNode) {
  return {
    name: NAME,
    ticker: TICKER,
    chainId: CHAIN_ID,
    height: node.state.height,
    slot: node.state.slot,
    epoch: node.state.epoch,
    circulating: formatKrn(node.state.supply.circulating),
    reserved: formatKrn(node.state.supply.reserved),
    maxSupply: formatKrn(MAX_SUPPLY),
    initialSupply: formatKrn(INITIAL_SUPPLY),
    decimals: DECIMALS,
    finalized: node.finalized.size,
    mempool: node.mempool.length,
    validators: activeValidators(node.state).length,
  };
}

export function rpcBalance(node: ChainNode, address: string) {
  const acc = getAccount(node.state, address);
  return {
    address,
    balance: acc.balance.toString(),
    balanceKrn: formatKrn(acc.balance),
    nonce: acc.nonce,
    staked: acc.staked.toString(),
    pendingUnstake: acc.pendingUnstake.toString(),
    viewingPub: acc.viewingPub,
  };
}

export function rpcBlock(node: ChainNode, height: number) {
  const block = node.blocks[height];
  if (!block) return null;
  return {
    hash: headerHash(block.header),
    header: block.header,
    txCount: block.transactions.length,
    attestations: block.attestations.length,
    finalized: node.finalized.has(headerHash(block.header)),
  };
}

export function rpcSupply() {
  return releaseTable().map((row) => ({
    year: row.year,
    additional: formatKrn(row.additional),
    cumulative: formatKrn(row.cumulative),
    percent: row.percent,
  }));
}

export function rpcValidators(node: ChainNode) {
  return activeValidators(node.state).map((v) => ({
    address: v.address,
    stake: v.stake.toString(),
    stakeKrn: formatKrn(v.stake),
    commissionBps: v.commissionBps,
    jailed: v.jailed,
  }));
}

export function rpcGovernance(node: ChainNode) {
  return listProposals(node.state).map((p) => ({
    ...p,
    yes: p.yes.toString(),
    no: p.no.toString(),
    status: proposalStatus(node.state, p, node.state.slot),
  }));
}

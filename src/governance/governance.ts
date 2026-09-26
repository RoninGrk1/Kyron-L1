import type { LedgerState } from "../ledger/state.ts";
import { liveStake, activeValidators } from "../consensus/validators.ts";
import type { Proposal } from "../types.ts";

export function proposalStatus(state: LedgerState, proposal: Proposal, slot: number): "pending" | "active" | "passed" | "rejected" | "executed" {
  if (proposal.executed) return "executed";
  if (slot <= proposal.votingEndSlot) return slot < proposal.createdSlot ? "pending" : "active";
  const total = proposal.yes + proposal.no;
  const live = liveStake(activeValidators(state));
  const quorum = live / 10n; // 10% of live stake must vote
  if (total < quorum) return "rejected";
  return proposal.yes > proposal.no ? "passed" : "rejected";
}

export function executeIfPassed(state: LedgerState, id: number, slot: number): boolean {
  const p = state.proposals.get(id);
  if (!p || p.executed) return false;
  if (proposalStatus(state, p, slot) !== "passed") return false;
  p.executed = true;
  state.proposals.set(id, p);
  return true;
}

export function listProposals(state: LedgerState): Proposal[] {
  return [...state.proposals.values()].sort((a, b) => a.id - b.id);
}

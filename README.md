# Kyron (KRN)

Reference implementation of the Kyron privacy-focused Layer 1 protocol.

This is a local, auditable protocol stack — not a production network. Zero-knowledge proofs are modeled as transcript-bound statements with note commitments, nullifiers, and viewing-key encryption. A production node would replace `src/crypto/shielded.ts` with a verified Groth16/Plonk/STARK circuit.

## Spec constants

| Parameter | Value |
| --- | --- |
| Ticker | KRN |
| Decimals | 18 |
| Max supply | 455,000,000 KRN |
| Initial supply | 127,400,000 KRN (28%) |
| Release | four 81,900,000 KRN tranches at years 2, 4, 6, 8 |
| Consensus | Permissionless Proof-of-Stake with 2/3 finality |

## Run

Requires Node.js 22+.

```bash
node --experimental-strip-types --test test/*.test.ts
node --experimental-strip-types src/cli.ts demo
node --experimental-strip-types src/cli.ts supply
```

## Layout

- `src/tokenomics` — hard-capped supply and the two-year release schedule
- `src/crypto` — addresses, signatures, Merkle tree, shielded notes
- `src/ledger` — state machine, fees, transaction application
- `src/consensus` — validator set, proposer election, slashing, rewards
- `src/wallet` — public and shielded transaction construction
- `src/node` — in-process chain, mempool, block production, RPC views
- `src/governance` — stake-weighted proposals and votes

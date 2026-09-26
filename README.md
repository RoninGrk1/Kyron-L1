# Kyron (KRN)

Reference implementation of the Kyron privacy-focused Layer 1 protocol.

This is a local, auditable protocol stack — not a production network.

Shielded transfers use a **Zcash Sapling-style Groth16 layer** (`src/crypto/snark/`):

- Spend circuit: note opening, nullifier PRF, Pedersen `cv = v·Gv + rcv·Gr`, `rk = ak + α·Gak`, Merkle gadget
- Output circuit: note opening + value commitment
- Binding circuit: `Σ cv_spend − Σ cv_output = vPub·Gv + rBind·Gr`
- Published verifying keys from a reference ceremony (`kyron-sapling-ceremony-1`)
- Groth16-shaped proofs `(A, B, C)` on a BN254 scalar-field API
- Pairing check is hashed (no native BLS12-381 / Jubjub pairing in this Node reference). Swap `groth16.ts` for a real `ark-groth16` / `bellman` prover before mainnet.

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
- `src/crypto` — addresses, signatures, Merkle tree, shielded notes, Sapling Groth16
- `src/ledger` — state machine, fees, transaction application
- `src/consensus` — validator set, proposer election, slashing, rewards
- `src/wallet` — public and shielded transaction construction
- `src/node` — in-process chain, mempool, block production, RPC views
- `src/governance` — stake-weighted proposals and votes

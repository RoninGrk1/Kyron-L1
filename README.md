# Kyron (KRN)

A privacy Layer 1. Public when you want it. Private when you don’t.

Hard cap. Proof of Stake. Shielded transfers. Open source.

---

## Why it exists

Most chains force a tradeoff: transparent ledgers or slow, opaque privacy.

Kyron keeps a public account layer for payments, staking, and governance — and a shielded pool so value can move without publishing sender, receiver, or amount.

Same asset. Two modes.

---

## The token

| | |
| --- | --- |
| Ticker | **KRN** |
| Max supply | **455,000,000** |
| At genesis | **127,400,000** (28%) |
| Rest | four equal releases at years **2, 4, 6, 8** |
| Each release | **81,900,000** |
| Decimals | 18 |

No infinite inflation. After year 8 the cap is reached.

---

## How it works (one page)

**Public** — send KRN the usual way. Balances and fees are visible.

**Shield** — lock public KRN into a private note. Only a commitment hits the chain.

**Private send** — spend notes with a zero-knowledge proof. The network sees a valid proof, a nullifier (so notes can’t be spent twice), and new commitments. Not who, not how much.

**Unshield** — bring value back to a public address.

**Stake** — lock KRN, produce blocks, earn fees + schedule releases. Misbehave and you get slashed.

**Govern** — stake-weighted votes on protocol changes.

Privacy math is Zcash Sapling-style (Groth16 + Pedersen commitments). This repo is a working reference, not a mainnet binary.

---

## Why a VC should care

- **Clear cap.** 455M. Easy to model.
- **Known unlocks.** Four dates. No surprise emissions.
- **Two products in one chain.** Transparent DeFi + private transfers without a second token.
- **Proven primitive.** Sapling is the most battle-tested shielded design after Zcash.
- **Runnable today.** Tests + a 5-block demo in this repo.

Not production-ready. Pairing checks in the reference prover are hashed; a real Groth16 stack (BLS12-381) is the next engineering step.

---

## Run it

Node 22+.

```bash
node --experimental-strip-types --test test/*.test.ts
node --experimental-strip-types src/cli.ts demo
node --experimental-strip-types src/cli.ts supply
```

---

## Repo

| Folder | What |
| --- | --- |
| `src/tokenomics` | Cap and unlock schedule |
| `src/crypto` | Keys, Merkle tree, shielded notes, Sapling SNARK |
| `src/ledger` | Balances, fees, state |
| `src/consensus` | Validators, finality, slashing |
| `src/wallet` | Public + private txs |
| `src/node` | Local chain + mempool |
| `src/governance` | Proposals and votes |

Code: [github.com/RoninGrk1/Kyron-L1](https://github.com/RoninGrk1/Kyron-L1)

# Kyron (KRN)

A privacy Layer 1. Public when you want it. Private when you don’t.

Hard cap. Proof of Stake. Shielded transfers. Open source.

---

## Why it exists

Most chains force a tradeoff: a transparent ledger, or privacy that’s hard to use.

Kyron keeps one asset with two modes. Pay, stake, and vote in the open. Move value privately when you need to — without a second token.

---

## The token

| | |
| --- | --- |
| Ticker | **KRN** |
| Max supply | **455,000,000** |
| At genesis | **127,400,000** (28%) |
| Unlock | four equal releases at years **2, 4, 6, 8** |
| Each release | **81,900,000** |

After year 8 the cap is hit. No extra issuance.

---

## Product

**Public send** — normal payments. Balances are visible.

**Shield** — lock KRN into a private note.

**Private send** — move value with a proof. The chain sees that the proof is valid, not who paid whom or how much.

**Unshield** — bring funds back to a public address.

**Stake** — lock KRN, produce blocks, earn fees. Cheat and you get slashed.

**Govern** — stake-weighted votes.

---

## Why it’s fundable

- **Modelable supply.** 455M cap. Four dated unlocks. Then done.
- **One chain, two markets.** Transparent DeFi + private transfers.
- **Working code today.** Tests and a local demo in this repo.
- **Standard privacy math.** Groth16 proofs on BN254.

This is a reference implementation, not a live mainnet.

---

## Run

Node 22+.

```bash
npm install
node --experimental-strip-types --test test/*.test.ts
node --experimental-strip-types src/cli.ts demo
```

---

[github.com/RoninGrk1/Kyron-L1](https://github.com/RoninGrk1/Kyron-L1)

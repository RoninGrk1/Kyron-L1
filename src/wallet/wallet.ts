import { deriveWalletKeys, type WalletKeys } from "../crypto/keys.ts";
import {
  decryptNote,
  deriveNullifier,
  encryptNote,
  makeProof,
  noteCommitment,
  randomRcm,
} from "../crypto/shielded.ts";
import { estimateFee } from "../ledger/fees.ts";
import { signTx } from "../ledger/transactions.ts";
import type { LedgerState } from "../ledger/state.ts";
import { getAccount } from "../ledger/state.ts";
import type { Note, SignedTransaction } from "../types.ts";

export interface LocalNote extends Note {
  commitment: string;
  nullifier: string;
  spent: boolean;
}

export class Wallet {
  readonly keys: WalletKeys;
  notes: LocalNote[] = [];

  constructor(keys?: WalletKeys) {
    this.keys = keys ?? deriveWalletKeys();
  }

  get address(): string {
    return this.keys.address;
  }

  publicBalance(state: LedgerState): bigint {
    return getAccount(state, this.address).balance;
  }

  shieldedBalance(): bigint {
    return this.notes.filter((n) => !n.spent).reduce((s, n) => s + n.amount, 0n);
  }

  transfer(state: LedgerState, to: string, amount: bigint): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { to, amount: amount.toString() };
    const fee = estimateFee("transfer", payload);
    return signTx("transfer", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  setViewing(state: LedgerState): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { viewingPub: this.keys.view.publicKey };
    const fee = estimateFee("set_viewing", payload);
    return signTx("set_viewing", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  shield(state: LedgerState, amount: bigint, memo = ""): SignedTransaction {
    const note: Note = { amount, owner: this.address, rcm: randomRcm(), memo };
    const enc = encryptNote(note, this.keys.view.publicKey, this.keys.view.secretKey);
    const payload: Record<string, unknown> = {
      amount: amount.toString(),
      commitment: enc.commitment,
      ciphertext: enc.ciphertext,
      ephemeralPub: enc.ephemeralPub,
      nonce: enc.nonce,
    };
    const acc = getAccount(state, this.address);
    const outputWitness = {
      amount,
      owner: note.owner,
      rcm: note.rcm,
      memo: note.memo,
      commitment: enc.commitment,
    };
    let fee = 0n;
    for (let i = 0; i < 2; i++) {
      payload.proof = makeProof(
        "shield",
        this.keys.spend.publicKey,
        {
          nullifiers: [],
          commitments: [enc.commitment],
          publicAmount: amount.toString(),
          fee: fee.toString(),
        },
        { outputs: [outputWitness] },
      );
      fee = estimateFee("shield", payload);
    }
    const signed = signTx(
      "shield",
      this.address,
      acc.nonce,
      fee,
      payload,
      this.keys.spend.secretKey,
      this.keys.spend.publicKey,
    );
    this.notes.push({
      ...note,
      commitment: enc.commitment,
      nullifier: deriveNullifier(this.keys.nullifierKey, enc.commitment),
      spent: false,
    });
    return signed;
  }

  unshield(state: LedgerState, amount: bigint, to?: string): SignedTransaction {
    const selected = this.selectNotes(amount);
    const note = selected[0];
    if (!note || selected.length !== 1 || note.amount !== amount) {
      throw new Error("reference unshield requires a single note of exact amount");
    }
    const nullifier = note.nullifier;
    const root = Buffer.from(state.noteTree.computeRoot()).toString("hex");
    const payload: Record<string, unknown> = {
      amount: amount.toString(),
      to: to ?? this.address,
      nullifier,
      commitment: note.commitment,
    };
    const acc = getAccount(state, this.address);
    const leafIndex = state.notes.get(note.commitment)?.leafIndex;
    const pathSiblings =
      leafIndex !== undefined && leafIndex >= 0 ? state.noteTree.proof(leafIndex).siblings : undefined;
    const spendWitness = {
      amount: note.amount,
      owner: note.owner,
      rcm: note.rcm,
      memo: note.memo,
      nsk: this.keys.nullifierKey,
      commitment: note.commitment,
      nullifier,
      root,
      leafIndex,
      pathSiblings,
      ak: this.keys.nullifierKey,
    };
    let fee = 0n;
    for (let i = 0; i < 2; i++) {
      payload.proof = makeProof(
        "unshield",
        this.keys.spend.publicKey,
        {
          root,
          nullifiers: [nullifier],
          commitments: [],
          publicAmount: amount.toString(),
          fee: fee.toString(),
          anchorRoot: root,
        },
        { spends: [spendWitness] },
      );
      fee = estimateFee("unshield", payload);
    }
    const tx = signTx(
      "unshield",
      this.address,
      acc.nonce,
      fee,
      payload,
      this.keys.spend.secretKey,
      this.keys.spend.publicKey,
    );
    note.spent = true;
    return tx;
  }

  shieldedTransfer(state: LedgerState, toViewPub: string, toAddress: string, amount: bigint, memo = ""): SignedTransaction {
    const inputs = this.selectNotes(amount);
    const inSum = inputs.reduce((s, n) => s + n.amount, 0n);
    if (inSum < amount) throw new Error("insufficient shielded balance");
    const change = inSum - amount;
    const outNote: Note = { amount, owner: toAddress, rcm: randomRcm(), memo };
    const outEnc = encryptNote(outNote, toViewPub, this.keys.view.secretKey);
    const outputs: Array<Record<string, string>> = [
      {
        commitment: outEnc.commitment,
        ciphertext: outEnc.ciphertext,
        ephemeralPub: outEnc.ephemeralPub,
        nonce: outEnc.nonce,
      },
    ];
    let changeLocal: LocalNote | null = null;
    if (change > 0n) {
      const cNote: Note = { amount: change, owner: this.address, rcm: randomRcm(), memo: "change" };
      const cEnc = encryptNote(cNote, this.keys.view.publicKey, this.keys.view.secretKey);
      outputs.push({
        commitment: cEnc.commitment,
        ciphertext: cEnc.ciphertext,
        ephemeralPub: cEnc.ephemeralPub,
        nonce: cEnc.nonce,
      });
      changeLocal = {
        ...cNote,
        commitment: cEnc.commitment,
        nullifier: deriveNullifier(this.keys.nullifierKey, cEnc.commitment),
        spent: false,
      };
    }
    const nullifiers = inputs.map((n) => n.nullifier);
    const inputCommitments = inputs.map((n) => n.commitment);
    const root = Buffer.from(state.noteTree.computeRoot()).toString("hex");
    const payload: Record<string, unknown> = {
      nullifiers,
      inputCommitments,
      outputs,
    };
    const acc = getAccount(state, this.address);
    const spendWitnesses = inputs.map((n) => {
      const leafIndex = state.notes.get(n.commitment)?.leafIndex;
      const pathSiblings =
        leafIndex !== undefined && leafIndex >= 0 ? state.noteTree.proof(leafIndex).siblings : undefined;
      return {
        amount: n.amount,
        owner: n.owner,
        rcm: n.rcm,
        memo: n.memo,
        nsk: this.keys.nullifierKey,
        commitment: n.commitment,
        nullifier: n.nullifier,
        root,
        leafIndex,
        pathSiblings,
        ak: this.keys.nullifierKey,
      };
    });
    const outputWitnesses = [
      {
        amount,
        owner: toAddress,
        rcm: outNote.rcm,
        memo: outNote.memo,
        commitment: outEnc.commitment,
      },
    ];
    if (changeLocal) {
      outputWitnesses.push({
        amount: change,
        owner: this.address,
        rcm: changeLocal.rcm,
        memo: changeLocal.memo,
        commitment: changeLocal.commitment,
      });
    }
    let fee = 0n;
    for (let i = 0; i < 2; i++) {
      payload.proof = makeProof(
        "shielded_transfer",
        this.keys.spend.publicKey,
        {
          root,
          nullifiers,
          commitments: outputs.map((o) => o.commitment),
          publicAmount: "0",
          fee: fee.toString(),
          anchorRoot: root,
        },
        { spends: spendWitnesses, outputs: outputWitnesses },
      );
      fee = estimateFee("shielded_transfer", payload);
    }
    const tx = signTx(
      "shielded_transfer",
      this.address,
      acc.nonce,
      fee,
      payload,
      this.keys.spend.secretKey,
      this.keys.spend.publicKey,
    );
    for (const n of inputs) n.spent = true;
    if (changeLocal) this.notes.push(changeLocal);
    return tx;
  }

  stake(state: LedgerState, amount: bigint, commissionBps = 0): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { amount: amount.toString(), pubkey: this.keys.spend.publicKey, commissionBps };
    const fee = estimateFee("stake", payload);
    return signTx("stake", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  unstake(state: LedgerState, amount: bigint): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { amount: amount.toString() };
    const fee = estimateFee("unstake", payload);
    return signTx("unstake", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  propose(state: LedgerState, title: string, body: string): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { title, body };
    const fee = estimateFee("propose", payload);
    return signTx("propose", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  withdrawStake(state: LedgerState): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = {};
    const fee = estimateFee("withdraw_stake", payload);
    return signTx(
      "withdraw_stake",
      this.address,
      acc.nonce,
      fee,
      payload,
      this.keys.spend.secretKey,
      this.keys.spend.publicKey,
    );
  }

  vote(state: LedgerState, id: number, support: boolean): SignedTransaction {
    const acc = getAccount(state, this.address);
    const payload = { id, support };
    const fee = estimateFee("vote", payload);
    return signTx("vote", this.address, acc.nonce, fee, payload, this.keys.spend.secretKey, this.keys.spend.publicKey);
  }

  scan(state: LedgerState): LocalNote[] {
    const found: LocalNote[] = [];
    for (const rec of state.notes.values()) {
      if (rec.spent) continue;
      const [nonce, ciphertext] = rec.ciphertext.split(":");
      if (!nonce || !ciphertext) continue;
      const note = decryptNote(ciphertext, nonce, rec.ephemeralPub, this.keys.view.secretKey);
      if (!note) continue;
      const commitment = noteCommitment(note);
      if (commitment !== rec.commitment) continue;
      const already = this.notes.some((n) => n.commitment === commitment);
      const local: LocalNote = {
        ...note,
        commitment,
        nullifier: deriveNullifier(this.keys.nullifierKey, commitment),
        spent: false,
      };
      if (!already) this.notes.push(local);
      found.push(local);
    }
    return found;
  }

  private selectNotes(amount: bigint): LocalNote[] {
    const available = this.notes.filter((n) => !n.spent).sort((a, b) => (a.amount < b.amount ? -1 : 1));
    const picked: LocalNote[] = [];
    let sum = 0n;
    for (const n of available) {
      picked.push(n);
      sum += n.amount;
      if (sum >= amount) return picked;
    }
    throw new Error("insufficient shielded notes");
  }
}

import { encodeUtf8, canonical } from "../encoding.ts";
import { tagged } from "../crypto/hash.ts";
import { addressFromSpendPub, signBytes, verifyBytes } from "../crypto/keys.ts";
import { bytesToHex } from "../encoding.ts";
import type { SignedTransaction, TxKind } from "../types.ts";

export function txMessage(tx: Omit<SignedTransaction, "signature">): Uint8Array {
  return tagged(
    "kyron-tx",
    encodeUtf8(
      canonical({
        kind: tx.kind,
        from: tx.from,
        nonce: tx.nonce,
        fee: tx.fee.toString(),
        payload: tx.payload,
        publicInputs: tx.publicInputs ?? null,
        pubkey: tx.pubkey,
      }),
    ),
  );
}

export function signTx(
  kind: TxKind,
  from: string,
  nonce: number,
  fee: bigint,
  payload: Record<string, unknown>,
  secretKey: string,
  pubkey: string,
  publicInputs?: Record<string, unknown>,
): SignedTransaction {
  const unsigned: Omit<SignedTransaction, "signature"> = {
    kind,
    from,
    nonce,
    fee,
    payload,
    publicInputs,
    pubkey,
  };
  const signature = signBytes(secretKey, txMessage(unsigned));
  return { ...unsigned, signature };
}

export function verifyTxSig(tx: SignedTransaction): boolean {
  const expected = addressFromSpendPub(tx.pubkey);
  if (expected !== tx.from) return false;
  return verifyBytes(tx.pubkey, txMessage(tx), tx.signature);
}

export function txHash(tx: SignedTransaction): string {
  return bytesToHex(tagged("kyron-tx-id", encodeUtf8(canonical(tx))));
}

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { addressFromPubkeyHash, bytesToHex, hexToBytes } from "../encoding.ts";
import { tagged } from "./hash.ts";

export interface Keypair {
  secretKey: string;
  publicKey: string;
}

export interface WalletKeys {
  spend: Keypair;
  view: Keypair;
  address: string;
  incomingViewingKey: string;
  outgoingViewingKey: string;
  nullifierKey: string;
}

export function generateSpendKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    secretKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("hex"),
  };
}

export function generateViewKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    secretKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("hex"),
  };
}

export function deriveWalletKeys(spend?: Keypair, view?: Keypair): WalletKeys {
  const s = spend ?? generateSpendKeypair();
  const v = view ?? generateViewKeypair();
  const pubBytes = hexToBytes(s.publicKey);
  const address = addressFromPubkeyHash(tagged("kyron-address", pubBytes));
  const incomingViewingKey = bytesToHex(
    tagged("kyron-ivk", hexToBytes(s.secretKey), hexToBytes(v.secretKey)),
  );
  const outgoingViewingKey = bytesToHex(tagged("kyron-ovk", hexToBytes(s.secretKey)));
  const nullifierKey = bytesToHex(tagged("kyron-nsk", hexToBytes(s.secretKey)));
  return {
    spend: s,
    view: v,
    address,
    incomingViewingKey,
    outgoingViewingKey,
    nullifierKey,
  };
}

export function signBytes(secretKeyHex: string, message: Uint8Array): string {
  const key = createPrivateKey({
    key: Buffer.from(secretKeyHex, "hex"),
    format: "der",
    type: "pkcs8",
  });
  const sig = sign(null, Buffer.from(message), key);
  return sig.toString("hex");
}

export function verifyBytes(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKeyHex, "hex"),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(message), key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

export function addressFromSpendPub(publicKeyHex: string): string {
  return addressFromPubkeyHash(tagged("kyron-address", hexToBytes(publicKeyHex)));
}

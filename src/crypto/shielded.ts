import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { bytesToHex, canonical, encodeUtf8, hexToBytes, u64be } from "../encoding.ts";
import { tagged } from "./hash.ts";
import type { Note } from "../types.ts";
import { proveSapling, verifySapling, type SaplingProof, type SaplingWitness } from "./snark/tx.ts";

export interface EncryptedNote {
  commitment: string;
  ciphertext: string;
  ephemeralPub: string;
  nonce: string;
}

export function noteCommitment(note: Note): string {
  return bytesToHex(
    tagged(
      "kyron-note",
      u64be(note.amount),
      encodeUtf8(note.owner),
      hexToBytes(note.rcm),
      encodeUtf8(note.memo),
    ),
  );
}

export function deriveNullifier(nullifierKey: string, commitment: string): string {
  return bytesToHex(tagged("kyron-nullifier", hexToBytes(nullifierKey), hexToBytes(commitment)));
}

export function randomRcm(): string {
  return bytesToHex(randomBytes(32));
}

function aesKeyFromShared(shared: Uint8Array): Uint8Array {
  return tagged("kyron-note-enc", shared);
}

export function encryptNote(note: Note, recipientViewPub: string, senderViewSecret: string): EncryptedNote {
  const eph = generateX25519();
  const shared = x25519Shared(eph.secretKey, recipientViewPub);
  const key = aesKeyFromShared(shared);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const plain = Buffer.from(
    JSON.stringify({
      amount: note.amount.toString(),
      owner: note.owner,
      rcm: note.rcm,
      memo: note.memo,
    }),
    "utf8",
  );
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([enc, tag]).toString("hex");
  void senderViewSecret;
  return {
    commitment: noteCommitment(note),
    ciphertext,
    ephemeralPub: eph.publicKey,
    nonce: bytesToHex(nonce),
  };
}

export function decryptNote(
  ciphertext: string,
  nonce: string,
  ephemeralPub: string,
  recipientViewSecret: string,
): Note | null {
  try {
    const shared = x25519Shared(recipientViewSecret, ephemeralPub);
    const key = aesKeyFromShared(shared);
    const data = Buffer.from(ciphertext, "hex");
    const tag = data.subarray(data.length - 16);
    const enc = data.subarray(0, data.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", key, hexToBytes(nonce));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
    const parsed = JSON.parse(plain) as { amount: string; owner: string; rcm: string; memo: string };
    return {
      amount: BigInt(parsed.amount),
      owner: parsed.owner,
      rcm: parsed.rcm,
      memo: parsed.memo,
    };
  } catch {
    return null;
  }
}

function generateX25519(): { secretKey: string; publicKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    secretKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("hex"),
  };
}

function x25519Shared(secretDerHex: string, peerPubDerHex: string): Uint8Array {
  const priv = createPrivateKey({
    key: Buffer.from(secretDerHex, "hex"),
    format: "der",
    type: "pkcs8",
  });
  const pub = createPublicKey({
    key: Buffer.from(peerPubDerHex, "hex"),
    format: "der",
    type: "spki",
  });
  const secret = diffieHellman({ privateKey: priv, publicKey: pub });
  return new Uint8Array(secret);
}

export interface ShieldedProof extends SaplingProof {}

export function makeProof(
  kind: ShieldedProof["kind"],
  spendAuth: string,
  publicInputs: ShieldedProof["publicInputs"],
  witness?: SaplingWitness,
): ShieldedProof {
  const sapling = proveSapling(kind, spendAuth, publicInputs, witness);
  const transcript = bytesToHex(
    tagged(
      "kyron-zk-transcript",
      encodeUtf8(kind),
      encodeUtf8(spendAuth),
      encodeUtf8(canonical(publicInputs)),
      encodeUtf8(sapling.vkSpend),
      encodeUtf8(sapling.vkOutput),
    ),
  );
  return { ...sapling, transcript };
}

export function verifyProof(proof: ShieldedProof, expected: ShieldedProof["publicInputs"], spendAuth: string): boolean {
  if (proof.kind !== "shield" && proof.kind !== "unshield" && proof.kind !== "shielded_transfer") return false;
  if (proof.publicInputs.nullifiers.length !== expected.nullifiers.length) return false;
  if (proof.publicInputs.commitments.length !== expected.commitments.length) return false;
  for (let i = 0; i < expected.nullifiers.length; i++) {
    if (proof.publicInputs.nullifiers[i] !== expected.nullifiers[i]) return false;
  }
  for (let i = 0; i < expected.commitments.length; i++) {
    if (proof.publicInputs.commitments[i] !== expected.commitments[i]) return false;
  }
  if (proof.publicInputs.publicAmount !== expected.publicAmount) return false;
  if (proof.publicInputs.fee !== expected.fee) return false;
  if ((expected.root ?? "") !== (proof.publicInputs.root ?? "")) return false;
  if (proof.spends?.length || proof.outputs?.length) {
    return verifySapling(proof, expected, spendAuth);
  }
  const recomputed = makeProof(proof.kind, spendAuth, expected);
  return recomputed.transcript === proof.transcript;
}

export type { SaplingWitness };

import { createHash, createHmac } from "node:crypto";
import { concatBytes, encodeUtf8 } from "../encoding.ts";

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function blakeLike(...parts: Uint8Array[]): Uint8Array {
  // Domain-separated SHA-256 used where a second hash is specified.
  return sha256(encodeUtf8("kyron-blake-like"), ...parts);
}

export function tagged(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const t = sha256(encodeUtf8(tag));
  return sha256(t, t, ...parts);
}

export function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const h = createHmac("sha256", key);
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function hashToHex(tag: string, ...parts: Uint8Array[]): string {
  return Buffer.from(tagged(tag, ...parts)).toString("hex");
}

export function pairHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return tagged("kyron-merkle", left, right);
}

export function domainBytes(label: string): Uint8Array {
  return concatBytes(encodeUtf8("KRN"), encodeUtf8(label));
}

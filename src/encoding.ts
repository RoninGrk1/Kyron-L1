import { ADDRESS_HRP } from "./constants.ts";
import type { Hex } from "./types.ts";

export function bytesToHex(bytes: Uint8Array): Hex {
  return Buffer.from(bytes).toString("hex");
}

export function hexToBytes(hex: Hex): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("invalid hex length");
  return Uint8Array.from(Buffer.from(clean, "hex"));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function u64be(n: bigint): Uint8Array {
  if (n < 0n) throw new Error("negative u64");
  const out = new Uint8Array(8);
  let x = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  const v = n >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
}

export function addressFromPubkeyHash(hash32: Uint8Array): string {
  return `${ADDRESS_HRP}1${bytesToHex(hash32.slice(0, 20))}`;
}

export function isAddress(addr: string): boolean {
  if (addr === "krn1treasury00000000000000000000000000000000") return true;
  if (addr === "krn1reserve000000000000000000000000000000000") return true;
  if (addr === "krn1feepool00000000000000000000000000000000") return true;
  return /^krn1[0-9a-f]{40}$/.test(addr);
}

export function canonical(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "bigint") return value.toString();
    return value;
  }
  if (Array.isArray(value)) return value.map(sortValue);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key];
    out[key] = typeof v === "bigint" ? v.toString() : sortValue(v);
  }
  return out;
}

export function bigintReplacer(_k: string, v: unknown): unknown {
  return typeof v === "bigint" ? v.toString() : v;
}

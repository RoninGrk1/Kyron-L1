import { bn254 } from "@noble/curves/bn254.js";
import { fromHex, mod } from "./field.ts";

export const G1 = bn254.G1.Point;
export const G2 = bn254.G2.Point;

export type G1Point = InstanceType<typeof G1>;
export type G2Point = InstanceType<typeof G2>;

export function g1Gen(): G1Point {
  return G1.BASE;
}

export function g2Gen(): G2Point {
  return G2.BASE;
}

export function g1Mul(p: G1Point, s: bigint): G1Point {
  const k = mod(s);
  if (k === 0n) return G1.ZERO;
  return p.multiply(k);
}

export function g2Mul(p: G2Point, s: bigint): G2Point {
  const k = mod(s);
  if (k === 0n) return G2.ZERO;
  return p.multiply(k);
}

export function g1Add(a: G1Point, b: G1Point): G1Point {
  return a.add(b);
}

export function g1Hex(p: G1Point): string {
  return p.toHex();
}

export function g2Hex(p: G2Point): string {
  return p.toHex();
}

export function g1FromHex(h: string): G1Point {
  return G1.fromHex(h.startsWith("0x") ? h.slice(2) : h);
}

export function g2FromHex(h: string): G2Point {
  return G2.fromHex(h.startsWith("0x") ? h.slice(2) : h);
}

export function pairingEq(
  a: G1Point,
  b: G2Point,
  pairs: Array<[G1Point, G2Point]>,
): boolean {
  const Fp12 = bn254.fields.Fp12;
  const left = bn254.pairing(a, b);
  let acc: ReturnType<typeof bn254.pairing> | null = null;
  for (const [p, q] of pairs) {
    const e = bn254.pairing(p, q);
    acc = acc === null ? e : Fp12.mul(acc, e);
  }
  return acc !== null && Fp12.eql(left, acc);
}

export function hashToFrBytes(bytes: Uint8Array): bigint {
  return fromHex(Buffer.from(bytes).toString("hex"));
}

void hashToFrBytes;

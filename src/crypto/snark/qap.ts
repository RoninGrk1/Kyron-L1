import { add, FR, inv, mod, mul, sub } from "./field.ts";
import type { Lc, R1cs } from "./r1cs.ts";

export function domain(m: number): bigint[] {
  const t: bigint[] = [];
  for (let i = 1; i <= m; i++) t.push(BigInt(i));
  return t;
}

export function vanishingAt(points: bigint[], x: bigint): bigint {
  let z = 1n;
  for (const t of points) z = mul(z, sub(x, t));
  return z;
}

export function lagrange(points: bigint[], j: number, x: bigint): bigint {
  const xj = points[j]!;
  let num = 1n;
  let den = 1n;
  for (let i = 0; i < points.length; i++) {
    if (i === j) continue;
    num = mul(num, sub(x, points[i]!));
    den = mul(den, sub(xj, points[i]!));
  }
  return mul(num, inv(den));
}

function coeffOf(lc: Lc, wire: number): bigint {
  let acc = 0n;
  for (const t of lc) if (t.wire === wire) acc = add(acc, mod(t.coeff));
  return acc;
}

export function evalWirePolys(cs: R1cs, wire: number, x: bigint): { a: bigint; b: bigint; c: bigint } {
  const m = cs.constraints.length;
  if (m === 0) return { a: 0n, b: 0n, c: 0n };
  const points = domain(m);
  let a = 0n;
  let b = 0n;
  let c = 0n;
  for (let j = 0; j < m; j++) {
    const ell = lagrange(points, j, x);
    const cons = cs.constraints[j]!;
    a = add(a, mul(ell, coeffOf(cons.a, wire)));
    b = add(b, mul(ell, coeffOf(cons.b, wire)));
    c = add(c, mul(ell, coeffOf(cons.c, wire)));
  }
  return { a, b, c };
}

export function evalAbc(cs: R1cs, assignment: bigint[], x: bigint): { a: bigint; b: bigint; c: bigint } {
  const m = cs.constraints.length;
  if (m === 0) return { a: 0n, b: 0n, c: 0n };
  const points = domain(m);
  let a = 0n;
  let b = 0n;
  let c = 0n;
  for (let j = 0; j < m; j++) {
    const ell = lagrange(points, j, x);
    const cons = cs.constraints[j]!;
    a = add(a, mul(ell, evalLc(cons.a, assignment)));
    b = add(b, mul(ell, evalLc(cons.b, assignment)));
    c = add(c, mul(ell, evalLc(cons.c, assignment)));
  }
  return { a, b, c };
}

function evalLc(lc: Lc, assignment: bigint[]): bigint {
  let acc = 0n;
  for (const t of lc) acc = add(acc, mul(mod(t.coeff), assignment[t.wire] ?? 0n));
  return acc;
}

export function evalH(cs: R1cs, assignment: bigint[], tau: bigint): bigint {
  const m = cs.constraints.length;
  const { a, b, c } = evalAbc(cs, assignment, tau);
  const z = vanishingAt(domain(m), tau);
  if (z === 0n) throw new Error("tau landed on the QAP domain");
  return mul(sub(mul(a, b), c), inv(z));
}

export function randomFr(tag: string, seed: Uint8Array): bigint {
  let n = 0n;
  for (const byte of seed) n = (n << 8n) | BigInt(byte);
  n ^= BigInt(tag.length) << 240n;
  return mod(n === 0n ? 1n : n);
}

export { FR };

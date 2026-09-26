import { add, mul, sub } from "./field.ts";

/** Sparse linear combination: sum coeff_i * wire_i */
export type Term = { wire: number; coeff: bigint };
export type Lc = Term[];

export interface Constraint {
  a: Lc;
  b: Lc;
  c: Lc;
}

export class R1cs {
  readonly constraints: Constraint[] = [];
  wires = 1; // wire 0 is the constant 1

  alloc(): number {
    const i = this.wires;
    this.wires += 1;
    return i;
  }

  enforce(a: Lc, b: Lc, c: Lc): void {
    this.constraints.push({ a, b, c });
  }

  /** a * 1 = b  (equality) */
  equal(a: number, b: number): void {
    this.enforce([{ wire: a, coeff: 1n }], [{ wire: 0, coeff: 1n }], [{ wire: b, coeff: 1n }]);
  }

  /** left * right = out */
  mul(left: number, right: number, out: number): void {
    this.enforce([{ wire: left, coeff: 1n }], [{ wire: right, coeff: 1n }], [{ wire: out, coeff: 1n }]);
  }

  evalLc(lc: Lc, assignment: bigint[]): bigint {
    let acc = 0n;
    for (const t of lc) acc = add(acc, mul(t.coeff, assignment[t.wire] ?? 0n));
    return acc;
  }

  satisfied(assignment: bigint[]): boolean {
    if (assignment.length < this.wires) return false;
    if (assignment[0] !== 1n) return false;
    for (const c of this.constraints) {
      const av = this.evalLc(c.a, assignment);
      const bv = this.evalLc(c.b, assignment);
      const cv = this.evalLc(c.c, assignment);
      if (sub(mul(av, bv), cv) !== 0n) return false;
    }
    return true;
  }
}

export function lcConst(n: bigint): Lc {
  return [{ wire: 0, coeff: n }];
}

export function lcWire(w: number): Lc {
  return [{ wire: w, coeff: 1n }];
}

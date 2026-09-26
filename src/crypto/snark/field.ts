/** BN254 scalar field used by Groth16 (Zcash Sapling uses BLS12-381; same API shape). */
export const FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function mod(a: bigint): bigint {
  let x = a % FR;
  if (x < 0n) x += FR;
  return x;
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

export function pow(base: bigint, exp: bigint): bigint {
  let b = mod(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = mul(r, b);
    b = mul(b, b);
    e >>= 1n;
  }
  return r;
}

export function inv(a: bigint): bigint {
  const x = mod(a);
  if (x === 0n) throw new Error("inverse of zero");
  return pow(x, FR - 2n);
}

export function fromBytes(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return mod(n);
}

export function fromHex(hex: string): bigint {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!clean) return 0n;
  return mod(BigInt("0x" + clean));
}

export function toHex(n: bigint): string {
  return mod(n).toString(16).padStart(64, "0");
}

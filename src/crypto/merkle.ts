import { EMPTY_HASH, MERKLE_DEPTH } from "../constants.ts";
import { bytesToHex, hexToBytes } from "../encoding.ts";
import { pairHash, tagged } from "./hash.ts";

function zeros(): Uint8Array[] {
  const z: Uint8Array[] = new Array(MERKLE_DEPTH + 1);
  z[0] = tagged("kyron-empty-leaf");
  for (let i = 1; i <= MERKLE_DEPTH; i++) {
    z[i] = pairHash(z[i - 1], z[i - 1]);
  }
  return z;
}

const ZEROS = zeros();

export class IncrementalMerkleTree {
  readonly depth: number;
  private nextIndex = 0;
  private layers: Uint8Array[][];

  constructor(depth = MERKLE_DEPTH) {
    this.depth = depth;
    this.layers = Array.from({ length: depth + 1 }, () => []);
  }

  get size(): number {
    return this.nextIndex;
  }

  get root(): string {
    return bytesToHex(this.computeRoot());
  }

  insert(leafHex: string): number {
    const leaf = hexToBytes(leafHex);
    if (leaf.length !== 32) throw new Error("leaf must be 32 bytes");
    const index = this.nextIndex;
    if (index >= 2 ** this.depth) throw new Error("tree full");
    this.layers[0][index] = leaf;
    let i = index;
    let current = leaf;
    for (let level = 0; level < this.depth; level++) {
      const isRight = i % 2 === 1;
      const sibling = isRight
        ? this.layers[level][i - 1] ?? ZEROS[level]
        : this.layers[level][i + 1] ?? ZEROS[level];
      current = isRight ? pairHash(sibling, current) : pairHash(current, sibling);
      i = Math.floor(i / 2);
      this.layers[level + 1][i] = current;
    }
    this.nextIndex += 1;
    return index;
  }

  computeRoot(): Uint8Array {
    if (this.nextIndex === 0) return ZEROS[this.depth];
    return this.layers[this.depth][0] ?? ZEROS[this.depth];
  }

  proof(index: number): { siblings: string[]; path: number } {
    if (index < 0 || index >= this.nextIndex) throw new Error("index out of range");
    const siblings: string[] = [];
    let i = index;
    for (let level = 0; level < this.depth; level++) {
      const isRight = i % 2 === 1;
      const sib = isRight
        ? this.layers[level][i - 1] ?? ZEROS[level]
        : this.layers[level][i + 1] ?? ZEROS[level];
      siblings.push(bytesToHex(sib));
      i = Math.floor(i / 2);
    }
    return { siblings, path: index };
  }

  static verify(leafHex: string, index: number, siblings: string[], rootHex: string, depth = MERKLE_DEPTH): boolean {
    let current = hexToBytes(leafHex);
    let i = index;
    for (let level = 0; level < depth; level++) {
      const sib = hexToBytes(siblings[level] ?? bytesToHex(ZEROS[level]));
      current = i % 2 === 1 ? pairHash(sib, current) : pairHash(current, sib);
      i = Math.floor(i / 2);
    }
    return bytesToHex(current) === rootHex;
  }
}

export function emptyRoot(depth = MERKLE_DEPTH): string {
  return bytesToHex(ZEROS[depth]);
}

export { EMPTY_HASH };

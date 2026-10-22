import { createHash } from "crypto";

export interface MerkleProofStep {
  /** Sibling hash */
  hash: string;
  /** Whether the sibling is on the left of the current node */
  position: "left" | "right";
}

export interface MerkleInclusionProof {
  leafIndex: number;
  leafHash: string;
  root: string;
  path: MerkleProofStep[];
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Domain-separated leaf hash. */
export function hashLeaf(entryHash: string): string {
  return sha256Hex(`leaf:${entryHash}`);
}

/** Domain-separated internal node. */
export function hashNode(left: string, right: string): string {
  return sha256Hex(`node:${left}|${right}`);
}

/**
 * Build a Merkle tree over entryHashes (in order).
 * Odd nodes are duplicated (Bitcoin-style) so every level is even-width.
 */
export function buildMerkleTree(entryHashes: string[]): {
  root: string;
  layers: string[][];
} {
  if (entryHashes.length === 0) {
    return { root: sha256Hex("empty"), layers: [[]] };
  }
  const leaves = entryHashes.map(hashLeaf);
  const layers: string[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      const right = current[i + 1] ?? left;
      next.push(hashNode(left, right));
    }
    layers.push(next);
    current = next;
  }
  return { root: current[0]!, layers };
}

export function getMerkleRoot(entryHashes: string[]): string {
  return buildMerkleTree(entryHashes).root;
}

/** Inclusion proof for leaf at `index` within `entryHashes`. */
export function getInclusionProof(
  entryHashes: string[],
  index: number,
): MerkleInclusionProof {
  if (index < 0 || index >= entryHashes.length) {
    throw new Error(`Leaf index ${index} out of range`);
  }
  const { root, layers } = buildMerkleTree(entryHashes);
  const path: MerkleProofStep[] = [];
  let idx = index;
  for (let level = 0; level < layers.length - 1; level++) {
    const layer = layers[level]!;
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;
    const sibling =
      siblingIdx < layer.length ? layer[siblingIdx]! : layer[idx]!;
    path.push({
      hash: sibling,
      position: isRight ? "left" : "right",
    });
    idx = Math.floor(idx / 2);
  }
  return {
    leafIndex: index,
    leafHash: hashLeaf(entryHashes[index]!),
    root,
    path,
  };
}

export function verifyInclusionProof(proof: MerkleInclusionProof): boolean {
  let current = proof.leafHash;
  for (const step of proof.path) {
    if (step.position === "left") {
      current = hashNode(step.hash, current);
    } else {
      current = hashNode(current, step.hash);
    }
  }
  return current === proof.root;
}

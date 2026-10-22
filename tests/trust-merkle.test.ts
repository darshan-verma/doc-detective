import { describe, expect, it } from "vitest";
import {
  buildMerkleTree,
  getInclusionProof,
  getMerkleRoot,
  verifyInclusionProof,
} from "../src/lib/trust/merkle";

describe("Merkle tree", () => {
  it("builds a stable root for known leaves", () => {
    const leaves = ["a", "b", "c", "d"].map((x) => `hash-${x}`);
    const root1 = getMerkleRoot(leaves);
    const root2 = getMerkleRoot(leaves);
    expect(root1).toBe(root2);
    expect(root1).toHaveLength(64);
  });

  it("verifies inclusion proof for every leaf", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => `entry-${i}`);
    const { root } = buildMerkleTree(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const proof = getInclusionProof(leaves, i);
      expect(proof.root).toBe(root);
      expect(verifyInclusionProof(proof)).toBe(true);
    }
  });

  it("fails for a modified leaf", () => {
    const leaves = ["x", "y", "z"];
    const proof = getInclusionProof(leaves, 1);
    expect(verifyInclusionProof(proof)).toBe(true);

    const tampered = {
      ...proof,
      leafHash: "0".repeat(64),
    };
    expect(verifyInclusionProof(tampered)).toBe(false);

    const wrongRoot = { ...proof, root: "f".repeat(64) };
    expect(verifyInclusionProof(wrongRoot)).toBe(false);
  });
});

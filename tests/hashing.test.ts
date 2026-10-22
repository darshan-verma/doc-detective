import { createHash } from "crypto";
import { Readable } from "stream";
import { describe, expect, it } from "vitest";
import { hashBuffer, hashStream } from "../src/lib/hashing";

describe("hashing", () => {
  it('SHA-256 of "hello" matches known vector', async () => {
    const result = await hashBuffer(Buffer.from("hello"));
    expect(result.sha256).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
    expect(result.sizeBytes).toBe(5);
  });

  it("streams without loading whole content into one buffer path", async () => {
    const parts = [Buffer.from("hel"), Buffer.from("lo")];
    const result = await hashStream(Readable.from(parts));
    expect(result.sha256).toBe(
      createHash("sha256").update("hello").digest("hex"),
    );
  });

  it("produces chunk hashes for multi-block input", async () => {
    const data = Buffer.alloc(4096 + 10, 0x41);
    const result = await hashBuffer(data);
    expect(result.chunkHashes.length).toBe(2);
    expect(result.sizeBytes).toBe(4106);
  });
});

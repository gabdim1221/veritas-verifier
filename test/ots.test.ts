import { describe, it, expect } from "vitest";
import { verifyOtsProof, upgradeOtsProof } from "../src/ots.js";

const ZERO_HASH = new Uint8Array(32);

describe("opentimestamps", () => {
  it("returns invalid for random/garbage proof bytes", async () => {
    const garbage = Buffer.from(new Uint8Array(64).fill(0xff)).toString("base64");
    const result = await verifyOtsProof(garbage, ZERO_HASH);
    expect(result.status).toBe("invalid");
    expect(result.details).toBeDefined();
  });

  it("returns invalid (does not throw) for empty/malformed base64", async () => {
    const r1 = await verifyOtsProof("", ZERO_HASH);
    expect(r1.status).toBe("invalid");
    const r2 = await verifyOtsProof("!!!not base64!!!", ZERO_HASH);
    expect(r2.status).toBe("invalid");
  });

  it("returns invalid (does not throw) for non-string-shaped junk", async () => {
    const r = await verifyOtsProof(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ZERO_HASH,
    );
    expect(r.status).toBe("invalid");
  });

  it("upgradeOtsProof returns null on garbage input (does not throw)", async () => {
    const result = await upgradeOtsProof("notarealproof");
    expect(result).toBeNull();
  });

  it.todo("real upgraded proof verifies as confirmed (fixture lands in Phase 5)");
  it.todo("real pending proof verifies as pending without network call (fixture lands in Phase 5)");
});

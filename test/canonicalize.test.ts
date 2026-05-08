import { describe, it, expect } from "vitest";
import { canonicalizeForSigning, tesseraHash, hex } from "../src/canonicalize.js";
import type { Tessera } from "../src/index.js";

const sample: Tessera = {
  version: "tessera/v0.1",
  type: "authorship",
  tessera_id: "550e8400-e29b-41d4-a716-446655440000",
  issuer: {
    user_handle: "test",
    user_master_pubkey: "AAAA",
    device_pubkey: "BBBB",
    device_delegation_hash: "deadbeef",
  },
  claim: { loa: 2, issued_at: "2026-05-08T12:00:00Z" },
  type_payload: {
    subject: {
      content_hash: "abc123",
      content_size_bytes: 100,
      content_mime: "text/plain",
    },
    session: {
      started_at: "2026-05-08T11:00:00Z",
      ended_at: "2026-05-08T12:00:00Z",
      duration_ms: 3600000,
      tools_used: ["test"],
    },
    behavioral_fingerprint: "fingerprint",
    ai_assistance_disclosure: "none",
  },
  biometric_attestation: { method: "none" },
  anchor: { service: "opentimestamps", ots_proof: "proofdata" },
  signature: { algorithm: "Ed25519", value: "shouldbestripped" },
};

describe("canonicalize", () => {
  it("strips the signature field before canonicalizing", () => {
    const bytes = canonicalizeForSigning(sample);
    const text = new TextDecoder().decode(bytes);
    expect(text).not.toContain("shouldbestripped");
    expect(text).not.toContain("signature");
  });

  it("produces deterministic output for the same input", () => {
    const a = canonicalizeForSigning(sample);
    const b = canonicalizeForSigning(sample);
    expect(hex(a)).toBe(hex(b));
  });

  it("produces sorted-key output (RFC 8785)", () => {
    const bytes = canonicalizeForSigning(sample);
    const text = new TextDecoder().decode(bytes);
    // top-level: anchor before biometric_attestation before claim before issuer …
    const anchorIdx = text.indexOf('"anchor"');
    const claimIdx = text.indexOf('"claim"');
    const issuerIdx = text.indexOf('"issuer"');
    const versionIdx = text.indexOf('"version"');
    expect(anchorIdx).toBeGreaterThanOrEqual(0);
    expect(anchorIdx).toBeLessThan(claimIdx);
    expect(claimIdx).toBeLessThan(issuerIdx);
    expect(issuerIdx).toBeLessThan(versionIdx);
  });

  it("tesseraHash is 32 bytes", () => {
    const h = tesseraHash(sample);
    expect(h).toHaveLength(32);
  });

  it("hex encoding is lowercase", () => {
    const h = hex(new Uint8Array([0xab, 0xcd]));
    expect(h).toBe("abcd");
  });

  it("canonicalize is independent of source key order", () => {
    const reordered: Tessera = JSON.parse(
      JSON.stringify({
        // intentionally scrambled key order
        signature: sample.signature,
        type: sample.type,
        version: sample.version,
        anchor: sample.anchor,
        biometric_attestation: sample.biometric_attestation,
        type_payload: sample.type_payload,
        claim: sample.claim,
        issuer: sample.issuer,
        tessera_id: sample.tessera_id,
      }),
    );
    expect(hex(canonicalizeForSigning(sample))).toBe(hex(canonicalizeForSigning(reordered)));
  });
});

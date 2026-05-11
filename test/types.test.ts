import { describe, it, expect } from "vitest";
import type { Tessera, LOA, TesseraType } from "../src/index.js";
import { VerificationErrorCode } from "../src/index.js";

describe("types", () => {
  it("LOA accepts 0 through 4", () => {
    const valid: LOA[] = [0, 1, 2, 3, 4];
    expect(valid).toHaveLength(5);
  });

  it("TesseraType includes all seven canonical types", () => {
    const all: TesseraType[] = [
      "authorship",
      "witness",
      "covenant",
      "delegation",
      "revocation",
      "attestation",
      "lodestone",
    ];
    expect(all).toHaveLength(7);
  });

  it("VerificationErrorCode covers all 14 spec failure modes (13 v0.1 + 1 v0.2)", () => {
    expect(Object.keys(VerificationErrorCode)).toHaveLength(14);
    expect(VerificationErrorCode.COMPOSITION_INVARIANT_VIOLATION).toBe("COMPOSITION_INVARIANT_VIOLATION");
  });

  it("Tessera envelope discriminates type_payload by `type`", () => {
    // Compile-time check: this object should be assignable; if BaseEnvelope or
    // AuthorshipPayload drift from the spec, this no longer type-checks.
    const t: Tessera = {
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
          content_hash: "abc",
          content_size_bytes: 0,
          content_mime: "text/plain",
        },
        session: {
          started_at: "2026-05-08T11:00:00Z",
          ended_at: "2026-05-08T12:00:00Z",
          duration_ms: 0,
          tools_used: [],
        },
        behavioral_fingerprint: "fp",
        ai_assistance_disclosure: "none",
      },
      biometric_attestation: { method: "none" },
      anchor: { service: "opentimestamps", ots_proof: "p" },
      signature: { algorithm: "Ed25519", value: "sig" },
    };
    expect(t.type).toBe("authorship");
  });
});

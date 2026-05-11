import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  verify,
  VerificationErrorCode,
  generateKeypair,
  sign,
  base64urlEncode,
  canonicalizeForSigning,
  tesseraHash,
  hex,
  type Tessera,
  type LOA,
  type VerifyOptions,
  type OTSResult,
} from "../src/index.js";

const stubConfirmedAnchor: VerifyOptions["verifyAnchor"] = async () => ({
  status: "confirmed",
  blockHeight: 800_000,
  blockTime: new Date("2026-05-08T12:00:00Z"),
});

const stubPendingAnchor: VerifyOptions["verifyAnchor"] = async () => ({
  status: "pending",
});

interface PairOpts {
  contentText?: string;
  loa?: LOA;
  delegationValidFrom?: string;
  delegationValidUntil?: string | null;
  delegationScope?: string[];
  contentIssuedAt?: string;
  /** When provided, sign the content with a different device than the
   *  one the delegation authorizes (for the KEY_MISMATCH test). */
  signWithDifferentDevice?: boolean;
}

interface Pair {
  tessera: Tessera;
  delegation: Tessera;
  contentBytes: Uint8Array;
}

function buildAuthorshipPair(opts: PairOpts = {}): Pair {
  const {
    contentText = "hello confirmata",
    loa = 2 as LOA,
    delegationValidFrom = "2026-05-08T11:00:00Z",
    delegationValidUntil = null,
    delegationScope = ["sign:authorship"],
    contentIssuedAt = "2026-05-08T12:00:00Z",
    signWithDifferentDevice = false,
  } = opts;

  const masterKp = generateKeypair();
  const authorisedDeviceKp = generateKeypair();
  const signingDeviceKp = signWithDifferentDevice ? generateKeypair() : authorisedDeviceKp;

  const masterPub = base64urlEncode(masterKp.publicKey);
  const authorisedDevicePub = base64urlEncode(authorisedDeviceKp.publicKey);
  const signingDevicePub = base64urlEncode(signingDeviceKp.publicKey);

  // ---- delegation ----
  const delegationDraft: Tessera = {
    version: "tessera/v0.1",
    type: "delegation",
    tessera_id: "11111111-1111-4111-8111-111111111111",
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: masterPub, // master signs the delegation directly
      device_delegation_hash: "",
    },
    claim: { loa: 0, issued_at: "2026-05-08T10:00:00Z" },
    type_payload: {
      delegated_pubkey: authorisedDevicePub,
      device_name: "alice-laptop",
      device_platform: "test",
      scope: delegationScope,
      valid_from: delegationValidFrom,
      valid_until: delegationValidUntil,
    },
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps", ots_proof: "stub" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  const delMsg = canonicalizeForSigning(delegationDraft);
  const delSig = sign(delMsg, masterKp.privateKey);
  delegationDraft.signature.value = base64urlEncode(delSig);
  const delegation = delegationDraft;
  const delegationHashHex = hex(tesseraHash(delegation));

  // ---- content (authorship) ----
  const contentBytes = new TextEncoder().encode(contentText);
  const contentHashHex = hex(sha256(contentBytes));

  const contentDraft: Tessera = {
    version: "tessera/v0.1",
    type: "authorship",
    tessera_id: "22222222-2222-4222-8222-222222222222",
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: signingDevicePub,
      device_delegation_hash: delegationHashHex,
    },
    claim: { loa, issued_at: contentIssuedAt },
    type_payload: {
      subject: {
        content_hash: contentHashHex,
        content_size_bytes: contentBytes.length,
        content_mime: "text/plain",
      },
      session: {
        started_at: "2026-05-08T11:30:00Z",
        ended_at: contentIssuedAt,
        duration_ms: 30 * 60 * 1000,
        tools_used: ["confirmata-cli@0.1"],
      },
      behavioral_fingerprint: base64urlEncode(sha256(contentBytes)),
      ai_assistance_disclosure: "none",
    },
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps", ots_proof: "stub" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  const contentMsg = canonicalizeForSigning(contentDraft);
  const contentSig = sign(contentMsg, signingDeviceKp.privateKey);
  contentDraft.signature.value = base64urlEncode(contentSig);

  return { tessera: contentDraft, delegation, contentBytes };
}

const fetchOf = (delegation: Tessera) => async () => delegation;

describe("verify()", () => {
  it("verifies a valid authorship Tessera (synthetic, stubbed anchor)", async () => {
    const { tessera, delegation, contentBytes } = buildAuthorshipPair();
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
      content: contentBytes,
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.loa).toBe(2);
      expect(result.anchorStatus).toBe("confirmed");
      expect(result.anchoredAtBlock).toBe(800_000);
      expect(result.authorHandle).toBe("alice");
    }
  });

  it("returns INVALID_SIGNATURE when signature byte is flipped", async () => {
    const { tessera, delegation } = buildAuthorshipPair();
    // Flip first character of signature.value (still valid base64url alphabet)
    const orig = tessera.signature.value;
    const flipped = (orig[0] === "A" ? "B" : "A") + orig.slice(1);
    const tampered: Tessera = {
      ...tessera,
      signature: { ...tessera.signature, value: flipped },
    };
    const result = await verify(tampered, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.INVALID_SIGNATURE);
    }
  });

  it("returns DELEGATION_KEY_MISMATCH when content is signed by a different device than the delegation authorized", async () => {
    const { tessera, delegation } = buildAuthorshipPair({ signWithDifferentDevice: true });
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.DELEGATION_KEY_MISMATCH);
    }
  });

  it("returns DELEGATION_EXPIRED when valid_until precedes issued_at", async () => {
    const { tessera, delegation } = buildAuthorshipPair({
      contentIssuedAt: "2026-05-08T12:00:00Z",
      delegationValidUntil: "2026-05-08T11:00:00Z",
    });
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.DELEGATION_EXPIRED);
    }
  });

  it("returns CONTENT_MISMATCH when provided content does not match content_hash", async () => {
    const { tessera, delegation } = buildAuthorshipPair({ contentText: "original" });
    const wrongContent = new TextEncoder().encode("not the original");
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
      content: wrongContent,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.CONTENT_MISMATCH);
    }
  });

  it("returns LOA_INSUFFICIENT when claim.loa < requiredLoa", async () => {
    const { tessera, delegation } = buildAuthorshipPair({ loa: 2 });
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
      requiredLoa: 4,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.LOA_INSUFFICIENT);
    }
  });

  it("returns DELEGATION_NOT_FOUND when fetchDelegation returns null", async () => {
    const { tessera } = buildAuthorshipPair();
    const result = await verify(tessera, {
      fetchDelegation: async () => null,
      verifyAnchor: stubConfirmedAnchor,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.DELEGATION_NOT_FOUND);
    }
  });

  it("returns INVALID_SCHEMA for an unknown version", async () => {
    const { tessera, delegation } = buildAuthorshipPair();
    const bad = { ...tessera, version: "tessera/v0.99" } as unknown as Tessera;
    const result = await verify(bad, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.INVALID_SCHEMA);
    }
  });

  it("returns REVOKED when isRevoked reports the content tessera revoked", async () => {
    const { tessera, delegation } = buildAuthorshipPair();
    const targetHashHex = hex(tesseraHash(tessera));
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubConfirmedAnchor,
      isRevoked: async (h) => h === targetHashHex,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.REVOKED);
    }
  });

  it("succeeds with anchorStatus='pending' when OTS is pending and not strict", async () => {
    const { tessera, delegation } = buildAuthorshipPair();
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubPendingAnchor,
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.anchorStatus).toBe("pending");
      expect(result.anchoredAtBlock).toBeUndefined();
    }
  });

  it("returns ANCHOR_PENDING when OTS is pending and requireConfirmedAnchor=true", async () => {
    const { tessera, delegation } = buildAuthorshipPair();
    const result = await verify(tessera, {
      fetchDelegation: fetchOf(delegation),
      verifyAnchor: stubPendingAnchor,
      requireConfirmedAnchor: true,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errorCode).toBe(VerificationErrorCode.ANCHOR_PENDING);
    }
  });

  it.todo("real OTS round-trip — verified in Phase 5");
});

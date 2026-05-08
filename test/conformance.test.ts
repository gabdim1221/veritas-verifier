import { describe, it, expect } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verify,
  verifyDelegation,
  hex,
  tesseraHash,
  VerificationErrorCode,
  type Tessera,
  type VerifyOptions,
  type OTSResult,
} from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.resolve(__dirname, "..", "test-vectors");

interface Bundle {
  tessera: Tessera;
  delegation?: Tessera;
}

async function loadJson<T>(rel: string): Promise<T> {
  const raw = await fs.readFile(path.join(VECTORS_DIR, rel), "utf8");
  return JSON.parse(raw) as T;
}

async function loadContent(rel: string): Promise<Uint8Array> {
  const buf = await fs.readFile(path.join(VECTORS_DIR, rel));
  return new Uint8Array(buf);
}

// Browser-equivalent stub anchor: proof must decode as base64 to be "pending"
const stubAnchor: VerifyOptions["verifyAnchor"] = async (proofB64): Promise<OTSResult> => {
  if (!proofB64) return { status: "invalid", details: "anchor.ots_proof empty" };
  try {
    atob(proofB64.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return { status: "invalid", details: "anchor.ots_proof not valid base64" };
  }
  return { status: "pending" };
};

describe("conformance vectors (Tessera v0.1)", () => {
  describe("authorship", () => {
    it("valid-loa2 → VALID, anchor pending, loa 2", async () => {
      const b = await loadJson<Bundle>("authorship/valid-loa2.json");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(true);
      if (r.valid) {
        expect(r.loa).toBe(2);
        expect(r.anchorStatus).toBe("pending");
        expect(r.authorHandle).toBe("alice");
      }
    });

    it("valid-loa3 → VALID, loa 3", async () => {
      const b = await loadJson<Bundle>("authorship/valid-loa3.json");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(true);
      if (r.valid) expect(r.loa).toBe(3);
    });

    it("valid-loa4 → VALID, loa 4", async () => {
      const b = await loadJson<Bundle>("authorship/valid-loa4.json");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(true);
      if (r.valid) expect(r.loa).toBe(4);
    });

    it("invalid-bad-signature → INVALID_SIGNATURE", async () => {
      const b = await loadJson<Bundle>("authorship/invalid-bad-signature.json");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(false);
      if (!r.valid) expect(r.errorCode).toBe(VerificationErrorCode.INVALID_SIGNATURE);
    });

    it("invalid-bad-anchor → INVALID_ANCHOR", async () => {
      const b = await loadJson<Bundle>("authorship/invalid-bad-anchor.json");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(false);
      if (!r.valid) expect(r.errorCode).toBe(VerificationErrorCode.INVALID_ANCHOR);
    });

    it("invalid-content-mismatch → CONTENT_MISMATCH (when wrong content supplied)", async () => {
      const b = await loadJson<Bundle>("authorship/invalid-content-mismatch.json");
      const wrongContent = await loadContent("fixtures/mismatch-content.txt");
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
        content: wrongContent,
      });
      expect(r.valid).toBe(false);
      if (!r.valid) expect(r.errorCode).toBe(VerificationErrorCode.CONTENT_MISMATCH);
    });

    it("invalid-revoked → REVOKED (when paired with revocation/valid.json)", async () => {
      const b = await loadJson<Bundle>("authorship/invalid-revoked.json");
      const targetHashHex = hex(tesseraHash(b.tessera));
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
        isRevoked: async (h) => h === targetHashHex,
      });
      expect(r.valid).toBe(false);
      if (!r.valid) expect(r.errorCode).toBe(VerificationErrorCode.REVOKED);
    });
  });

  describe("delegation", () => {
    it("valid-chain → VALID standalone (signed by master == device_pubkey)", async () => {
      const t = await loadJson<Tessera>("delegation/valid-chain.json");
      const r = await verify(t, { verifyAnchor: stubAnchor });
      expect(r.valid).toBe(true);
    });

    it("invalid-expired → DELEGATION_EXPIRED when used to authorize content after valid_until", async () => {
      const t = await loadJson<Tessera>("delegation/invalid-expired.json");
      // Test directly via verifyDelegation with a contentIssuedAt past valid_until.
      const issuer = t.issuer;
      const r = await verifyDelegation(
        t,
        "authorship",
        "2026-05-08T18:00:00.000Z",
        // Use the delegated_pubkey from the payload; expectedDevicePubkey simulates
        // the content tessera's device_pubkey, which by construction matches.
        (t.type_payload as { delegated_pubkey: string }).delegated_pubkey,
        issuer.user_master_pubkey,
      );
      expect(r.valid).toBe(false);
      expect(r.errorCode).toBe(VerificationErrorCode.DELEGATION_EXPIRED);
    });
  });

  describe("revocation", () => {
    it("valid → VALID standalone (signed by an authorized device)", async () => {
      const t = await loadJson<Tessera>("revocation/valid.json");
      const delegation = await loadJson<Tessera>("delegation/valid-chain.json");
      const r = await verify(t, {
        fetchDelegation: async () => delegation,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(true);
    });
  });
});

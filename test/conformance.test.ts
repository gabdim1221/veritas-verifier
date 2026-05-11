import { describe, it, expect } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verify,
  verifyDelegation,
  hex,
  tesseraHash,
  checkCompositionInvariants,
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

describe("conformance vectors (Tessera v0.2 — composition_analysis)", () => {
  const cases: Array<{
    file: string;
    expectedHumanPct: number;
    expectedConfidence: "high" | "medium" | "low";
    expectedCategories: string[];
  }> = [
    {
      file: "v0.2/composition_pure_human.json",
      expectedHumanPct: 95.0,
      expectedConfidence: "high",
      expectedCategories: ["academic_70_plus", "journalism_60_plus", "creative_writing_50_plus"],
    },
    {
      file: "v0.2/composition_hybrid.json",
      expectedHumanPct: 70.0,
      expectedConfidence: "high",
      expectedCategories: ["academic_70_plus", "journalism_60_plus"],
    },
    {
      file: "v0.2/composition_mostly_ai.json",
      expectedHumanPct: 28.0,
      expectedConfidence: "medium",
      expectedCategories: [],
    },
  ];

  for (const c of cases) {
    it(`${c.file} → VALID, signature + composition invariants both hold`, async () => {
      const b = await loadJson<Bundle>(c.file);
      const r = await verify(b.tessera, {
        fetchDelegation: async () => b.delegation ?? null,
        verifyAnchor: stubAnchor,
      });
      expect(r.valid).toBe(true);
      expect(b.tessera.version).toBe("tessera/v0.2");
      const ca = b.tessera.composition_analysis;
      expect(ca).toBeDefined();
      if (ca) {
        expect(ca.computed_authorship.human_pct).toBe(c.expectedHumanPct);
        expect(ca.computed_authorship.confidence).toBe(c.expectedConfidence);
        expect(ca.policy_eligible_categories).toEqual(c.expectedCategories);
        // Invariants 1, 2, 3, 5 — exercise checkCompositionInvariants directly.
        expect(checkCompositionInvariants(ca)).toBe(null);
        const buckets = ca.buckets;
        const bucketSum =
          buckets.human_active_ms +
          buckets.ai_assisted_ms +
          buckets.voice_authored_ms +
          buckets.paste_inserted_ms +
          buckets.context_review_ms +
          buckets.idle_ms;
        expect(Math.abs(bucketSum - ca.total_session_ms)).toBeLessThanOrEqual(100);
        const pctSum =
          ca.computed_authorship.human_pct +
          ca.computed_authorship.ai_assisted_pct +
          ca.computed_authorship.ambiguous_pct;
        expect(pctSum).toBeGreaterThanOrEqual(99.0);
        expect(pctSum).toBeLessThanOrEqual(101.0);
      }
    });
  }

  it("rejects a tampered composition_analysis with COMPOSITION_INVARIANT_VIOLATION", async () => {
    const b = await loadJson<Bundle>("v0.2/composition_hybrid.json");
    // Tamper: flip bucket sum out of range. This breaks the on-tessera signature
    // because the field is part of the canonicalized payload, so we re-sign the
    // tampered tessera with the device key. To keep the test self-contained
    // without re-signing, we instead bypass verify() and call the invariant
    // check directly with a mutated copy.
    const broken = JSON.parse(JSON.stringify(b.tessera.composition_analysis));
    broken.buckets.idle_ms += 5_000_000; // overshoot total_session_ms
    expect(checkCompositionInvariants(broken)).not.toBe(null);
  });
});

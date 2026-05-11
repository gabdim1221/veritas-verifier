#!/usr/bin/env -S npx tsx
/**
 * Generate the 10 conformance test vectors for Tessera v0.1.
 *
 * Produces files under test-vectors/ relative to the verifier package root.
 * Outputs are reproducible per-run from a fixed RNG seed.
 *
 * The conformance test harness (test/conformance.test.ts) verifies each
 * vector with a stub anchor (pending-or-invalid based on b64 decodability)
 * — this lets vectors stay fast/network-free; real OTS proofs are exercised
 * end-to-end via the live fixture at test/fixtures/first-real-authorship.*.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import {
  base64urlEncode,
  canonicalizeForSigning,
  hex,
  sign,
  tesseraHash,
  type AuthorshipPayload,
  type CompositionAnalysis,
  type DelegationPayload,
  type RevocationPayload,
  type Tessera,
  type LOA,
  type BiometricMethod,
  type TesseraVersion,
} from "../src/index.js";

ed.hashes.sha512 = sha512;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "test-vectors");

// Deterministic helpers ----------------------------------------------------

/** Deterministic 32-byte key derived from a label, so vectors regenerate
 *  identically across runs. NOT a cryptographic KDF — for reproducibility
 *  of test fixtures only. */
function deterministicKey(label: string): Uint8Array {
  // h = sha256("confirmata/v0.1/test-vectors/" + label) — bound to this purpose
  return sha256(new TextEncoder().encode(`confirmata/v0.1/test-vectors/${label}`));
}

function detKeypair(label: string): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = deterministicKey(label);
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

const ISSUED_AT = "2026-05-08T18:00:00.000Z";
const DELEGATION_VALID_FROM = "2026-05-08T17:00:00.000Z";
const DELEGATION_FAR_FUTURE = "2099-01-01T00:00:00.000Z";
const DELEGATION_PAST_END = "2026-05-08T17:30:00.000Z"; // before content's issued_at

// A placeholder OTS proof: 64 base64-url-safe bytes. Decodes successfully
// (the conformance harness's stub treats this as `pending`).
const STUB_PROOF = base64urlEncode(new Uint8Array(64).fill(0xab));

// Issuer identity ----------------------------------------------------------

const masterKp = detKeypair("master");
const deviceKp = detKeypair("device");
const masterPub = base64urlEncode(masterKp.publicKey);
const devicePub = base64urlEncode(deviceKp.publicKey);

// Build, sign, and (optionally) anchor a Tessera ---------------------------

function signTessera(t: Tessera, secretKey: Uint8Array): Tessera {
  const msg = canonicalizeForSigning(t);
  t.signature.value = base64urlEncode(sign(msg, secretKey));
  return t;
}

function withProof(t: Tessera, proofB64: string): Tessera {
  t.anchor.ots_proof = proofB64;
  return t;
}

// Delegation ---------------------------------------------------------------

function buildDelegation(opts: {
  validUntil: string | null;
  scope?: string[];
  uuid: string;
}): Tessera {
  const draft: Tessera = {
    version: "tessera/v0.1",
    type: "delegation",
    tessera_id: opts.uuid,
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: masterPub, // master signs delegation directly
      device_delegation_hash: "",
    },
    claim: { loa: 0, issued_at: DELEGATION_VALID_FROM },
    type_payload: {
      delegated_pubkey: devicePub,
      device_name: "alice-test-device",
      device_platform: "test",
      scope: opts.scope ?? ["sign:authorship", "sign:revocation"],
      valid_from: DELEGATION_VALID_FROM,
      valid_until: opts.validUntil,
    } satisfies DelegationPayload,
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  signTessera(draft, masterKp.privateKey);
  withProof(draft, STUB_PROOF);
  return draft;
}

// Authorship ---------------------------------------------------------------

interface AuthorshipOpts {
  uuid: string;
  loa: LOA;
  biometric: BiometricMethod;
  contentBytes: Uint8Array;
  delegation: Tessera;
  /** Override envelope version. Default: "tessera/v0.1". */
  version?: TesseraVersion;
  /** Override the session sub-block (used by v0.2 composition vectors). */
  session?: AuthorshipPayload["session"];
  /** Override ai_assistance_disclosure. Default: "none". */
  aiDisclosure?: AuthorshipPayload["ai_assistance_disclosure"];
  /** Override claim.issued_at. Default: ISSUED_AT. */
  issuedAt?: string;
  /** Optional v0.2 composition_analysis. */
  composition?: CompositionAnalysis;
}

function buildAuthorship(o: AuthorshipOpts): Tessera {
  const contentHashHex = hex(sha256(o.contentBytes));
  const draft: Tessera = {
    version: o.version ?? "tessera/v0.1",
    type: "authorship",
    tessera_id: o.uuid,
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: devicePub,
      device_delegation_hash: hex(tesseraHash(o.delegation)),
    },
    claim: { loa: o.loa, issued_at: o.issuedAt ?? ISSUED_AT },
    type_payload: {
      subject: {
        content_hash: contentHashHex,
        content_size_bytes: o.contentBytes.length,
        content_mime: "text/plain",
        content_filename: "conformance.txt",
      },
      session: o.session ?? {
        started_at: ISSUED_AT,
        ended_at: ISSUED_AT,
        duration_ms: 0,
        tools_used: ["confirmata-conformance@v0.1"],
      },
      behavioral_fingerprint: base64urlEncode(sha256(o.contentBytes)),
      ai_assistance_disclosure: o.aiDisclosure ?? "none",
    } satisfies AuthorshipPayload,
    biometric_attestation:
      o.biometric === "none"
        ? { method: "none" }
        : {
            method: o.biometric,
            authenticator_data: base64urlEncode(new Uint8Array(32).fill(0xcc)),
            client_data_json: base64urlEncode(new Uint8Array(64).fill(0xdd)),
          },
    anchor: { service: "opentimestamps" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  if (o.composition) {
    draft.composition_analysis = o.composition;
  }
  signTessera(draft, deviceKp.privateKey);
  withProof(draft, STUB_PROOF);
  return draft;
}

// Revocation ---------------------------------------------------------------

function buildRevocation(opts: { uuid: string; revokedHash: string }): Tessera {
  const draft: Tessera = {
    version: "tessera/v0.1",
    type: "revocation",
    tessera_id: opts.uuid,
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: devicePub,
      device_delegation_hash: hex(tesseraHash(VALID_DELEGATION)),
    },
    claim: { loa: 0, issued_at: ISSUED_AT },
    type_payload: {
      revoked_tessera_hash: opts.revokedHash,
      reason: "retracted",
      reason_text: "test vector — not a real revocation",
    } satisfies RevocationPayload,
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  signTessera(draft, deviceKp.privateKey);
  withProof(draft, STUB_PROOF);
  return draft;
}

// I/O ----------------------------------------------------------------------

async function writeFile(rel: string, value: unknown): Promise<void> {
  const abs = path.join(ROOT, rel);
  await fs.mkdir(path.dirname(abs), { recursive: true });
  await fs.writeFile(abs, JSON.stringify(value, null, 2) + "\n");
}

// Build the corpus ---------------------------------------------------------

const VALID_DELEGATION = buildDelegation({
  uuid: "11111111-1111-4111-8111-111111111111",
  validUntil: DELEGATION_FAR_FUTURE,
});

const EXPIRED_DELEGATION = buildDelegation({
  uuid: "22222222-2222-4222-8222-222222222222",
  validUntil: DELEGATION_PAST_END,
});

const CONTENT_BYTES = new TextEncoder().encode(
  "the canonical conformance test content for tessera v0.1\n",
);
const MISMATCH_CONTENT = new TextEncoder().encode("DIFFERENT BYTES\n");

const VALID_LOA2 = buildAuthorship({
  uuid: "aaaa1111-1111-4111-8111-aaaaaaaaaaaa",
  loa: 2,
  biometric: "webauthn",
  contentBytes: CONTENT_BYTES,
  delegation: VALID_DELEGATION,
});

const VALID_LOA3 = buildAuthorship({
  uuid: "aaaa2222-2222-4222-8222-aaaaaaaaaaaa",
  loa: 3,
  biometric: "webauthn_liveness",
  contentBytes: CONTENT_BYTES,
  delegation: VALID_DELEGATION,
});

const VALID_LOA4 = buildAuthorship({
  uuid: "aaaa3333-3333-4333-8333-aaaaaaaaaaaa",
  loa: 4,
  biometric: "kyc_bound",
  contentBytes: CONTENT_BYTES,
  delegation: VALID_DELEGATION,
});

// invalid-bad-signature: clone valid-loa2, flip one byte in the signature
const INVALID_BAD_SIG: Tessera = JSON.parse(JSON.stringify(VALID_LOA2));
{
  const v = INVALID_BAD_SIG.signature.value;
  INVALID_BAD_SIG.signature.value = (v[0] === "A" ? "B" : "A") + v.slice(1);
}

// invalid-bad-anchor: clone valid-loa2 and replace anchor with garbage that
// will fail base64 decode in the stub (and OTS deserialization in real verify)
const INVALID_BAD_ANCHOR: Tessera = JSON.parse(JSON.stringify(VALID_LOA2));
INVALID_BAD_ANCHOR.anchor.ots_proof = "!!!not base64!!!";

// invalid-content-mismatch: same as VALID_LOA2 in shape, but the content
// supplied to verify (MISMATCH_CONTENT) doesn't hash to type_payload.subject.content_hash
const INVALID_CONTENT_MISMATCH = VALID_LOA2; // re-use VALID_LOA2; harness supplies MISMATCH_CONTENT

// invalid-revoked: a separate authorship vector that the revocation targets
const INVALID_REVOKED = buildAuthorship({
  uuid: "aaaa4444-4444-4444-8444-aaaaaaaaaaaa",
  loa: 2,
  biometric: "webauthn",
  contentBytes: new TextEncoder().encode("this content is targeted by a revocation\n"),
  delegation: VALID_DELEGATION,
});

const REVOCATION_VALID = buildRevocation({
  uuid: "bbbb1111-1111-4111-8111-bbbbbbbbbbbb",
  revokedHash: hex(tesseraHash(INVALID_REVOKED)),
});

// Wrap into bundles --------------------------------------------------------

function bundle(t: Tessera, d: Tessera | null = null): { tessera: Tessera; delegation?: Tessera } {
  return d ? { tessera: t, delegation: d } : { tessera: t };
}

// NOTE: The committed v0.1 vectors under test-vectors/authorship,
// test-vectors/delegation, test-vectors/revocation, and test-vectors/fixtures
// were originally produced with an earlier version of @noble/ed25519 /
// @noble/hashes whose deterministic-key output differs from the current
// versions. Re-emitting them here would change the on-disk bytes (signatures
// would still verify, but third-party byte-level reproducibility checks
// would diverge). v0.1 reproducibility is therefore pinned to the committed
// files. The v0.1 build steps above still run because the v0.2 bundles
// reference VALID_DELEGATION (signed under current keys and self-contained
// within each v0.2 bundle).

// (v0.1 writeFile calls intentionally omitted — see note above.)
// Sidecar content files: already on disk and unchanged.
void [
  VALID_LOA2, VALID_LOA3, VALID_LOA4,
  INVALID_BAD_SIG, INVALID_BAD_ANCHOR, INVALID_REVOKED, INVALID_CONTENT_MISMATCH,
  EXPIRED_DELEGATION, REVOCATION_VALID,
  MISMATCH_CONTENT,
];

// =========================================================================
// v0.2 composition_analysis vectors
// =========================================================================
//
// Three vectors exercising the optional composition_analysis field
// introduced in spec/v0.2/tessera.md §13. Each uses arithmetic that
// satisfies invariants 1 (bucket sum ±100ms), 2 (percentage sum 99–101),
// 3 (non-negativity), 4 (authorship_time ≥ 1000ms), 5 (voice → human),
// and 6 (full sub-field population).

const COMPOSITION_ISSUED_AT = "2026-05-08T19:00:00.000Z";

function makeSession(totalMs: number, label: string): AuthorshipPayload["session"] {
  const start = new Date(COMPOSITION_ISSUED_AT);
  const end = new Date(start.getTime() + totalMs);
  return {
    started_at: start.toISOString(),
    ended_at: end.toISOString(),
    duration_ms: totalMs,
    tools_used: ["confirmata-conformance@v0.2", label],
  };
}

const COMP_PURE_HUMAN: CompositionAnalysis = {
  version: "1",
  total_session_ms: 1_800_000, // 30 min
  buckets: {
    human_active_ms: 1_500_000,
    ai_assisted_ms: 0,
    voice_authored_ms: 96_000,
    paste_inserted_ms: 84_000,
    context_review_ms: 60_000,
    idle_ms: 60_000,
  },
  // authorship_time = 1_800_000 - 60_000 - 60_000 = 1_680_000
  // human_pct = (1_500_000 + 96_000) / 1_680_000 = 0.95 → 95.0
  // ai_assisted_pct = 0 / 1_680_000 = 0.0
  // ambiguous_pct = 84_000 / 1_680_000 = 0.05 → 5.0
  computed_authorship: {
    human_pct: 95.0,
    ai_assisted_pct: 0.0,
    ambiguous_pct: 5.0,
    confidence: "high",
  },
  classification_method: "confirmata_classifier_v1.0",
  policy_eligible_categories: [
    "academic_70_plus",
    "journalism_60_plus",
    "creative_writing_50_plus",
  ],
};

const COMP_HYBRID: CompositionAnalysis = {
  version: "1",
  total_session_ms: 3_600_000, // 60 min
  buckets: {
    human_active_ms: 1_700_000,
    ai_assisted_ms: 633_600,
    voice_authored_ms: 316_000,
    paste_inserted_ms: 230_400,
    context_review_ms: 540_000,
    idle_ms: 180_000,
  },
  // authorship_time = 3_600_000 - 540_000 - 180_000 = 2_880_000
  // human_pct = (1_700_000 + 316_000) / 2_880_000 = 0.70 → 70.0
  // ai_assisted_pct = 633_600 / 2_880_000 = 0.22 → 22.0
  // ambiguous_pct = 230_400 / 2_880_000 = 0.08 → 8.0
  computed_authorship: {
    human_pct: 70.0,
    ai_assisted_pct: 22.0,
    ambiguous_pct: 8.0,
    confidence: "high",
  },
  classification_method: "confirmata_classifier_v1.0",
  policy_eligible_categories: ["academic_70_plus", "journalism_60_plus"],
};

const COMP_MOSTLY_AI: CompositionAnalysis = {
  version: "1",
  total_session_ms: 2_700_000, // 45 min
  buckets: {
    human_active_ms: 500_000,
    ai_assisted_ms: 1_430_000,
    voice_authored_ms: 116_000,
    paste_inserted_ms: 154_000,
    context_review_ms: 300_000,
    idle_ms: 200_000,
  },
  // authorship_time = 2_700_000 - 300_000 - 200_000 = 2_200_000
  // human_pct = (500_000 + 116_000) / 2_200_000 = 0.28 → 28.0
  // ai_assisted_pct = 1_430_000 / 2_200_000 = 0.65 → 65.0
  // ambiguous_pct = 154_000 / 2_200_000 = 0.07 → 7.0
  computed_authorship: {
    human_pct: 28.0,
    ai_assisted_pct: 65.0,
    ambiguous_pct: 7.0,
    confidence: "medium",
  },
  classification_method: "confirmata_classifier_v1.0",
  policy_eligible_categories: [],
};

const PURE_HUMAN_CONTENT = new TextEncoder().encode(
  "a thirty-minute session where alice typed every word herself\n",
);
const HYBRID_CONTENT = new TextEncoder().encode(
  "a sixty-minute session with mixed human and AI authorship\n",
);
const MOSTLY_AI_CONTENT = new TextEncoder().encode(
  "a forty-five-minute session that leaned heavily on AI assistance\n",
);

const COMP_PURE_HUMAN_TESSERA = buildAuthorship({
  uuid: "cccc1111-1111-4111-8111-cccccccccccc",
  loa: 3,
  biometric: "webauthn_liveness",
  contentBytes: PURE_HUMAN_CONTENT,
  delegation: VALID_DELEGATION,
  version: "tessera/v0.2",
  session: makeSession(COMP_PURE_HUMAN.total_session_ms, "composition_pure_human"),
  aiDisclosure: "none",
  issuedAt: COMPOSITION_ISSUED_AT,
  composition: COMP_PURE_HUMAN,
});

const COMP_HYBRID_TESSERA = buildAuthorship({
  uuid: "cccc2222-2222-4222-8222-cccccccccccc",
  loa: 3,
  biometric: "webauthn_liveness",
  contentBytes: HYBRID_CONTENT,
  delegation: VALID_DELEGATION,
  version: "tessera/v0.2",
  session: makeSession(COMP_HYBRID.total_session_ms, "composition_hybrid"),
  aiDisclosure: "generation",
  issuedAt: COMPOSITION_ISSUED_AT,
  composition: COMP_HYBRID,
});

const COMP_MOSTLY_AI_TESSERA = buildAuthorship({
  uuid: "cccc3333-3333-4333-8333-cccccccccccc",
  loa: 2,
  biometric: "webauthn",
  contentBytes: MOSTLY_AI_CONTENT,
  delegation: VALID_DELEGATION,
  version: "tessera/v0.2",
  session: makeSession(COMP_MOSTLY_AI.total_session_ms, "composition_mostly_ai"),
  aiDisclosure: "generation",
  issuedAt: COMPOSITION_ISSUED_AT,
  composition: COMP_MOSTLY_AI,
});

await writeFile(
  "v0.2/composition_pure_human.json",
  {
    description:
      "v0.2 composition_analysis: 30-min session, ~95% human, 0% AI-assisted, 5% ambiguous, confidence high. Tests the high-human edge of the model.",
    ...bundle(COMP_PURE_HUMAN_TESSERA, VALID_DELEGATION),
  },
);
await writeFile(
  "v0.2/composition_hybrid.json",
  {
    description:
      "v0.2 composition_analysis: 60-min session, ~70% human, 22% AI-assisted, 8% ambiguous, confidence high. Tests the realistic mixed-authorship case (satisfies academic_70_plus and journalism_60_plus).",
    ...bundle(COMP_HYBRID_TESSERA, VALID_DELEGATION),
  },
);
await writeFile(
  "v0.2/composition_mostly_ai.json",
  {
    description:
      "v0.2 composition_analysis: 45-min session, ~28% human, 65% AI-assisted, 7% ambiguous, confidence medium. Tests the low-human-authorship edge (passes no policy_eligible_categories).",
    ...bundle(COMP_MOSTLY_AI_TESSERA, VALID_DELEGATION),
  },
);

console.log(`✓ wrote 3 v0.2 composition_analysis vectors under ${ROOT}/v0.2/`);
console.log(`  (v0.1 vectors under ${ROOT}/{authorship,delegation,revocation,fixtures} are pinned to their committed bytes — see note in this script.)`);

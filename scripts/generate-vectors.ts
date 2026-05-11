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
  type DelegationPayload,
  type RevocationPayload,
  type Tessera,
  type LOA,
  type BiometricMethod,
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
}

function buildAuthorship(o: AuthorshipOpts): Tessera {
  const contentHashHex = hex(sha256(o.contentBytes));
  const draft: Tessera = {
    version: "tessera/v0.1",
    type: "authorship",
    tessera_id: o.uuid,
    issuer: {
      user_handle: "alice",
      user_master_pubkey: masterPub,
      device_pubkey: devicePub,
      device_delegation_hash: hex(tesseraHash(o.delegation)),
    },
    claim: { loa: o.loa, issued_at: ISSUED_AT },
    type_payload: {
      subject: {
        content_hash: contentHashHex,
        content_size_bytes: o.contentBytes.length,
        content_mime: "text/plain",
        content_filename: "conformance.txt",
      },
      session: {
        started_at: ISSUED_AT,
        ended_at: ISSUED_AT,
        duration_ms: 0,
        tools_used: ["confirmata-conformance@v0.1"],
      },
      behavioral_fingerprint: base64urlEncode(sha256(o.contentBytes)),
      ai_assistance_disclosure: "none",
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

await writeFile("authorship/valid-loa2.json", bundle(VALID_LOA2, VALID_DELEGATION));
await writeFile("authorship/valid-loa3.json", bundle(VALID_LOA3, VALID_DELEGATION));
await writeFile("authorship/valid-loa4.json", bundle(VALID_LOA4, VALID_DELEGATION));
await writeFile("authorship/invalid-bad-signature.json", bundle(INVALID_BAD_SIG, VALID_DELEGATION));
await writeFile("authorship/invalid-bad-anchor.json", bundle(INVALID_BAD_ANCHOR, VALID_DELEGATION));
await writeFile("authorship/invalid-revoked.json", bundle(INVALID_REVOKED, VALID_DELEGATION));
await writeFile("authorship/invalid-content-mismatch.json", bundle(INVALID_CONTENT_MISMATCH, VALID_DELEGATION));
await writeFile("delegation/valid-chain.json", VALID_DELEGATION);
await writeFile("delegation/invalid-expired.json", EXPIRED_DELEGATION);
await writeFile("revocation/valid.json", REVOCATION_VALID);

// Sidecar content files
await fs.mkdir(path.join(ROOT, "fixtures"), { recursive: true });
await fs.writeFile(path.join(ROOT, "fixtures", "conformance-content.txt"), CONTENT_BYTES);
await fs.writeFile(path.join(ROOT, "fixtures", "mismatch-content.txt"), MISMATCH_CONTENT);
await fs.writeFile(path.join(ROOT, "fixtures", "revoked-content.txt"),
  new TextEncoder().encode("this content is targeted by a revocation\n"));

console.log(`✓ wrote 10 vectors + 3 fixture content files under ${ROOT}`);

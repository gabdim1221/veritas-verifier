/**
 * TypeScript types for Tessera v0.1 and v0.2.
 *
 * Source of truth: github.com/gabdim1221/confirmata-protocol/blob/main/spec/v0.2/tessera.md
 * If a field appears here that is not in the spec, that is a bug in this file.
 */

import type { VerificationErrorCode } from "./errors.js";

export type TesseraVersion = "tessera/v0.1" | "tessera/v0.2";

export type TesseraType =
  | "authorship"
  | "witness"
  | "covenant"
  | "delegation"
  | "revocation"
  | "attestation"
  | "lodestone";

export type LOA = 0 | 1 | 2 | 3 | 4;

// ---- envelope sub-types (spec §2) ----

export interface Issuer {
  user_handle: string;
  user_master_pubkey: string;       // base64url Ed25519 public key (32 bytes)
  device_pubkey: string;            // base64url Ed25519 public key (32 bytes)
  device_delegation_hash: string;   // sha256 hex of the delegation Tessera; empty
                                    // string for delegation Tesserae signed by the
                                    // master key directly (the bootstrap case)
}

export interface Claim {
  loa: LOA;
  issued_at: string;                // ISO-8601 UTC timestamp
}

export type BiometricMethod =
  | "webauthn"
  | "webauthn_liveness"
  | "kyc_bound"
  | "none";

export interface BiometricAttestation {
  method: BiometricMethod;
  authenticator_data?: string;      // base64url, when method != "none"
  client_data_json?: string;        // base64url, when method != "none"
}

export type AnchorService = "opentimestamps" | "rfc3161" | "custom";

export interface Anchor {
  service: AnchorService;
  ots_proof?: string;               // base64 OTS binary, when service = "opentimestamps"
  anchor_uri?: string;              // optional URI to standalone proof file
}

export interface Signature {
  algorithm: "Ed25519";
  value: string;                    // base64url Ed25519 signature
}

// ---- per-type payloads (spec §7) ----

/**
 * Several spec fields are described as "free text or structured claim" —
 * we model that as either a string or a JSON object. The verifier does not
 * impose semantic constraints on these payload contents.
 */
export type StructuredClaim = string | Record<string, unknown>;

export type AIAssistanceDisclosure =
  | "none"
  | "spell_check"
  | "grammar"
  | "research"
  | "generation"
  | "other";

/** §7.1 authorship */
export interface AuthorshipPayload {
  subject: {
    content_hash: string;           // sha256 hex of the work
    content_size_bytes: number;
    content_mime: string;
    content_filename?: string;
    content_uri?: string;
  };
  session: {
    started_at: string;
    ended_at: string;
    duration_ms: number;
    tools_used: string[];
  };
  behavioral_fingerprint: string;   // base64url sha256 of fingerprint vector
  process_recording_hash?: string;  // base64url sha256 of encrypted recording
  ai_assistance_disclosure: AIAssistanceDisclosure;
}

/** §7.2 witness */
export interface WitnessPayload {
  observation: StructuredClaim;
  subject_hash?: string;
  location?: {
    latitude: number;
    longitude: number;
    accuracy_m: number;
  };
}

/** §7.3 covenant */
export interface CovenantPayload {
  covenant_id: string;
  parties: string[];
  terms: StructuredClaim;
  subject_hash?: string;
  effective_from: string;
  effective_until: string | null;
  co_signatures?: Tessera[];
}

/** §7.4 delegation (and §6 device delegation) */
export interface DelegationPayload {
  delegated_pubkey: string;         // base64url device public key
  device_name: string;
  device_platform: string;          // e.g. "macos" | "ios" | "browser_chrome" | …
  scope: string[];                  // e.g. ["sign:authorship", "sign:witness"]
  valid_from: string;
  valid_until: string | null;
}

/** §7.5 revocation */
export type RevocationReason =
  | "compromised"
  | "mistake"
  | "retracted"
  | "superseded"
  | "other";

export interface RevocationPayload {
  revoked_tessera_hash: string;     // sha256 hex
  reason: RevocationReason;
  reason_text?: string;
}

/** §7.6 attestation */
export interface AttestationPayload {
  subject_handle: string;
  subject_master_pubkey: string;
  claim: StructuredClaim;
  valid_from: string;
  valid_until: string | null;
}

/** §7.7 lodestone */
export interface LodestonePayload {
  topic: string;
  stance: StructuredClaim;
  supersedes?: string;              // sha256 of prior lodestone on same topic
}

// ---- composition analysis (spec v0.2 §13) ----

export type CompositionConfidence = "high" | "medium" | "low";

export interface CompositionBuckets {
  human_active_ms: number;
  ai_assisted_ms: number;
  voice_authored_ms: number;
  paste_inserted_ms: number;
  context_review_ms: number;
  idle_ms: number;
}

export interface ComputedAuthorship {
  human_pct: number;
  ai_assisted_pct: number;
  ambiguous_pct: number;
  confidence: CompositionConfidence;
}

/**
 * §13 v0.2 composition_analysis sub-schema. OPTIONAL top-level field on
 * authorship Tesserae. Verifiers MUST validate invariants 1–6 when present
 * (§13.3) and reject with COMPOSITION_INVARIANT_VIOLATION on failure.
 */
export interface CompositionAnalysis {
  version: "1";
  total_session_ms: number;
  buckets: CompositionBuckets;
  computed_authorship: ComputedAuthorship;
  classification_method: string;        // /^[a-z_]+_classifier_v\d+\.\d+$/
  policy_eligible_categories?: string[];
}

// ---- envelope (spec §2) ----

interface BaseEnvelope {
  version: TesseraVersion;
  tessera_id: string;               // UUID v4
  issuer: Issuer;
  claim: Claim;
  biometric_attestation: BiometricAttestation;
  anchor: Anchor;
  signature: Signature;
  /** v0.2 only: present on authorship Tesserae issued by capture-enabled clients. */
  composition_analysis?: CompositionAnalysis;
}

/**
 * The Tessera envelope, with `type` discriminating `type_payload`.
 *
 * Implementations MAY include additional fields in any object as long as the
 * canonicalization and signing rules are preserved (spec §12). Verifiers MUST
 * ignore unknown fields rather than reject the Tessera.
 */
export type Tessera =
  | (BaseEnvelope & { type: "authorship";  type_payload: AuthorshipPayload  })
  | (BaseEnvelope & { type: "witness";     type_payload: WitnessPayload     })
  | (BaseEnvelope & { type: "covenant";    type_payload: CovenantPayload    })
  | (BaseEnvelope & { type: "delegation";  type_payload: DelegationPayload  })
  | (BaseEnvelope & { type: "revocation";  type_payload: RevocationPayload  })
  | (BaseEnvelope & { type: "attestation"; type_payload: AttestationPayload })
  | (BaseEnvelope & { type: "lodestone";   type_payload: LodestonePayload   });

// ---- verification result (spec §8) ----

export type AnchorStatus = "confirmed" | "pending";

export interface VerificationSuccess {
  valid: true;
  loa: LOA;
  issuedAt: string;                 // copy of claim.issued_at
  anchorStatus: AnchorStatus;
  anchoredAtBlock?: number;         // present when anchorStatus === "confirmed"
  anchoredAtTime?: string;          // ISO-8601 of the Bitcoin block time
  authorHandle: string;             // copy of issuer.user_handle
}

export interface VerificationFailure {
  valid: false;
  errorCode: VerificationErrorCode;
  errorMessage: string;
  details?: unknown;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;

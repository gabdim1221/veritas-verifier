/**
 * Main verifier — implements spec §8 verbatim.
 *
 * Returns a structured VerificationResult, never throws on verification
 * failure. The only thrown errors are programmer errors (e.g. a Tessera
 * that requires a delegation lookup but no fetchDelegation callback
 * was supplied).
 */

import type {
  Tessera,
  VerificationResult,
  VerificationFailure,
  AnchorStatus,
  AuthorshipPayload,
  CompositionAnalysis,
} from "./types.js";
import { VerificationErrorCode } from "./errors.js";
import { canonicalizeForSigning, tesseraHash, hex } from "./canonicalize.js";
import { verifySignature } from "./ed25519.js";
// Type-only import: keeps src/ots.js (and its `opentimestamps` dep) out of
// the browser bundle. Callers supply a concrete verifyAnchor implementation.
import type { OTSResult } from "./ots.js";
import { verifyDelegation } from "./delegation.js";
import { sha256 } from "@noble/hashes/sha2.js";

export interface VerifyOptions {
  /** Resolves a delegation Tessera by its sha256 hex hash. Required for
   *  any non-delegation Tessera. */
  fetchDelegation?: (hash: string) => Promise<Tessera | null>;
  /** Returns true if the Tessera (identified by hex sha256) has been revoked. */
  isRevoked?: (tesseraHashHex: string) => Promise<boolean>;
  /** Original content bytes; if provided and the Tessera is `authorship`,
   *  verifier checks SHA-256 against type_payload.subject.content_hash. */
  content?: Uint8Array;
  /** Minimum LOA the verifier requires. Default 0. */
  requiredLoa?: number;
  /** Maximum allowed clock skew between claim.issued_at and the anchor
   *  block time, in seconds. Default 86400 (24 h). */
  maxClockSkewSec?: number;
  /** If true, a pending OTS proof yields ANCHOR_PENDING failure rather
   *  than a successful result with anchorStatus="pending". Default false. */
  requireConfirmedAnchor?: boolean;
  /** Anchor verifier. Required. Node consumers typically pass
   *  `verifyOtsProof` from `@confirmata/verifier/ots-node`; browsers can pass
   *  a stub (e.g. one that always returns `{ status: "pending" }`) until
   *  in-browser OTS is wired. */
  verifyAnchor?: (proofB64: string, expectedHash: Uint8Array) => Promise<OTSResult>;
}

function failure(
  code: VerificationErrorCode,
  message: string,
  details?: unknown,
): VerificationFailure {
  return { valid: false, errorCode: code, errorMessage: message, details };
}

/**
 * Validate composition_analysis invariants 1–6 from spec/v0.2/tessera.md §13.3.
 * Returns null when all invariants hold, otherwise a human-readable error string.
 *
 * Invariants 1 and 2 use ±100ms and ±1.0pp rounding tolerances per the spec.
 * Invariant 3 (non-negativity) and 6 (required sub-fields) are partially
 * enforced by the type system but re-checked at runtime for untrusted input.
 */
export function checkCompositionInvariants(ca: CompositionAnalysis): string | null {
  // Invariant 6: required sub-fields (re-check runtime shape)
  if (
    ca.version !== "1" ||
    !Number.isFinite(ca.total_session_ms) ||
    !ca.buckets ||
    !ca.computed_authorship ||
    typeof ca.classification_method !== "string"
  ) {
    return "composition_analysis: missing or malformed required sub-fields";
  }
  if (!/^[a-z_]+_classifier_v\d+\.\d+$/.test(ca.classification_method)) {
    return `composition_analysis.classification_method has invalid format: ${ca.classification_method}`;
  }
  const b = ca.buckets;
  const bucketKeys: (keyof typeof b)[] = [
    "human_active_ms",
    "ai_assisted_ms",
    "voice_authored_ms",
    "paste_inserted_ms",
    "context_review_ms",
    "idle_ms",
  ];
  // Invariant 3: non-negativity of _ms
  for (const k of bucketKeys) {
    if (!Number.isFinite(b[k]) || b[k] < 0) {
      return `composition_analysis.buckets.${k}: must be >= 0`;
    }
  }
  // Invariant 1: bucket sum == total_session_ms ±100ms
  const bucketSum = bucketKeys.reduce((s, k) => s + b[k], 0);
  if (Math.abs(bucketSum - ca.total_session_ms) > 100) {
    return `composition_analysis: bucket sum ${bucketSum} != total_session_ms ${ca.total_session_ms} (±100ms tolerance)`;
  }
  // Invariant 4: authorship_time minimum
  const authorshipTime = ca.total_session_ms - b.context_review_ms - b.idle_ms;
  if (authorshipTime < 1000) {
    return `composition_analysis: authorship_time ${authorshipTime}ms < 1000ms; field must be omitted for sub-second sessions`;
  }
  const ca2 = ca.computed_authorship;
  // Invariant 3: percentage range
  for (const k of ["human_pct", "ai_assisted_pct", "ambiguous_pct"] as const) {
    if (!Number.isFinite(ca2[k]) || ca2[k] < 0 || ca2[k] > 100) {
      return `composition_analysis.computed_authorship.${k}: must be in [0, 100]`;
    }
  }
  // Invariant 2: percentage sum in [99.0, 101.0]
  const pctSum = ca2.human_pct + ca2.ai_assisted_pct + ca2.ambiguous_pct;
  if (pctSum < 99.0 || pctSum > 101.0) {
    return `composition_analysis: percentage sum ${pctSum.toFixed(2)} not in [99.0, 101.0]`;
  }
  // Invariant 5 (voice → human) is a classifier-side rule; the verifier
  // cannot independently confirm voice classification, but enforces the
  // human_pct formula against the buckets the issuer reported.
  const expectedHumanPct = (b.human_active_ms + b.voice_authored_ms) / authorshipTime * 100;
  if (Math.abs(expectedHumanPct - ca2.human_pct) > 1.0) {
    return `composition_analysis: computed human_pct ${ca2.human_pct.toFixed(2)} disagrees with (human_active+voice)/authorship_time = ${expectedHumanPct.toFixed(2)} (±1pp)`;
  }
  if (!["high", "medium", "low"].includes(ca2.confidence)) {
    return `composition_analysis.computed_authorship.confidence: invalid value ${String(ca2.confidence)}`;
  }
  return null;
}

const KNOWN_TYPES = new Set([
  "authorship",
  "witness",
  "covenant",
  "delegation",
  "revocation",
  "attestation",
  "lodestone",
]);

function validateSchema(t: unknown): VerificationFailure | null {
  if (!t || typeof t !== "object") {
    return failure(VerificationErrorCode.INVALID_SCHEMA, "tessera is not an object");
  }
  const o = t as Record<string, unknown>;
  if (o.version !== "tessera/v0.1" && o.version !== "tessera/v0.2") {
    return failure(VerificationErrorCode.INVALID_SCHEMA, `unknown version: ${String(o.version)}`);
  }
  if (typeof o.type !== "string" || !KNOWN_TYPES.has(o.type)) {
    return failure(VerificationErrorCode.INVALID_SCHEMA, `unknown type: ${String(o.type)}`);
  }
  for (const k of [
    "tessera_id",
    "issuer",
    "claim",
    "type_payload",
    "biometric_attestation",
    "anchor",
    "signature",
  ]) {
    if (!(k in o)) {
      return failure(VerificationErrorCode.INVALID_SCHEMA, `missing field: ${k}`);
    }
  }
  const sig = o.signature as { algorithm?: unknown; value?: unknown } | undefined;
  if (!sig || sig.algorithm !== "Ed25519" || typeof sig.value !== "string") {
    return failure(VerificationErrorCode.INVALID_SCHEMA, "invalid signature object");
  }
  const issuer = o.issuer as Record<string, unknown> | undefined;
  if (
    !issuer ||
    typeof issuer.user_handle !== "string" ||
    typeof issuer.user_master_pubkey !== "string" ||
    typeof issuer.device_pubkey !== "string" ||
    typeof issuer.device_delegation_hash !== "string"
  ) {
    return failure(VerificationErrorCode.INVALID_SCHEMA, "invalid issuer object");
  }
  const claim = o.claim as { loa?: unknown; issued_at?: unknown } | undefined;
  if (
    !claim ||
    typeof claim.loa !== "number" ||
    !Number.isInteger(claim.loa) ||
    claim.loa < 0 ||
    claim.loa > 4 ||
    typeof claim.issued_at !== "string"
  ) {
    return failure(VerificationErrorCode.INVALID_SCHEMA, "invalid claim object");
  }
  const anchor = o.anchor as { service?: unknown; ots_proof?: unknown } | undefined;
  if (!anchor || typeof anchor.service !== "string") {
    return failure(VerificationErrorCode.INVALID_SCHEMA, "invalid anchor object");
  }
  return null;
}

export async function verify(
  tessera: Tessera,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const maxSkewSec = options.maxClockSkewSec ?? 86400;
  const requiredLoa = options.requiredLoa ?? 0;
  const verifyAnchor = options.verifyAnchor;
  if (!verifyAnchor) {
    throw new Error(
      "verify(): options.verifyAnchor is required. Node: import { verifyOtsProof } from '@confirmata/verifier/ots-node'. Browser: pass a stub.",
    );
  }

  // 1. Schema validation
  const schemaErr = validateSchema(tessera);
  if (schemaErr) return schemaErr;

  // 2. Canonicalize and verify signature against device pubkey
  const message = canonicalizeForSigning(tessera);
  if (!verifySignature(tessera.signature.value, message, tessera.issuer.device_pubkey)) {
    return failure(
      VerificationErrorCode.INVALID_SIGNATURE,
      "Ed25519 signature does not verify against issuer.device_pubkey",
    );
  }

  // 3. Delegation chain (skipped for delegation Tesserae — those are signed
  //    by the master key directly, which step 2 already verified since
  //    issuer.device_pubkey === issuer.user_master_pubkey for delegations.)
  if (tessera.type !== "delegation") {
    if (!options.fetchDelegation) {
      throw new Error(
        "verify(): non-delegation Tesserae require options.fetchDelegation to resolve the device delegation",
      );
    }
    const delegation = await options.fetchDelegation(tessera.issuer.device_delegation_hash);
    if (!delegation) {
      return failure(
        VerificationErrorCode.DELEGATION_NOT_FOUND,
        `delegation ${tessera.issuer.device_delegation_hash} not found`,
      );
    }
    const delResult = await verifyDelegation(
      delegation,
      tessera.type,
      tessera.claim.issued_at,
      tessera.issuer.device_pubkey,
      tessera.issuer.user_master_pubkey,
    );
    if (!delResult.valid) {
      return failure(
        delResult.errorCode ?? VerificationErrorCode.INVALID_DELEGATION_SIGNATURE,
        delResult.details ?? "delegation invalid",
      );
    }
    if (options.isRevoked) {
      const delegationHashHex = hex(tesseraHash(delegation));
      if (await options.isRevoked(delegationHashHex)) {
        return failure(
          VerificationErrorCode.DELEGATION_REVOKED,
          "delegation has been revoked",
        );
      }
    }
  }

  // 4. Time anchor
  let anchorStatus: AnchorStatus = "pending";
  let anchoredAtBlock: number | undefined;
  let anchoredAtTime: string | undefined;

  if (tessera.anchor.service === "opentimestamps") {
    if (!tessera.anchor.ots_proof) {
      return failure(VerificationErrorCode.INVALID_ANCHOR, "anchor.ots_proof missing");
    }
    const fullHash = tesseraHash(tessera);
    const ots = await verifyAnchor(tessera.anchor.ots_proof, fullHash);
    if (ots.status === "invalid") {
      return failure(
        VerificationErrorCode.INVALID_ANCHOR,
        ots.details ?? "OTS proof invalid",
      );
    }
    if (ots.status === "confirmed") {
      anchorStatus = "confirmed";
      anchoredAtBlock = ots.blockHeight;
      anchoredAtTime = ots.blockTime?.toISOString();
      const issuedMs = new Date(tessera.claim.issued_at).getTime();
      const blockMs = ots.blockTime?.getTime() ?? 0;
      if (Math.abs(blockMs - issuedMs) > maxSkewSec * 1000) {
        return failure(
          VerificationErrorCode.ANCHOR_TIME_MISMATCH,
          `clock skew |${(blockMs - issuedMs) / 1000}s| exceeds ${maxSkewSec}s`,
        );
      }
    } else {
      // status === "pending"
      if (options.requireConfirmedAnchor) {
        return failure(
          VerificationErrorCode.ANCHOR_PENDING,
          "OTS proof not yet confirmed on Bitcoin",
        );
      }
    }
  } else {
    return failure(
      VerificationErrorCode.INVALID_ANCHOR,
      `unsupported anchor service: ${tessera.anchor.service}`,
    );
  }

  // 5. Revocation of the content tessera itself
  if (options.isRevoked) {
    const thisHashHex = hex(tesseraHash(tessera));
    if (await options.isRevoked(thisHashHex)) {
      return failure(VerificationErrorCode.REVOKED, "tessera has been revoked");
    }
  }

  // 6. Content hash check (authorship only, when content provided)
  if (options.content && tessera.type === "authorship") {
    const payload = tessera.type_payload as AuthorshipPayload;
    const computed = sha256(options.content);
    if (hex(computed) !== payload.subject.content_hash) {
      return failure(
        VerificationErrorCode.CONTENT_MISMATCH,
        "SHA-256 of provided content does not match type_payload.subject.content_hash",
      );
    }
  }

  // 7. LOA check
  if (tessera.claim.loa < requiredLoa) {
    return failure(
      VerificationErrorCode.LOA_INSUFFICIENT,
      `LOA ${tessera.claim.loa} < required ${requiredLoa}`,
    );
  }

  // 8. Composition analysis invariants (v0.2 §13.3, when present)
  if (tessera.composition_analysis !== undefined) {
    const violation = checkCompositionInvariants(tessera.composition_analysis);
    if (violation !== null) {
      return failure(VerificationErrorCode.COMPOSITION_INVARIANT_VIOLATION, violation);
    }
  }

  return {
    valid: true,
    loa: tessera.claim.loa,
    issuedAt: tessera.claim.issued_at,
    anchorStatus,
    anchoredAtBlock,
    anchoredAtTime,
    authorHandle: tessera.issuer.user_handle,
  };
}

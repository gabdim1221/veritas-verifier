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
  if (o.version !== "tessera/v0.1") {
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

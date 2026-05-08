/**
 * Delegation chain verification (spec §6).
 *
 * A delegation Tessera authorizes a device key to sign content of a given
 * scope, on behalf of a master key, within a validity window. This module
 * verifies a single delegation independently. Whether the delegation has
 * been REVOKED is a separate concern handled by the verify() caller via
 * the isRevoked option.
 */

import type { Tessera, DelegationPayload } from "./types.js";
import { canonicalizeForSigning } from "./canonicalize.js";
import { verifySignature } from "./ed25519.js";
import { VerificationErrorCode } from "./errors.js";

export interface DelegationCheckResult {
  valid: boolean;
  errorCode?: VerificationErrorCode;
  details?: string;
}

function tsToMs(s: string): number {
  const ms = new Date(s).getTime();
  if (Number.isNaN(ms)) throw new Error(`invalid ISO-8601: ${s}`);
  return ms;
}

export async function verifyDelegation(
  delegation: Tessera,
  contentTesseraType: string,
  contentIssuedAt: string,
  expectedDevicePubkey: string,
  masterPubkey: string,
): Promise<DelegationCheckResult> {
  if (delegation.type !== "delegation") {
    return {
      valid: false,
      errorCode: VerificationErrorCode.INVALID_DELEGATION_SIGNATURE,
      details: `delegation Tessera has wrong type: ${delegation.type}`,
    };
  }

  // 1. Signature: the delegation must be signed by the master key.
  const message = canonicalizeForSigning(delegation);
  if (!verifySignature(delegation.signature.value, message, masterPubkey)) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.INVALID_DELEGATION_SIGNATURE,
      details: "delegation signature does not verify against master pubkey",
    };
  }

  const payload = delegation.type_payload as DelegationPayload;

  // 2. The delegated pubkey in the delegation must match the device pubkey
  //    that signed the content Tessera.
  if (payload.delegated_pubkey !== expectedDevicePubkey) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.DELEGATION_KEY_MISMATCH,
      details: `delegated_pubkey does not match content's device_pubkey`,
    };
  }

  // 3. Validity window must cover the content's issued_at.
  let issuedMs: number;
  let validFromMs: number;
  let validUntilMs: number | null;
  try {
    issuedMs = tsToMs(contentIssuedAt);
    validFromMs = tsToMs(payload.valid_from);
    validUntilMs = payload.valid_until === null ? null : tsToMs(payload.valid_until);
  } catch (err) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.DELEGATION_EXPIRED,
      details: err instanceof Error ? err.message : String(err),
    };
  }
  if (validFromMs > issuedMs) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.DELEGATION_EXPIRED,
      details: "content issued before delegation valid_from",
    };
  }
  if (validUntilMs !== null && validUntilMs < issuedMs) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.DELEGATION_EXPIRED,
      details: "content issued after delegation valid_until",
    };
  }

  // 4. Scope must permit the content Tessera type.
  const wanted = `sign:${contentTesseraType}`;
  if (!payload.scope.includes(wanted) && !payload.scope.includes("sign:*")) {
    return {
      valid: false,
      errorCode: VerificationErrorCode.INVALID_DELEGATION_SIGNATURE,
      details: `delegation scope does not include ${wanted}`,
    };
  }

  return { valid: true };
}

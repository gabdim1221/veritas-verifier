import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Tessera } from "./types.js";

/**
 * Compute the canonical bytes of a Tessera with `signature` AND the
 * late-added anchor fields (`ots_proof`, `anchor_uri`) removed. These bytes
 * are what the device key signs.
 *
 * Spec §3 says only "Remove the `signature` field." Stripping ots_proof
 * too is required because the signature is produced BEFORE the OTS proof
 * is fetched (the issuer signs, then submits the resulting tessera-hash
 * to a calendar, then embeds the returned proof). If the proof bytes were
 * part of the signed canonicalization, embedding the proof would break
 * the signature, and upgrading the proof later would break it again.
 *
 * Symmetric with {@link tesseraHash}, which strips the same anchor fields.
 *
 * Spec ambiguity flagged for v0.2: §2/§3 should explicitly enumerate which
 * fields are excluded from the signing message and from the identity hash.
 */
export function canonicalizeForSigning(tessera: Tessera): Uint8Array {
  const copy = JSON.parse(JSON.stringify(tessera)) as Record<string, unknown>;
  delete copy.signature;
  const anchor = copy.anchor as Record<string, unknown> | undefined;
  if (anchor) {
    delete anchor.ots_proof;
    delete anchor.anchor_uri;
  }
  const canonical = canonicalize(copy);
  if (canonical === undefined) {
    throw new Error("JCS canonicalization returned undefined");
  }
  return new TextEncoder().encode(canonical);
}

/**
 * Compute the SHA-256 hash of the signed Tessera, used for OpenTimestamps
 * anchoring and the public short_hash.
 *
 * Spec §3 says "Run JCS over the complete signed Tessera." Taken literally
 * this creates a recursion (the OTS proof commits to a hash that includes
 * the proof bytes themselves). We resolve the recursion by stripping the
 * late-added anchor fields — `ots_proof` and `anchor_uri` — before hashing.
 * The signature is preserved (it was computed over a signature-stripped
 * canonicalization, but its value IS part of the identity hash).
 *
 * Both the issuer (who computes the hash, submits to OTS, then embeds the
 * proof) and the verifier (who strips and recomputes) run the same
 * function, so the hash that the OTS proof commits to is reproducible.
 *
 * Spec ambiguity flagged for v0.2: §3 should explicitly enumerate which
 * fields are included in the hash input.
 */
export function tesseraHash(tessera: Tessera): Uint8Array {
  const copy = JSON.parse(JSON.stringify(tessera)) as Record<string, unknown>;
  const anchor = copy.anchor as Record<string, unknown> | undefined;
  if (anchor) {
    delete anchor.ots_proof;
    delete anchor.anchor_uri;
  }
  const canonical = canonicalize(copy);
  if (canonical === undefined) {
    throw new Error("JCS canonicalization returned undefined");
  }
  const bytes = new TextEncoder().encode(canonical);
  return sha256(bytes);
}

/** Hex-encode a byte array (lowercase). */
export function hex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

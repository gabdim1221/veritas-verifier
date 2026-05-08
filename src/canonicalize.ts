import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Tessera } from "./types.js";

/**
 * Compute the canonical bytes of a Tessera with the `signature` field removed.
 * This is the message that gets signed.
 *
 * Per spec §3:
 *   1. Build the Tessera object.
 *   2. Remove the `signature` field.
 *   3. Serialize using JCS rules (RFC 8785).
 *   4. Return UTF-8 bytes.
 */
export function canonicalizeForSigning(tessera: Tessera): Uint8Array {
  const copy = JSON.parse(JSON.stringify(tessera)) as Record<string, unknown>;
  delete copy.signature;
  const canonical = canonicalize(copy);
  if (canonical === undefined) {
    throw new Error("JCS canonicalization returned undefined");
  }
  return new TextEncoder().encode(canonical);
}

/**
 * Compute the SHA-256 hash of the complete signed Tessera.
 * This is the value anchored on OpenTimestamps and used to derive the
 * public short_hash.
 */
export function tesseraHash(tessera: Tessera): Uint8Array {
  const canonical = canonicalize(tessera as unknown as Record<string, unknown>);
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

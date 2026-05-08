import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

// @noble/ed25519 v3 ships sync APIs but requires a sha512 implementation to be
// supplied at module load. The library does not bundle one (works in browsers
// only via the *Async variants backed by Web Crypto).
ed.hashes.sha512 = sha512;

// ---- base64url codecs (cross-runtime: Node 16+, modern browsers, edge) ----

/** Encode bytes to base64url (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/** Decode base64url (with or without padding) to bytes. */
export function base64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const bin = atob(padded + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- Ed25519 ----

/**
 * Verify an Ed25519 signature.
 * @param signatureB64u  base64url signature (64 bytes raw)
 * @param message        canonical bytes that were signed
 * @param pubkeyB64u     base64url Ed25519 public key (32 bytes raw)
 */
export function verifySignature(
  signatureB64u: string,
  message: Uint8Array,
  pubkeyB64u: string,
): boolean {
  try {
    const sig = base64urlDecode(signatureB64u);
    const pk = base64urlDecode(pubkeyB64u);
    return ed.verify(sig, message, pk);
  } catch {
    return false;
  }
}

/** Sign a message with an Ed25519 secret key. Used by the issuer CLI. */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed.sign(message, secretKey);
}

/** Generate a fresh keypair. Used by the issuer CLI for setup. */
export function generateKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  // v3 renamed randomPrivateKey → randomSecretKey; we keep the public name
  // `privateKey` for ergonomic continuity with the rest of the codebase.
  const privateKey = ed.utils.randomSecretKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

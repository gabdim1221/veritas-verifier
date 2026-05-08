import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  sign,
  verifySignature,
  base64urlEncode,
  base64urlDecode,
} from "../src/ed25519.js";

describe("ed25519", () => {
  it("generates a 32-byte private key and 32-byte public key", () => {
    const { privateKey, publicKey } = generateKeypair();
    expect(privateKey).toHaveLength(32);
    expect(publicKey).toHaveLength(32);
  });

  it("sign-then-verify round trip succeeds", () => {
    const { privateKey, publicKey } = generateKeypair();
    const message = new TextEncoder().encode("hello, tessera");
    const sig = sign(message, privateKey);
    const sigB64u = base64urlEncode(sig);
    const pkB64u = base64urlEncode(publicKey);
    expect(verifySignature(sigB64u, message, pkB64u)).toBe(true);
  });

  it("rejects a tampered message", () => {
    const { privateKey, publicKey } = generateKeypair();
    const message = new TextEncoder().encode("hello, tessera");
    const tampered = new TextEncoder().encode("hello, tampered");
    const sig = sign(message, privateKey);
    const sigB64u = base64urlEncode(sig);
    const pkB64u = base64urlEncode(publicKey);
    expect(verifySignature(sigB64u, tampered, pkB64u)).toBe(false);
  });

  it("rejects a wrong public key", () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const message = new TextEncoder().encode("hello");
    const sig = sign(message, a.privateKey);
    expect(
      verifySignature(base64urlEncode(sig), message, base64urlEncode(b.publicKey)),
    ).toBe(false);
  });

  it("base64url encoding has no +/= characters", () => {
    const buf = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    const encoded = base64urlEncode(buf);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });

  it("base64url decode is the inverse of encode (round trip across all byte values)", () => {
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it("rejects a malformed signature without throwing", () => {
    const { publicKey } = generateKeypair();
    const message = new TextEncoder().encode("x");
    expect(verifySignature("notavalidsignature", message, base64urlEncode(publicKey))).toBe(
      false,
    );
  });
});

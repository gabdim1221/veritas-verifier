/**
 * OpenTimestamps proof verification (spec §5).
 *
 * The OTS proof is the cryptographic timestamp anchor that binds a Tessera's
 * existence to the Bitcoin clock. We treat three statuses:
 *
 *   confirmed  — the proof is upgraded against a Bitcoin block header
 *                (returns blockHeight + blockTime)
 *   pending    — the proof was accepted by an OTS calendar but not yet
 *                attested to a Bitcoin block (typically <1h after issuance)
 *   invalid    — the proof is malformed or its file digest does not match
 *                the expected SHA-256 hash
 *
 * The verifier's caller (verify.ts) decides whether `pending` is a hard
 * failure or a soft warning per the verifier's policy.
 */

import ots, { DetachedTimestampFile } from "opentimestamps";

export interface OTSResult {
  status: "confirmed" | "pending" | "invalid";
  blockHeight?: number;
  blockTime?: Date;
  details?: string;
}

function fromBase64(s: string): Buffer {
  return Buffer.from(s, "base64");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Verify an OpenTimestamps proof against an expected SHA-256 hash.
 *
 * Pending proofs do NOT throw — they return `{ status: "pending" }`. Only
 * malformed proofs and digest mismatches yield `"invalid"`.
 */
export async function verifyOtsProof(
  otsProofB64: string,
  expectedHash: Uint8Array,
): Promise<OTSResult> {
  let detached: DetachedTimestampFile | null = null;
  try {
    const proofBytes = fromBase64(otsProofB64);
    const ctx = new ots.Context.StreamDeserialization(proofBytes);
    detached = ots.DetachedTimestampFile.deserialize(ctx);
  } catch (err) {
    return {
      status: "invalid",
      details: `failed to deserialize OTS proof: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!detached) {
    return { status: "invalid", details: "OTS proof yielded null DetachedTimestampFile" };
  }

  // Sanity: the proof's file digest must match the expected Tessera hash.
  try {
    const fileDigest = detached.fileDigest();
    if (!bytesEqual(new Uint8Array(fileDigest), expectedHash)) {
      return { status: "invalid", details: "fileDigest does not match expected hash" };
    }
  } catch (err) {
    return {
      status: "invalid",
      details: `failed to read fileDigest: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let result: Record<string, { height?: number; timestamp?: number; time?: number } | undefined>;
  try {
    const sha256Op = new ots.Ops.OpSHA256();
    const dataDetached = ots.DetachedTimestampFile.fromHash(sha256Op, Buffer.from(expectedHash));
    result = await ots.verify(detached, dataDetached);
  } catch (err) {
    // verify() can throw for malformed internal proof structure; treat as invalid.
    return {
      status: "invalid",
      details: `verify() threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (result && typeof result === "object") {
    const chains = Object.keys(result);
    if (chains.length > 0) {
      const att = result.bitcoin ?? result[chains[0]];
      if (att) {
        const epoch = att.timestamp ?? att.time ?? 0;
        return {
          status: "confirmed",
          blockHeight: att.height,
          blockTime: new Date(epoch * 1000),
        };
      }
    }
  }
  return { status: "pending" };
}

/**
 * Attempt to upgrade a pending proof against a calendar server.
 * Returns the upgraded proof base64, or null if not yet upgradable / on error.
 *
 * NOTE: This makes a network call to OTS calendar servers. Callers should not
 * invoke it from request hot paths.
 */
export async function upgradeOtsProof(otsProofB64: string): Promise<string | null> {
  try {
    const proofBytes = fromBase64(otsProofB64);
    const ctx = new ots.Context.StreamDeserialization(proofBytes);
    const detached = ots.DetachedTimestampFile.deserialize(ctx);
    const wasUpgraded = await ots.upgrade(detached);
    if (!wasUpgraded) return null;
    const out = detached.serializeToBytes();
    return Buffer.from(out).toString("base64");
  } catch {
    return null;
  }
}

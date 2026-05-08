/**
 * OpenTimestamps issuance helper for the veritas CLI.
 *
 * Submits a SHA-256 hash to OTS calendar servers and returns the resulting
 * pending proof base64. On network failure, returns null and the caller
 * decides whether to proceed with an unanchored Tessera (and run
 * `veritas upgrade` later) or to abort.
 */

import ots from "opentimestamps";

export interface AnchorOutcome {
  proofB64: string | null;
  error?: string;
}

/**
 * Submit `hash` to OTS calendars and return the pending proof bytes as
 * base64. The call is bounded by `timeoutMs`.
 */
export async function submitToOTS(
  hash: Uint8Array,
  timeoutMs = 30_000,
): Promise<AnchorOutcome> {
  try {
    const sha256Op = new ots.Ops.OpSHA256();
    const detached = ots.DetachedTimestampFile.fromHash(sha256Op, Buffer.from(hash));

    const stampPromise = ots.stamp(detached);
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`OTS submit timed out after ${timeoutMs}ms`)), timeoutMs),
    );
    await Promise.race([stampPromise, timeout]);

    const proofBytes = detached.serializeToBytes();
    return { proofB64: Buffer.from(proofBytes).toString("base64") };
  } catch (err) {
    return { proofB64: null, error: err instanceof Error ? err.message : String(err) };
  }
}

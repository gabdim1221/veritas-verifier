export * from "./types.js";
export * from "./errors.js";
export { verify } from "./verify.js";
export type { VerifyOptions } from "./verify.js";
export {
  canonicalizeForSigning,
  tesseraHash,
  hex,
} from "./canonicalize.js";
export {
  verifySignature,
  sign,
  generateKeypair,
  base64urlEncode,
  base64urlDecode,
} from "./ed25519.js";
// OTS functions live at "@confirmata/verifier/ots-node" so the main entry stays
// browser-friendly (no Node-only `opentimestamps` dep in the bundle). Only
// the result TYPE is re-exported here.
export type { OTSResult } from "./ots.js";
export { verifyDelegation, type DelegationCheckResult } from "./delegation.js";

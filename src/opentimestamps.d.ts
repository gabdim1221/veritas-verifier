/**
 * Minimal ambient types for the `opentimestamps` package.
 * The package ships no .d.ts; we declare just enough for ots.ts to compile.
 * See node_modules/opentimestamps for the canonical JS source of truth.
 */
declare module "opentimestamps" {
  export interface Attestation {
    height?: number;
    timestamp?: number;
    time?: number;
  }

  export type VerifyResult = Record<string, Attestation | undefined>;

  export class DetachedTimestampFile {
    static deserialize(ctx: unknown): DetachedTimestampFile;
    static fromBytes(op: unknown, bytes: Uint8Array | Buffer): DetachedTimestampFile;
    static fromHash(op: unknown, hash: Uint8Array | Buffer): DetachedTimestampFile;
    fileDigest(): Uint8Array;
    serialize(ctx?: unknown): unknown;
    serializeToBytes(): Buffer;
    toString(): string;
  }

  export const Ops: {
    Op: new () => unknown;
    OpSHA256: new () => unknown;
    OpSHA1: new () => unknown;
    OpRIPEMD160: new () => unknown;
    [key: string]: unknown;
  };

  export const Context: {
    StreamDeserialization: new (bytes: Uint8Array | Buffer) => unknown;
    StreamSerialization: new () => unknown;
    [key: string]: unknown;
  };

  export function verify(
    detached: DetachedTimestampFile,
    data: DetachedTimestampFile,
  ): Promise<VerifyResult>;

  export function upgrade(detached: DetachedTimestampFile): Promise<boolean>;

  const _default: {
    DetachedTimestampFile: typeof DetachedTimestampFile;
    Ops: typeof Ops;
    Context: typeof Context;
    verify: typeof verify;
    upgrade: typeof upgrade;
  };
  export default _default;
}

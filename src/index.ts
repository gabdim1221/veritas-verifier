export * from "./types.js";
export * from "./errors.js";

export async function verify(/* tessera: Tessera */): Promise<never> {
  throw new Error("verify() not yet implemented — see Phase 2");
}

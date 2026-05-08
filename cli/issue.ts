#!/usr/bin/env -S npx tsx
/**
 * veritas — issuer CLI for Tessera v0.1.
 *
 * Subcommands:
 *   init [--handle <handle>]       Generate master + first device
 *   device add <name>              Add a new device + delegation
 *   issue <file> [--loa <0..4>]    Issue an authorship Tessera
 *   upgrade <tessera>              Upgrade a pending OTS proof
 *   info                           Show keys, devices, recent Tesserae
 *   verify <bundle> [--content P]  Verify a bundle (.bundle.json)
 *
 * NOTE: deviating from the prompt's "split each command into its own file"
 * suggestion — keeping commands inline here for Phase 5 manageability.
 * Refactor to cli/commands/ if the file grows.
 */

import { cac } from "cac";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import readline from "node:readline";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  generateKeypair,
  sign,
  base64urlEncode,
  canonicalizeForSigning,
  tesseraHash,
  hex,
  verify,
  type Tessera,
  type LOA,
  type AuthorshipPayload,
  type DelegationPayload,
} from "../src/index.js";
import { verifyOtsProof, upgradeOtsProof } from "../src/ots.js";
import {
  ROOT,
  ensureKeystore,
  loadMaster,
  saveMaster,
  loadDevices,
  saveDevice,
  activeDevice,
  masterExists,
  findDeviceByDelegationHash,
  type DeviceRecord,
  type MasterRecord,
} from "./keystore.js";
import { submitToOTS } from "./anchor.js";

// --------------------------------------------------------------------------
// utilities
// --------------------------------------------------------------------------

function nowIso(): string {
  return new Date().toISOString();
}

function uuidv4(): string {
  return crypto.randomUUID();
}

async function promptForHandle(): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      "stdin is not a TTY — pass --handle <handle> when running non-interactively",
    );
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise<string>((resolve) => {
    rl.question("Choose a handle (e.g. firstname-lastname): ", (a) => {
      rl.close();
      resolve(a.trim());
    });
  });
}

function devicePlatform(): string {
  switch (process.platform) {
    case "darwin": return "macos";
    case "win32":  return "windows";
    case "linux":  return "linux";
    default:       return process.platform;
  }
}

/** Build an authorship behavioral_fingerprint stub: sha256(content || iso || devicePub). */
function stubBehavioralFingerprint(
  content: Uint8Array,
  issuedAtIso: string,
  devicePubB64u: string,
): string {
  const buf = new Uint8Array(content.length + issuedAtIso.length + devicePubB64u.length);
  buf.set(content, 0);
  buf.set(new TextEncoder().encode(issuedAtIso), content.length);
  buf.set(new TextEncoder().encode(devicePubB64u), content.length + issuedAtIso.length);
  return base64urlEncode(sha256(buf));
}

// --------------------------------------------------------------------------
// command: init
// --------------------------------------------------------------------------

interface InitOpts {
  handle?: string;
}

async function initCommand(opts: InitOpts): Promise<void> {
  if (await masterExists()) {
    console.error(`error: keystore already initialized at ${ROOT}`);
    console.error("  delete it first if you really mean to start over: rm -rf ~/.veritas");
    process.exitCode = 1;
    return;
  }

  const handle = opts.handle ?? (await promptForHandle());
  if (!handle || !/^[a-zA-Z0-9._-]{1,64}$/.test(handle)) {
    console.error("error: handle must be 1–64 chars of [A-Za-z0-9._-]");
    process.exitCode = 1;
    return;
  }

  console.log("→ Generating master keypair…");
  const masterKp = generateKeypair();
  const masterRecord: MasterRecord = {
    handle,
    privateKey: base64urlEncode(masterKp.privateKey),
    publicKey: base64urlEncode(masterKp.publicKey),
    createdAt: nowIso(),
  };
  await saveMaster(masterRecord);

  console.log("→ Generating first device + delegation Tessera…");
  await issueNewDevice(masterRecord, "default", devicePlatform());

  console.log("");
  console.log(`✓ Keystore initialized at ${ROOT}`);
  console.log(`  master pubkey:  ${masterRecord.publicKey.slice(0, 32)}…`);
  console.log(`  handle:         ${handle}`);
  console.log("");
  console.log("⚠  BACK UP ~/.veritas/master.json — losing it means losing your identity.");
}

// --------------------------------------------------------------------------
// command: device add <name>
// --------------------------------------------------------------------------

async function deviceAddCommand(name: string): Promise<void> {
  const master = await loadMaster();
  if (!master) {
    console.error("error: no master key — run `veritas init` first");
    process.exitCode = 1;
    return;
  }
  if (!name || !/^[a-zA-Z0-9._ -]{1,64}$/.test(name)) {
    console.error("error: device name must be 1–64 chars");
    process.exitCode = 1;
    return;
  }
  const dev = await issueNewDevice(master, name, devicePlatform());
  console.log("");
  console.log(`✓ device "${name}" added`);
  console.log(`  device id:                  ${dev.id}`);
  console.log(`  delegation tessera hash:    ${dev.delegationTesseraHash}`);
}

async function issueNewDevice(
  master: MasterRecord,
  name: string,
  platform: string,
): Promise<DeviceRecord> {
  const deviceKp = generateKeypair();
  const deviceId = uuidv4();
  const issuedAt = nowIso();
  const masterPubB64u = master.publicKey;
  const devicePubB64u = base64urlEncode(deviceKp.publicKey);

  // Build the delegation Tessera, signed by the master.
  const draft: Tessera = {
    version: "tessera/v0.1",
    type: "delegation",
    tessera_id: uuidv4(),
    issuer: {
      user_handle: master.handle,
      user_master_pubkey: masterPubB64u,
      device_pubkey: masterPubB64u, // master signs the delegation
      device_delegation_hash: "",   // bootstrap
    },
    claim: { loa: 0, issued_at: issuedAt },
    type_payload: {
      delegated_pubkey: devicePubB64u,
      device_name: name,
      device_platform: platform,
      scope: ["sign:authorship", "sign:witness", "sign:revocation"],
      valid_from: issuedAt,
      valid_until: null,
    } satisfies DelegationPayload,
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  const masterSk = base64urlDecodeBytes(master.privateKey);
  draft.signature.value = base64urlEncode(sign(canonicalizeForSigning(draft), masterSk));

  // Anchor to OTS (best effort — pending is fine; a network failure is logged).
  const delegationHash = tesseraHash(draft);
  process.stderr.write("  submitting delegation to OTS calendars… ");
  const anchor = await submitToOTS(delegationHash);
  if (anchor.proofB64) {
    draft.anchor.ots_proof = anchor.proofB64;
    process.stderr.write("ok (pending)\n");
  } else {
    process.stderr.write(`failed (${anchor.error}); save without proof — run upgrade later\n`);
  }

  const record: DeviceRecord = {
    id: deviceId,
    name,
    platform,
    privateKey: base64urlEncode(deviceKp.privateKey),
    publicKey: devicePubB64u,
    delegationTesseraHash: hex(delegationHash),
    delegation: draft,
    createdAt: issuedAt,
    revokedAt: null,
  };
  await saveDevice(record);
  return record;
}

function base64urlDecodeBytes(s: string): Uint8Array {
  // local copy to avoid pulling globals; matches src/ed25519 base64urlDecode
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const bin = atob(padded + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --------------------------------------------------------------------------
// command: issue <file>
// --------------------------------------------------------------------------

interface IssueOpts {
  loa?: string;
}

async function issueCommand(filePath: string, opts: IssueOpts): Promise<void> {
  const master = await loadMaster();
  if (!master) {
    console.error("error: no master key — run `veritas init` first");
    process.exitCode = 1;
    return;
  }
  const device = await activeDevice();
  if (!device) {
    console.error("error: no active device — run `veritas device add <name>`");
    process.exitCode = 1;
    return;
  }

  const absPath = path.resolve(filePath);
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await fs.readFile(absPath));
  } catch (err) {
    console.error(`error: cannot read ${absPath}: ${err instanceof Error ? err.message : err}`);
    process.exitCode = 1;
    return;
  }

  const loa = (opts.loa ? parseInt(opts.loa, 10) : 0) as LOA;
  if (!Number.isInteger(loa) || loa < 0 || loa > 4) {
    console.error("error: --loa must be an integer 0..4");
    process.exitCode = 1;
    return;
  }
  if (loa > 0) {
    console.error(
      "warn: CLI-issued Tesserae are software-only (LOA 0). Higher LOA requires a biometric attestation flow that the CLI does not implement; the field will be set as requested but consumers MAY reject it.",
    );
  }

  const issuedAt = nowIso();
  const contentHashHex = hex(sha256(bytes));
  const devicePubB64u = device.publicKey;
  const masterPubB64u = master.publicKey;

  const draft: Tessera = {
    version: "tessera/v0.1",
    type: "authorship",
    tessera_id: uuidv4(),
    issuer: {
      user_handle: master.handle,
      user_master_pubkey: masterPubB64u,
      device_pubkey: devicePubB64u,
      device_delegation_hash: device.delegationTesseraHash,
    },
    claim: { loa, issued_at: issuedAt },
    type_payload: {
      subject: {
        content_hash: contentHashHex,
        content_size_bytes: bytes.length,
        content_mime: "application/octet-stream",
        content_filename: path.basename(absPath),
      },
      session: {
        started_at: issuedAt,
        ended_at: issuedAt,
        duration_ms: 0,
        tools_used: ["veritas-cli@0.1"],
      },
      behavioral_fingerprint: stubBehavioralFingerprint(bytes, issuedAt, devicePubB64u),
      ai_assistance_disclosure: "none",
    } satisfies AuthorshipPayload,
    biometric_attestation: { method: "none" },
    anchor: { service: "opentimestamps" },
    signature: { algorithm: "Ed25519", value: "" },
  };
  const deviceSk = base64urlDecodeBytes(device.privateKey);
  draft.signature.value = base64urlEncode(sign(canonicalizeForSigning(draft), deviceSk));

  const fullHash = tesseraHash(draft);
  process.stderr.write("→ submitting tessera hash to OTS calendars… ");
  const anchor = await submitToOTS(fullHash);
  if (anchor.proofB64) {
    draft.anchor.ots_proof = anchor.proofB64;
    process.stderr.write("ok (pending)\n");
  } else {
    process.stderr.write(`failed (${anchor.error})\n`);
  }

  // Write outputs: <file>.tessera.json (bare) and <file>.bundle.json (bundle for verifier page).
  const tesseraPath = `${absPath}.tessera.json`;
  const bundlePath = `${absPath}.bundle.json`;
  await fs.writeFile(tesseraPath, JSON.stringify(draft, null, 2) + "\n");
  await fs.writeFile(
    bundlePath,
    JSON.stringify({ tessera: draft, delegation: device.delegation }, null, 2) + "\n",
  );
  if (anchor.proofB64) {
    // marker file for "needs upgrade later"
    await fs.writeFile(`${tesseraPath}.upgradeable`, "");
  }

  console.log("");
  console.log(`✓ Tessera issued`);
  console.log(`  file:           ${absPath}`);
  console.log(`  content hash:   ${contentHashHex}`);
  console.log(`  tessera hash:   ${hex(fullHash)}`);
  console.log(`  anchor:         ${anchor.proofB64 ? "OTS pending" : "(unanchored)"}`);
  console.log(`  written:        ${tesseraPath}`);
  console.log(`                  ${bundlePath}`);
  if (anchor.proofB64) {
    console.log("");
    console.log("→ The OTS proof will become Bitcoin-confirmed in ~60–90 minutes.");
    console.log(`  Run \`npx tsx cli/issue.ts upgrade ${tesseraPath}\` then.`);
  }
}

// --------------------------------------------------------------------------
// command: upgrade <tessera>
// --------------------------------------------------------------------------

async function upgradeCommand(tesseraPath: string): Promise<void> {
  const abs = path.resolve(tesseraPath);
  let raw: string;
  try {
    raw = await fs.readFile(abs, "utf8");
  } catch (err) {
    console.error(`error: cannot read ${abs}: ${err}`);
    process.exitCode = 1;
    return;
  }
  const obj = JSON.parse(raw) as Tessera | { tessera: Tessera; delegation?: Tessera };
  const isBundle = "tessera" in obj && (obj as { tessera: Tessera }).tessera;
  const t: Tessera = isBundle ? (obj as { tessera: Tessera }).tessera : (obj as Tessera);

  if (!t.anchor?.ots_proof) {
    console.error("error: tessera has no ots_proof to upgrade");
    process.exitCode = 1;
    return;
  }

  process.stderr.write("→ asking calendars to upgrade pending proof… ");
  const upgraded = await upgradeOtsProof(t.anchor.ots_proof);
  if (!upgraded) {
    process.stderr.write("not yet upgradable (try again later)\n");
    return;
  }
  process.stderr.write("ok\n");
  t.anchor.ots_proof = upgraded;

  // Re-marshal in the same shape we read.
  const out = isBundle ? { ...(obj as { delegation?: Tessera }), tessera: t } : t;
  await fs.writeFile(abs, JSON.stringify(out, null, 2) + "\n");
  await fs.rm(`${abs}.upgradeable`, { force: true });
  console.log(`✓ Upgraded proof written back to ${abs}`);
}

// --------------------------------------------------------------------------
// command: info
// --------------------------------------------------------------------------

async function infoCommand(): Promise<void> {
  const master = await loadMaster();
  if (!master) {
    console.log("(no master key — run `veritas init`)");
    return;
  }
  const devices = await loadDevices();
  console.log(`keystore:     ${ROOT}`);
  console.log(`handle:       ${master.handle}`);
  console.log(`master pub:   ${master.publicKey}`);
  console.log(`master since: ${master.createdAt}`);
  console.log(`devices:      ${devices.length}`);
  for (const d of devices) {
    const tag = d.revokedAt ? "[revoked]" : (await activeDevice())?.id === d.id ? "[active]" : "";
    console.log(`  - ${d.name.padEnd(16)} ${d.platform.padEnd(10)} ${d.id} ${tag}`);
    console.log(`    delegation:   ${d.delegationTesseraHash}`);
    console.log(`    device pub:   ${d.publicKey}`);
  }
}

// --------------------------------------------------------------------------
// command: verify <bundle>
// --------------------------------------------------------------------------

interface VerifyOpts {
  content?: string;
}

async function verifyCommand(bundlePath: string, opts: VerifyOpts): Promise<void> {
  const abs = path.resolve(bundlePath);
  let raw: string;
  try {
    raw = await fs.readFile(abs, "utf8");
  } catch (err) {
    console.error(`error: cannot read ${abs}: ${err}`);
    process.exitCode = 1;
    return;
  }
  const obj = JSON.parse(raw) as Tessera | { tessera: Tessera; delegation?: Tessera };
  const t: Tessera = "tessera" in obj && (obj as { tessera: Tessera }).tessera
    ? (obj as { tessera: Tessera }).tessera
    : (obj as Tessera);
  let delegation: Tessera | null = "delegation" in obj
    ? ((obj as { delegation?: Tessera }).delegation ?? null)
    : null;

  // If bundle didn't include a delegation, try the keystore.
  if (!delegation) {
    const dev = await findDeviceByDelegationHash(t.issuer.device_delegation_hash);
    if (dev) delegation = dev.delegation;
  }

  let contentBytes: Uint8Array | undefined;
  if (opts.content) {
    contentBytes = new Uint8Array(await fs.readFile(path.resolve(opts.content)));
  }

  const result = await verify(t, {
    fetchDelegation: async () => delegation,
    content: contentBytes,
    verifyAnchor: verifyOtsProof,
  });

  if (result.valid) {
    console.log("✓ VALID");
    console.log(`  loa:          ${result.loa}`);
    console.log(`  issued at:    ${result.issuedAt}`);
    console.log(`  anchor:       ${result.anchorStatus}`);
    if (result.anchoredAtBlock !== undefined) {
      console.log(`  block:        ${result.anchoredAtBlock} @ ${result.anchoredAtTime}`);
    }
    console.log(`  author:       ${result.authorHandle}`);
  } else {
    console.log("✗ INVALID");
    console.log(`  error:        ${result.errorCode}`);
    console.log(`  message:      ${result.errorMessage}`);
    if (result.details) console.log(`  details:      ${JSON.stringify(result.details)}`);
    process.exitCode = 1;
  }
}

// --------------------------------------------------------------------------
// CLI wiring
// --------------------------------------------------------------------------

const cli = cac("veritas");

cli.command("init", "Generate a master key and first device")
  .option("--handle <handle>", "Handle to use (skips interactive prompt)")
  .action((opts: InitOpts) => initCommand(opts));

cli.command("device <action> <name>", "Manage devices (action: add)")
  .action(async (action: string, name: string) => {
    if (action !== "add") {
      console.error(`error: unknown device action: ${action}`);
      process.exitCode = 1;
      return;
    }
    return deviceAddCommand(name);
  });

cli.command("issue <file>", "Issue an authorship Tessera for the file")
  .option("--loa <n>", "Level of Assurance (0–4); default 0", { default: "0" })
  .action((file: string, opts: IssueOpts) => issueCommand(file, opts));

cli.command("upgrade <tessera>", "Upgrade a pending OTS proof")
  .action((p: string) => upgradeCommand(p));

cli.command("info", "Show keys, devices, recent Tesserae")
  .action(() => infoCommand());

cli.command("verify <bundle>", "Verify a Tessera bundle")
  .option("--content <path>", "Verify against actual content bytes")
  .action((p: string, opts: VerifyOpts) => verifyCommand(p, opts));

cli.help();
cli.version("0.1.0");

cli.parse();

/**
 * Filesystem keystore for the confirmata CLI.
 *
 * Layout:
 *   ~/.confirmata/                                   (mode 0700)
 *   ├── master.json                               (mode 0600)
 *   └── devices/                                  (mode 0700)
 *       └── <deviceId>.json                       (mode 0600)
 *           └─ contains the device record AND its delegation Tessera
 *
 * Master and device private keys are base64url Ed25519 secret keys.
 * The keystore is local-only — never copy it to a shared location.
 */

import { promises as fs, constants } from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Tessera } from "../src/index.js";

export interface MasterRecord {
  handle: string;
  privateKey: string;
  publicKey: string;
  createdAt: string;
}

export interface DeviceRecord {
  id: string;
  name: string;
  platform: string;
  privateKey: string;
  publicKey: string;
  delegationTesseraHash: string;
  delegation: Tessera;
  createdAt: string;
  revokedAt?: string | null;
}

export const ROOT = path.join(os.homedir(), ".confirmata");
const MASTER = path.join(ROOT, "master.json");
const DEVICES_DIR = path.join(ROOT, "devices");

export async function ensureKeystore(): Promise<void> {
  await fs.mkdir(ROOT, { recursive: true, mode: 0o700 });
  await fs.mkdir(DEVICES_DIR, { recursive: true, mode: 0o700 });
  // chmod in case the dirs already existed with looser perms
  await fs.chmod(ROOT, 0o700).catch(() => {});
  await fs.chmod(DEVICES_DIR, 0o700).catch(() => {});
}

export async function masterExists(): Promise<boolean> {
  try {
    await fs.access(MASTER, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function loadMaster(): Promise<MasterRecord | null> {
  try {
    const raw = await fs.readFile(MASTER, "utf8");
    return JSON.parse(raw) as MasterRecord;
  } catch {
    return null;
  }
}

export async function saveMaster(record: MasterRecord): Promise<void> {
  await ensureKeystore();
  await fs.writeFile(MASTER, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
  await fs.chmod(MASTER, 0o600).catch(() => {});
}

export async function loadDevices(): Promise<DeviceRecord[]> {
  await ensureKeystore();
  let entries: string[];
  try {
    entries = await fs.readdir(DEVICES_DIR);
  } catch {
    return [];
  }
  const out: DeviceRecord[] = [];
  for (const name of entries) {
    if (!name.endsWith(".json")) continue;
    try {
      const raw = await fs.readFile(path.join(DEVICES_DIR, name), "utf8");
      out.push(JSON.parse(raw) as DeviceRecord);
    } catch {
      // ignore unreadable / malformed device files
    }
  }
  return out.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export async function saveDevice(record: DeviceRecord): Promise<void> {
  await ensureKeystore();
  const target = path.join(DEVICES_DIR, `${record.id}.json`);
  await fs.writeFile(target, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
  await fs.chmod(target, 0o600).catch(() => {});
}

/** Return the most recently created un-revoked device, or null. */
export async function activeDevice(): Promise<DeviceRecord | null> {
  const devices = await loadDevices();
  const live = devices.filter((d) => !d.revokedAt);
  return live[live.length - 1] ?? null;
}

/** Look up a device record whose delegation Tessera matches the given hash. */
export async function findDeviceByDelegationHash(
  hashHex: string,
): Promise<DeviceRecord | null> {
  const devices = await loadDevices();
  return devices.find((d) => d.delegationTesseraHash === hashHex) ?? null;
}

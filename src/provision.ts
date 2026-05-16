import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import plist from "plist";
import forge from "node-forge";
import { certificateFromDer } from "./cert.js";
import type {
  ParsedProvisioningProfile,
  ProfileType,
  ProvisionDeveloperCertificate,
  ProvisioningProfileInfo,
} from "./types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export class ProvisionParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProvisionParseError";
  }
}

export function parseMobileProvision(path: string): ParsedProvisioningProfile {
  assertReadableFile(path, "Provisioning profile");
  const xml = extractPlistWithOpenSsl(path);
  const rawPlist = parsePlist(xml);
  const info = profileInfoFromPlist(rawPlist);
  return { info, rawPlist };
}

function extractPlistWithOpenSsl(path: string): string {
  const smime = runOpenSsl([
    "smime",
    "-inform",
    "DER",
    "-verify",
    "-noverify",
    "-in",
    path,
  ]);

  if (smime.ok) {
    return smime.stdout;
  }

  const cms = runOpenSsl([
    "cms",
    "-inform",
    "DER",
    "-verify",
    "-noverify",
    "-in",
    path,
  ]);

  if (cms.ok) {
    return cms.stdout;
  }

  throw new ProvisionParseError(
    `OpenSSL could not extract the plist from the provisioning profile: ${compactError(
      cms.stderr || smime.stderr,
    )}`,
  );
}

function runOpenSsl(args: string[]): { ok: true; stdout: string } | { ok: false; stderr: string } {
  const result = spawnSync("openssl", args, {
    encoding: "utf8",
    maxBuffer: 25 * 1024 * 1024,
  });

  if (hasErrorCode(result.error, "ENOENT")) {
    throw new ProvisionParseError(
      "openssl was not found on PATH. Install OpenSSL to inspect .mobileprovision files.",
    );
  }

  if (result.status !== 0) {
    return { ok: false, stderr: result.stderr };
  }

  return { ok: true, stdout: result.stdout };
}

function parsePlist(xml: string): Record<string, unknown> {
  const trimmed = xml.trimStart();
  if (trimmed.startsWith("bplist")) {
    throw new ProvisionParseError(
      "The extracted provisioning profile plist is binary. This MVP supports XML plist payloads only.",
    );
  }

  try {
    const parsed = plist.parse(xml);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("plist root is not a dictionary");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown parse error";
    throw new ProvisionParseError(`Could not parse provisioning profile plist: ${reason}`);
  }
}

function profileInfoFromPlist(raw: Record<string, unknown>): ProvisioningProfileInfo {
  const entitlements = asRecord(raw.Entitlements);
  const teamIds = asStringArray(raw.TeamIdentifier);
  const profileTeamId = teamIds[0] ?? asStringArray(raw.ApplicationIdentifierPrefix)[0] ?? null;
  const applicationIdentifier =
    asString(entitlements["application-identifier"]) ??
    asString(entitlements["com.apple.application-identifier"]);
  const bundleId = deriveBundleId(applicationIdentifier, profileTeamId);
  const expirationDate = asDate(raw.ExpirationDate);
  const now = new Date();
  const developerCertificates = parseDeveloperCertificates(raw.DeveloperCertificates);

  const info: ProvisioningProfileInfo = {
    name: asString(raw.Name),
    uuid: asString(raw.UUID),
    teamName: asString(raw.TeamName),
    teamId: profileTeamId,
    appIdName: asString(raw.AppIDName),
    applicationIdentifier,
    bundleId,
    isWildcard: Boolean(bundleId?.includes("*")),
    creationDate: asDate(raw.CreationDate)?.toISOString() ?? null,
    expirationDate: expirationDate?.toISOString() ?? null,
    platform: asStringArray(raw.Platform),
    profileType: detectProfileType(raw, entitlements),
    provisionedDevices: asStringArray(raw.ProvisionedDevices),
    entitlements,
    developerCertificates,
    isCurrentlyValid: expirationDate ? now <= expirationDate : null,
    daysUntilExpiration: expirationDate
      ? Math.ceil((expirationDate.getTime() - now.getTime()) / DAY_MS)
      : null,
  };

  return info;
}

function parseDeveloperCertificates(value: unknown): ProvisionDeveloperCertificate[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((item): ProvisionDeveloperCertificate[] => {
    const der = dataToBuffer(item);
    if (!der) {
      return [];
    }

    try {
      const parsed = certificateFromDer(der);
      return [
        {
          commonName: parsed.info.commonName,
          teamId: parsed.info.teamId,
          serialDecimal: parsed.info.serialDecimal,
          serialHex: parsed.info.serialHex,
          sha1Fingerprint: parsed.info.sha1Fingerprint,
          sha256Fingerprint: parsed.info.sha256Fingerprint,
          validFrom: parsed.info.validFrom,
          expiration: parsed.info.expiration,
        },
      ];
    } catch {
      return [
        {
          commonName: null,
          teamId: null,
          serialDecimal: null,
          serialHex: null,
          sha1Fingerprint: fingerprint(der, "sha1"),
          sha256Fingerprint: fingerprint(der, "sha256"),
          validFrom: null,
          expiration: null,
        },
      ];
    }
  });
}

function detectProfileType(raw: Record<string, unknown>, entitlements: Record<string, unknown>): ProfileType {
  const getTaskAllow = entitlements["get-task-allow"] === true;
  const provisionedDevices = Array.isArray(raw.ProvisionedDevices);
  const provisionsAllDevices = raw.ProvisionsAllDevices === true;

  if (provisionsAllDevices) {
    return "Enterprise";
  }
  if (getTaskAllow) {
    return "Development";
  }
  if (provisionedDevices) {
    return "Ad Hoc";
  }
  if (getTaskAllow === false && !provisionedDevices) {
    return "App Store";
  }
  return "Unknown";
}

function deriveBundleId(applicationIdentifier: string | null, teamId: string | null): string | null {
  if (!applicationIdentifier) {
    return null;
  }

  if (teamId && applicationIdentifier.startsWith(`${teamId}.`)) {
    return applicationIdentifier.slice(teamId.length + 1);
  }

  const firstDot = applicationIdentifier.indexOf(".");
  return firstDot >= 0 ? applicationIdentifier.slice(firstDot + 1) : applicationIdentifier;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asDate(value: unknown): Date | null {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === "string") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  return null;
}

function dataToBuffer(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    const normalized = value.replace(/\s+/g, "");
    try {
      return Buffer.from(normalized, "base64");
    } catch {
      return null;
    }
  }
  if (value && typeof value === "object" && "data" in value) {
    const maybeData = (value as { data?: unknown }).data;
    if (Array.isArray(maybeData)) {
      return Buffer.from(maybeData);
    }
  }
  return null;
}

function fingerprint(der: Buffer, algorithm: "sha1" | "sha256"): string {
  return createHash(algorithm)
    .update(der)
    .digest("hex")
    .toUpperCase()
    .match(/.{2}/g)!
    .join(":");
}

function assertReadableFile(path: string, label: string): void {
  if (!existsSync(path)) {
    throw new ProvisionParseError(`${label} not found: ${path}`);
  }
}

function compactError(stderr: string): string {
  return stderr.trim().replace(/\s+/g, " ") || "unknown error";
}

function hasErrorCode(error: Error | undefined, code: string): boolean {
  return Boolean(error && "code" in error && error.code === code);
}

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import forge from "node-forge";
import type { CertificateInfo, ParsedCertificate } from "./types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export class CertificateParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateParseError";
  }
}

export class InvalidP12PasswordError extends CertificateParseError {
  constructor() {
    super("Invalid PKCS#12 password.");
    this.name = "InvalidP12PasswordError";
  }
}

export function parseP12(path: string, password = ""): ParsedCertificate {
  assertReadableFile(path, "PKCS#12 file");

  const p12Bytes = readFileSync(path);
  try {
    return parseP12WithForge(p12Bytes, password);
  } catch (error) {
    if (looksLikeInvalidPassword(error)) {
      throw new InvalidP12PasswordError();
    }

    return parseP12WithOpenSsl(path, password);
  }
}

export function certificateFromDer(der: Buffer): ParsedCertificate {
  const binary = der.toString("binary");
  const asn1 = forge.asn1.fromDer(binary);
  const cert = forge.pki.certificateFromAsn1(asn1);
  return certificateFromForgeCert(cert, der);
}

function parseP12WithForge(p12Bytes: Buffer, password: string): ParsedCertificate {
  const binary = p12Bytes.toString("binary");
  const asn1 = forge.asn1.fromDer(binary);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[
    forge.pki.oids.certBag
  ];

  if (!certBags || certBags.length === 0) {
    throw new CertificateParseError("No certificate found in PKCS#12 file.");
  }

  const cert = certBags
    .map((bag) => bag.cert)
    .find((candidate): candidate is forge.pki.Certificate => Boolean(candidate));

  if (!cert) {
    throw new CertificateParseError("No readable X.509 certificate found in PKCS#12 file.");
  }

  const der = Buffer.from(
    forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
    "binary",
  );
  return certificateFromForgeCert(cert, der);
}

function parseP12WithOpenSsl(path: string, password: string): ParsedCertificate {
  const result = spawnSync(
    "openssl",
    [
      "pkcs12",
      "-in",
      path,
      "-nokeys",
      "-clcerts",
      "-passin",
      "env:IOS_CERT_CHECKER_P12_PASSWORD",
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        IOS_CERT_CHECKER_P12_PASSWORD: password,
      },
      maxBuffer: 10 * 1024 * 1024,
    },
  );

  if (hasErrorCode(result.error, "ENOENT")) {
    throw new CertificateParseError(
      "Could not parse PKCS#12 with node-forge, and openssl was not found on PATH.",
    );
  }

  if (result.status !== 0) {
    const stderr = result.stderr.toLowerCase();
    if (
      stderr.includes("mac verify failure") ||
      stderr.includes("invalid password") ||
      stderr.includes("bad decrypt")
    ) {
      throw new InvalidP12PasswordError();
    }
    throw new CertificateParseError(
      `OpenSSL could not parse PKCS#12 certificate: ${compactError(result.stderr)}`,
    );
  }

  const pemMatch = result.stdout.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/,
  );
  if (!pemMatch) {
    throw new CertificateParseError("OpenSSL did not return a certificate from the PKCS#12 file.");
  }

  const cert = forge.pki.certificateFromPem(pemMatch[0]);
  const der = Buffer.from(
    forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
    "binary",
  );
  return certificateFromForgeCert(cert, der);
}

function certificateFromForgeCert(cert: forge.pki.Certificate, der: Buffer): ParsedCertificate {
  const commonName = getSubjectValue(cert, "CN");
  const organizationalUnit = getSubjectValue(cert, "OU");
  const teamId = detectTeamId(commonName, organizationalUnit);
  const serialHex = normalizeSerialHex(cert.serialNumber);
  const expiration = cert.validity.notAfter;
  const now = new Date();

  const info: CertificateInfo = {
    commonName,
    teamId,
    validFrom: cert.validity.notBefore.toISOString(),
    expiration: expiration.toISOString(),
    serialDecimal: hexToDecimal(serialHex),
    serialHex,
    sha1Fingerprint: fingerprint(der, "sha1"),
    sha256Fingerprint: fingerprint(der, "sha256"),
    isCurrentlyValid: now >= cert.validity.notBefore && now <= expiration,
    daysUntilExpiration: Math.ceil((expiration.getTime() - now.getTime()) / DAY_MS),
  };

  return { info, der };
}

function getSubjectValue(cert: forge.pki.Certificate, shortName: string): string | null {
  const field = cert.subject.attributes.find((attribute) => attribute.shortName === shortName);
  return typeof field?.value === "string" ? field.value : null;
}

function detectTeamId(commonName: string | null, organizationalUnit: string | null): string | null {
  if (organizationalUnit && /^[A-Z0-9]{10}$/.test(organizationalUnit)) {
    return organizationalUnit;
  }

  const match = commonName?.match(/\(([A-Z0-9]{10})\)\s*$/);
  return match?.[1] ?? null;
}

function fingerprint(der: Buffer, algorithm: "sha1" | "sha256"): string {
  return createHash(algorithm)
    .update(der)
    .digest("hex")
    .toUpperCase()
    .match(/.{2}/g)!
    .join(":");
}

function normalizeSerialHex(serial: string): string {
  const normalized = serial.replace(/^00+/, "").toUpperCase();
  return normalized.length > 0 ? normalized : "0";
}

function hexToDecimal(hex: string): string {
  return BigInt(`0x${hex}`).toString(10);
}

function looksLikeInvalidPassword(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  return (
    message.includes("invalid password") ||
    message.includes("pkcs#12 mac could not be verified") ||
    message.includes("mac could not be verified")
  );
}

function assertReadableFile(path: string, label: string): void {
  if (!existsSync(path)) {
    throw new CertificateParseError(`${label} not found: ${path}`);
  }
}

function compactError(stderr: string): string {
  return stderr.trim().replace(/\s+/g, " ") || "unknown error";
}

function hasErrorCode(error: Error | undefined, code: string): boolean {
  return Boolean(error && "code" in error && error.code === code);
}

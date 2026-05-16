import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { APPLE_ISSUER_PEMS } from "./appleIssuers.js";
import type { ParsedCertificate, RevocationInfo, RevocationStatus } from "./types.js";

const DEFAULT_OCSP_TIMEOUT_SECONDS = 10;

export function checkOcspRevocation(
  cert: ParsedCertificate,
  timeoutSeconds = DEFAULT_OCSP_TIMEOUT_SECONDS,
): RevocationInfo {
  const checkedAt = new Date().toISOString();
  const base = {
    method: "OCSP" as const,
    ocspUrl: null,
    checkedAt,
    thisUpdate: null,
    nextUpdate: null,
    revocationTime: null,
  };

  const issuerPem = cert.issuerPem ?? findBundledAppleIssuerPem(cert.pem);
  if (!issuerPem) {
    return {
      ...base,
      checked: false,
      status: "skipped",
      reason:
        "OCSP requires the issuer certificate, but no issuer was found in the PKCS#12 file or bundled Apple WWDR issuers.",
    };
  }

  const ocspUrlResult = readOcspUrl(cert.pem);
  if (ocspUrlResult.error) {
    return {
      ...base,
      checked: false,
      status: "error",
      reason: ocspUrlResult.error,
    };
  }

  if (!ocspUrlResult.url) {
    return {
      ...base,
      checked: false,
      status: "skipped",
      reason: "The certificate does not advertise an OCSP responder URL.",
    };
  }

  return runOpenSslOcsp(cert, issuerPem, ocspUrlResult.url, timeoutSeconds, checkedAt);
}

function readOcspUrl(certPem: string): { url: string | null; error: string | null } {
  const result = spawnSync("openssl", ["x509", "-noout", "-ocsp_uri"], {
    encoding: "utf8",
    input: certPem,
    maxBuffer: 1024 * 1024,
  });

  if (hasErrorCode(result.error, "ENOENT")) {
    return { url: null, error: "openssl was not found on PATH. OpenSSL is required for OCSP checks." };
  }

  if (result.status !== 0) {
    return {
      url: null,
      error: `OpenSSL could not read the certificate OCSP URL: ${compactError(result.stderr)}`,
    };
  }

  return { url: result.stdout.trim().split(/\r?\n/).find(Boolean) ?? null, error: null };
}

function runOpenSslOcsp(
  cert: ParsedCertificate,
  issuerPem: string,
  ocspUrl: string,
  timeoutSeconds: number,
  checkedAt: string,
): RevocationInfo {
  const tempDir = mkdtempSync(join(tmpdir(), "ios-cert-checker-ocsp-"));
  const certPath = join(tempDir, "cert.pem");
  const issuerPath = join(tempDir, "issuer.pem");

  try {
    writeFileSync(certPath, cert.pem, { mode: 0o600 });
    writeFileSync(issuerPath, issuerPem, { mode: 0o600 });

    let result = runOcspCommand(certPath, issuerPath, ocspUrl, timeoutSeconds, true);
    if (result.status !== 0 && /unknown option|invalid option|timeout/i.test(result.stderr)) {
      result = runOcspCommand(certPath, issuerPath, ocspUrl, timeoutSeconds, false);
    }

    const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
    const parsed = parseOpenSslOcspOutput(output);

    if (parsed.status) {
      return {
        method: "OCSP",
        checked: true,
        status: parsed.status,
        ocspUrl,
        checkedAt,
        thisUpdate: parsed.thisUpdate,
        nextUpdate: parsed.nextUpdate,
        revocationTime: parsed.revocationTime,
        reason: parsed.reason,
      };
    }

    return {
      method: "OCSP",
      checked: true,
      status: "error",
      ocspUrl,
      checkedAt,
      thisUpdate: null,
      nextUpdate: null,
      revocationTime: null,
      reason: compactError(output) || `OpenSSL OCSP check exited with status ${result.status}`,
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

function findBundledAppleIssuerPem(certPem: string): string | null {
  const issuerName = readCertificateName(certPem, "issuer");
  if (!issuerName) {
    return null;
  }

  return (
    APPLE_ISSUER_PEMS.find((issuerPem) => readCertificateName(issuerPem, "subject") === issuerName) ??
    null
  );
}

function readCertificateName(pem: string, field: "issuer" | "subject"): string | null {
  const result = spawnSync("openssl", ["x509", "-noout", `-${field}`, "-nameopt", "RFC2253"], {
    encoding: "utf8",
    input: pem,
    maxBuffer: 1024 * 1024,
  });

  if (result.status !== 0 || result.error) {
    return null;
  }

  return result.stdout.trim().replace(new RegExp(`^${field}=`), "");
}

function runOcspCommand(
  certPath: string,
  issuerPath: string,
  ocspUrl: string,
  timeoutSeconds: number,
  includeTimeout: boolean,
): { status: number | null; stdout: string; stderr: string; error?: Error } {
  const args = [
    "ocsp",
    "-issuer",
    issuerPath,
    "-cert",
    certPath,
    "-url",
    ocspUrl,
    "-no_nonce",
    "-noverify",
  ];

  if (includeTimeout) {
    args.push("-timeout", String(timeoutSeconds));
  }

  const result = spawnSync("openssl", args, {
    encoding: "utf8",
    maxBuffer: 5 * 1024 * 1024,
  });

  if (hasErrorCode(result.error, "ENOENT")) {
    return {
      status: 127,
      stdout: "",
      stderr: "openssl was not found on PATH. OpenSSL is required for OCSP checks.",
      error: result.error,
    };
  }

  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    error: result.error,
  };
}

function parseOpenSslOcspOutput(output: string): {
  status: RevocationStatus | null;
  thisUpdate: string | null;
  nextUpdate: string | null;
  revocationTime: string | null;
  reason: string | null;
} {
  const statusMatch = output.match(/:\s*(good|revoked|unknown)\b/i);
  const status = statusMatch?.[1]?.toLowerCase() as RevocationStatus | undefined;

  return {
    status: status ?? null,
    thisUpdate: readOpenSslDate(output, "This Update"),
    nextUpdate: readOpenSslDate(output, "Next Update"),
    revocationTime: readOpenSslDate(output, "Revocation Time"),
    reason: readReason(output),
  };
}

function readOpenSslDate(output: string, label: string): string | null {
  const escapedLabel = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = output.match(new RegExp(`${escapedLabel}:\\s*(.+)`, "i"));
  if (!match?.[1]) {
    return null;
  }

  const raw = match[1].trim();
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? raw : date.toISOString();
}

function readReason(output: string): string | null {
  const match =
    output.match(/Reason:\s*(.+)/i) ??
    output.match(/Response verify OK/i) ??
    output.match(/OCSP Response Status:\s*(.+)/i);
  return match?.[1]?.trim() ?? null;
}

function compactError(stderr: string): string {
  return stderr.trim().replace(/\s+/g, " ") || "unknown error";
}

function hasErrorCode(error: Error | undefined, code: string): boolean {
  return Boolean(error && "code" in error && error.code === code);
}

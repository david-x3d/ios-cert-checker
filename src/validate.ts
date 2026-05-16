import type {
  CertificateInfo,
  CheckStatus,
  ParsedCertificate,
  ParsedProvisioningProfile,
  ValidationCheck,
  ValidationResult,
} from "./types.js";

const EXPIRING_SOON_DAYS = 30;

export function validateCertificate(cert: CertificateInfo): ValidationResult {
  return resultFromChecks(certificateChecks(cert));
}

export function validateProvision(profile: ParsedProvisioningProfile["info"]): ValidationResult {
  return resultFromChecks(provisionChecks(profile));
}

export function validatePair(
  cert: ParsedCertificate,
  profile: ParsedProvisioningProfile,
): ValidationResult {
  const checks: ValidationCheck[] = [
    ...certificateChecks(cert.info),
    ...provisionChecks(profile.info),
    teamIdCheck(cert.info.teamId, profile.info.teamId),
    certificatePresenceCheck(profile.info.developerCertificates.length),
    certificateMatchCheck(cert.info.sha1Fingerprint, cert.info.sha256Fingerprint, profile),
  ];

  return resultFromChecks(checks);
}

function certificateChecks(cert: CertificateInfo): ValidationCheck[] {
  const checks: ValidationCheck[] = [
    {
      name: "certificate-currently-valid",
      status: cert.isCurrentlyValid ? "pass" : "fail",
      message: cert.isCurrentlyValid
        ? "Certificate is currently valid"
        : "Certificate is expired or not yet valid",
    },
  ];

  if (cert.isCurrentlyValid && cert.daysUntilExpiration <= EXPIRING_SOON_DAYS) {
    checks.push({
      name: "certificate-expiration-window",
      status: "warning",
      message: `Certificate expires in ${cert.daysUntilExpiration} day(s)`,
    });
  }

  return checks;
}

function provisionChecks(profile: ParsedProvisioningProfile["info"]): ValidationCheck[] {
  const checks: ValidationCheck[] = [
    {
      name: "provision-currently-valid",
      status: profile.isCurrentlyValid === true ? "pass" : "fail",
      message:
        profile.isCurrentlyValid === true
          ? "Provisioning profile is currently valid"
          : "Provisioning profile is expired or has no readable expiration date",
    },
  ];

  if (
    profile.isCurrentlyValid === true &&
    profile.daysUntilExpiration !== null &&
    profile.daysUntilExpiration <= EXPIRING_SOON_DAYS
  ) {
    checks.push({
      name: "provision-expiration-window",
      status: "warning",
      message: `Provisioning profile expires in ${profile.daysUntilExpiration} day(s)`,
    });
  }

  return checks;
}

function teamIdCheck(certTeamId: string | null, profileTeamId: string | null): ValidationCheck {
  if (!certTeamId || !profileTeamId) {
    return {
      name: "team-id-match",
      status: "warning",
      message: "Could not compare Team IDs because one or both Team IDs were not detectable",
    };
  }

  return {
    name: "team-id-match",
    status: certTeamId === profileTeamId ? "pass" : "fail",
    message: certTeamId === profileTeamId ? "Team IDs match" : "Team IDs do not match",
  };
}

function certificatePresenceCheck(count: number): ValidationCheck {
  return {
    name: "profile-developer-certificates",
    status: count > 0 ? "pass" : "warning",
    message:
      count > 0
        ? `Provisioning profile contains ${count} developer certificate(s)`
        : "Provisioning profile does not contain readable developer certificates",
  };
}

function certificateMatchCheck(
  certSha1: string,
  certSha256: string,
  profile: ParsedProvisioningProfile,
): ValidationCheck {
  if (profile.info.developerCertificates.length === 0) {
    return {
      name: "certificate-profile-match",
      status: "warning",
      message: "Could not compare certificate fingerprints with the provisioning profile",
    };
  }

  const matched = profile.info.developerCertificates.some(
    (developerCert) =>
      developerCert.sha1Fingerprint === certSha1 || developerCert.sha256Fingerprint === certSha256,
  );

  return {
    name: "certificate-profile-match",
    status: matched ? "pass" : "fail",
    message: matched
      ? "Certificate appears to match provisioning profile"
      : "Certificate fingerprint was not found in the provisioning profile",
  };
}

function resultFromChecks(checks: ValidationCheck[]): ValidationResult {
  const status = statusFromChecks(checks);
  return { status, checks };
}

function statusFromChecks(checks: ValidationCheck[]): ValidationResult["status"] {
  const worst = checks.reduce<CheckStatus>((current, check) => {
    if (current === "fail" || check.status === "fail") {
      return "fail";
    }
    if (current === "warning" || check.status === "warning") {
      return "warning";
    }
    return "pass";
  }, "pass");

  if (worst === "fail") {
    return "INVALID";
  }
  if (worst === "warning") {
    return "WARNING";
  }
  return "VALID";
}

export type OverallStatus = "VALID" | "WARNING" | "INVALID";

export type CheckStatus = "pass" | "warning" | "fail";

export interface ValidationCheck {
  name: string;
  status: CheckStatus;
  message: string;
}

export interface ValidationResult {
  status: OverallStatus;
  checks: ValidationCheck[];
}

export type RevocationStatus = "good" | "revoked" | "unknown" | "skipped" | "error";

export interface RevocationInfo {
  method: "OCSP";
  checked: boolean;
  status: RevocationStatus;
  ocspUrl: string | null;
  checkedAt: string;
  thisUpdate: string | null;
  nextUpdate: string | null;
  revocationTime: string | null;
  reason: string | null;
}

export interface CertificateInfo {
  commonName: string | null;
  teamId: string | null;
  validFrom: string;
  expiration: string;
  serialDecimal: string;
  serialHex: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  isCurrentlyValid: boolean;
  daysUntilExpiration: number;
  revocation: RevocationInfo | null;
}

export interface ParsedCertificate {
  info: CertificateInfo;
  der: Buffer;
  pem: string;
  issuerDer: Buffer | null;
  issuerPem: string | null;
}

export interface ProvisionDeveloperCertificate {
  commonName: string | null;
  teamId: string | null;
  serialDecimal: string | null;
  serialHex: string | null;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  validFrom: string | null;
  expiration: string | null;
}

export type ProfileType =
  | "Development"
  | "Ad Hoc"
  | "App Store"
  | "Enterprise"
  | "Unknown";

export interface ProvisioningProfileInfo {
  name: string | null;
  uuid: string | null;
  teamName: string | null;
  teamId: string | null;
  appIdName: string | null;
  applicationIdentifier: string | null;
  bundleId: string | null;
  isWildcard: boolean;
  creationDate: string | null;
  expirationDate: string | null;
  platform: string[];
  profileType: ProfileType;
  provisionedDevices: string[];
  entitlements: Record<string, unknown>;
  developerCertificates: ProvisionDeveloperCertificate[];
  isCurrentlyValid: boolean | null;
  daysUntilExpiration: number | null;
}

export interface ParsedProvisioningProfile {
  info: ProvisioningProfileInfo;
  rawPlist: Record<string, unknown>;
}

export interface CheckReport {
  certificate: CertificateInfo;
  provisioningProfile: ProvisioningProfileInfo;
  validation: ValidationResult;
}

export interface CertReport {
  certificate: CertificateInfo;
  validation: ValidationResult;
}

export interface ProvisionReport {
  provisioningProfile: ProvisioningProfileInfo;
  validation: ValidationResult;
}

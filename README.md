# ios-cert-checker 🍏

> Privacy-first local CLI for inspecting iOS signing certificates and provisioning profiles.

[![npm](https://img.shields.io/npm/v/ios-cert-checker?color=cb3837)](https://www.npmjs.com/package/ios-cert-checker)
[![GitHub](https://img.shields.io/badge/GitHub-david--x3d%2Fios--cert--checker-181717?logo=github)](https://github.com/david-x3d/ios-cert-checker)
![Node](https://img.shields.io/badge/node-%3E%3D18.17-339933)
![License](https://img.shields.io/badge/license-MIT-blue)

`ios-cert-checker` inspects local `.p12` certificates and `.mobileprovision` files, then reports signing metadata, entitlement details, expiry status, and certificate/profile compatibility. It is inspection-only: it does not upload files, sign IPAs, distribute apps, or call external services unless you explicitly request OCSP checks.

## ✨ Features

- Interactive wizard for guided certificate/profile inspection.
- `.p12` parsing with password validation, common name, Team ID, serials, dates, and SHA fingerprints.
- `.mobileprovision` parsing with profile metadata, devices, entitlements, app ID, and embedded developer certificates.
- Compatibility checks for expiry, Team ID match, profile validity, and embedded certificate fingerprints.
- Optional OCSP revocation checks for Apple signing certificates.
- JSON output for scripts and CI.
- Privacy-first local behavior with masked password prompts.

## 📦 Installation

```bash
npm install -g ios-cert-checker
```

Requirements:

| Tool | Purpose |
| --- | --- |
| Node.js `>=18.17` | CLI runtime |
| OpenSSL | CMS extraction, `.p12` fallback parsing, and OCSP checks |

## 🚀 Quick Start

Launch the wizard:

```bash
ios-cert-checker wizard
```

Validate a certificate and provisioning profile:

```bash
ios-cert-checker check \
  --p12 cert.p12 \
  --provision profile.mobileprovision \
  --password "password"
```

Inspect a certificate:

```bash
ios-cert-checker cert --p12 cert.p12 --password "password"
```

Inspect a provisioning profile:

```bash
ios-cert-checker provision profile.mobileprovision
```

Print JSON:

```bash
ios-cert-checker check \
  --p12 cert.p12 \
  --provision profile.mobileprovision \
  --password "password" \
  --json
```

## 🧙 Wizard Mode

```text
╭─ ios-cert-checker ───────────╮
│ Local iOS signing inspector  │
│ Interactive Wizard           │
╰──────────────────────────────╯

Choose Mode
1  Check certificate + provisioning profile
2  Inspect certificate only
3  Inspect provisioning profile only

? Choose a mode (1):
? Path to .p12:
? Path to .mobileprovision:
? P12 password: ********
```

Passwords are masked while typing and are never printed.

## 🔎 Output

```text
◆ Reading PKCS#12 certificate
◆ Extracting provisioning profile plist
◆ Comparing certificate and profile

╭─ Status ──────────╮
│ ● VALID           │
│ All checks passed │
╰───────────────────╯

╭─ Certificate ──────────────────────────────────────────────────────────────╮
│ Common Name     │ iPhone Distribution: Example User (TEAMID1234)           │
│ Team ID         │ TEAMID1234                                               │
│ Expiration      │ 2027-02-11 10:39:20 UTC                                  │
│ SHA-1           │ AA:BB:CC:DD:EE:FF:...                                    │
│ SHA-256         │ 11:22:33:44:55:66:...                                    │
╰────────────────────────────────────────────────────────────────────────────╯

╭─ Validation ─────────────────────────────────────────────╮
│ ✓ Certificate is currently valid                         │
│ ✓ Provisioning profile is currently valid                │
│ ✓ Team IDs match                                         │
│ ✓ Certificate appears to match provisioning profile      │
╰──────────────────────────────────────────────────────────╯
```

## 🧾 JSON Mode

`--json` is intentionally noninteractive. Missing inputs return structured errors.

```json
{
  "certificate": {
    "commonName": "iPhone Distribution: Example User (TEAMID1234)",
    "teamId": "TEAMID1234",
    "expiration": "2027-02-11T10:39:20.000Z",
    "sha1Fingerprint": "AA:BB:CC:DD:...",
    "sha256Fingerprint": "11:22:33:44:...",
    "isCurrentlyValid": true
  },
  "validation": {
    "status": "VALID",
    "checks": [
      {
        "name": "certificate-currently-valid",
        "status": "pass",
        "message": "Certificate is currently valid"
      }
    ]
  }
}
```

## 🛰 OCSP Revocation Checks

OCSP is opt-in because it contacts the certificate’s OCSP responder:

```bash
ios-cert-checker cert --p12 cert.p12 --password "password" --ocsp
ios-cert-checker check --p12 cert.p12 --provision profile.mobileprovision --password "password" --ocsp
```

The package includes Apple WWDR intermediate issuer certificates G2 through G6 for normal Apple signing certificates. Non-Apple certificates may still require their issuer certificate in the `.p12`.

## 🔐 Privacy & Security

- Files stay on your machine.
- No telemetry, analytics, or tracking.
- The CLI does not make network requests unless `--ocsp` is passed.
- `.p12` passwords are never printed.
- Private key material is never logged.
- OpenSSL fallback uses public certificate extraction with `-nokeys`.

## ⚠️ Limitations

- CRL checks are not implemented.
- XML plist payloads are supported; binary plist payloads return a clear unsupported-format error.
- Team ID and profile type detection are best-effort.
- Certificate/profile matching depends on embedded `DeveloperCertificates`.
- The wizard is terminal-friendly and focused, not a full-screen TUI.

## 🧪 Development

```bash
git clone https://github.com/david-x3d/ios-cert-checker.git
cd ios-cert-checker
npm install
npm run build
npm run typecheck
```

Run from source:

```bash
npm run dev -- wizard
```

Package dry run:

```bash
npm pack --dry-run
```

## 📄 License

MIT

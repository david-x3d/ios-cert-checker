# 🍏 ios-cert-checker

> A polished local CLI/TUI for inspecting Apple iOS signing certificates and provisioning profiles.

`ios-cert-checker` reads your local `.p12` and `.mobileprovision` files, extracts the important signing details, and gives you a clean compatibility report.

It is **inspection-only**. It does not upload files, sign IPAs, share certificates, distribute apps, or call external APIs.

---

## ✨ What It Looks Like

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
│ Valid From      │ 2026-02-11 10:39:21 UTC                                  │
│ Expiration      │ 2027-02-11 10:39:20 UTC                                  │
│ Days Left       │ 270                                                      │
│ Serial          │ 123456789                                                │
│ SHA-1           │ AA:BB:CC:DD:EE:FF:...                                    │
│ SHA-256         │ 11:22:33:44:55:66:...                                    │
│ Currently Valid │ yes                                                      │
╰────────────────────────────────────────────────────────────────────────────╯

╭─ Entitlements ────────────────────────────────────╮
│ ◇ application-identifier                          │
│   TEAMID1234.com.example.app                      │
│                                                   │
│ ◇ com.apple.developer.networking.networkextension │
│   • app-proxy-provider                            │
│   • content-filter-provider                       │
│   • packet-tunnel-provider                        │
│   • dns-proxy                                     │
╰───────────────────────────────────────────────────╯

╭─ Validation ─────────────────────────────────────────────╮
│ ✓ Certificate is currently valid                         │
│ ✓ Provisioning profile is currently valid                │
│ ✓ Team IDs match                                         │
│ ✓ Certificate appears to match provisioning profile      │
╰──────────────────────────────────────────────────────────╯
```

---

## 🔥 Highlights

| Feature | Details |
|---|---|
| 🧙 Interactive wizard | Guided local flow for cert/profile inspection |
| 🎨 Pretty terminal output | Rounded panels, colored status, wrapped long values |
| 🔐 `.p12` inspection | Password validation, CN, Team ID, serials, dates, SHA fingerprints |
| 📄 `.mobileprovision` inspection | Profile metadata, devices, entitlements, embedded certificates |
| 🧪 Compatibility checks | Team ID match, expiration, developer certificate fingerprint match |
| 🛰️ Revocation checks | Optional OCSP status checks with built-in Apple WWDR issuers |
| 🧾 JSON mode | Script-friendly output with `--json` |
| 🔒 Privacy-first | No uploads, no telemetry, no analytics; network is used only when `--ocsp` is requested |

---

## 📦 Install From GitHub

```bash
git clone https://github.com/david-x3d/ios-cert-checker.git
cd ios-cert-checker
npm install
npm run build
npm link
ios-cert-checker wizard
```

After `npm link`, the `ios-cert-checker` command is available from your terminal:

```bash
ios-cert-checker --help
ios-cert-checker check --interactive
ios-cert-checker cert --interactive
ios-cert-checker provision --interactive
```

### Direct Local Run

You can also run the built CLI without linking:

```bash
node dist/index.js wizard
```

### Requirements

| Tool | Purpose |
|---|---|
| Node.js `>=18.17` | CLI runtime |
| npm | Install/build workflow |
| OpenSSL | CMS extraction and `.p12` fallback parsing |

---

## 🧙 Wizard Mode

The easiest way to use the tool:

```bash
ios-cert-checker wizard
```

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

---

## 🚀 Commands

### Validate Certificate + Profile

```bash
ios-cert-checker check \
  --p12 cert.p12 \
  --provision profile.mobileprovision \
  --password "password"
```

Add OCSP revocation checking:

```bash
ios-cert-checker check \
  --p12 cert.p12 \
  --provision profile.mobileprovision \
  --password "password" \
  --ocsp
```

### Inspect Certificate Only

```bash
ios-cert-checker cert \
  --p12 cert.p12 \
  --password "password"
```

With OCSP:

```bash
ios-cert-checker cert \
  --p12 cert.p12 \
  --password "password" \
  --ocsp
```

### Inspect Provisioning Profile Only

```bash
ios-cert-checker provision profile.mobileprovision
```

### Prompt for Missing Input

```bash
ios-cert-checker check --interactive
ios-cert-checker cert --interactive
ios-cert-checker provision --interactive
```

### JSON Output

```bash
ios-cert-checker check \
  --p12 cert.p12 \
  --provision profile.mobileprovision \
  --password "password" \
  --json
```

`--json` is intentionally noninteractive. Missing inputs return structured errors.

---

## 🧾 JSON Example

```json
{
  "certificate": {
    "commonName": "iPhone Distribution: Example User (TEAMID1234)",
    "teamId": "TEAMID1234",
    "validFrom": "2026-02-11T10:39:21.000Z",
    "expiration": "2027-02-11T10:39:20.000Z",
    "serialDecimal": "123456789",
    "serialHex": "075BCD15",
    "sha1Fingerprint": "AA:BB:CC:DD:...",
    "sha256Fingerprint": "11:22:33:44:...",
    "isCurrentlyValid": true,
    "daysUntilExpiration": 270,
    "revocation": {
      "method": "OCSP",
      "checked": true,
      "status": "good",
      "ocspUrl": "http://ocsp.example.com",
      "checkedAt": "2026-05-16T01:12:00.000Z",
      "thisUpdate": "2026-05-16T00:00:00.000Z",
      "nextUpdate": "2026-05-23T00:00:00.000Z",
      "revocationTime": null,
      "reason": null
    }
  },
  "provisioningProfile": {
    "name": "Example Profile",
    "uuid": "00000000-0000-0000-0000-000000000000",
    "teamName": "Example User",
    "teamId": "TEAMID1234",
    "appIdName": "Example App",
    "applicationIdentifier": "TEAMID1234.com.example.app",
    "bundleId": "com.example.app",
    "isWildcard": false,
    "profileType": "Ad Hoc",
    "platform": ["iOS"],
    "provisionedDevices": ["00008020-001C2D1234567890"],
    "entitlements": {
      "application-identifier": "TEAMID1234.com.example.app",
      "aps-environment": "production"
    }
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

---

## 🔎 What Gets Parsed

### Certificate Fields

- Common Name
- Team ID, when detectable
- Valid From
- Expiration
- Days until expiration
- Serial decimal
- Serial hex
- SHA-1 fingerprint
- SHA-256 fingerprint
- Current validity state
- OCSP revocation status when `--ocsp` is used

### Provisioning Profile Fields

- Name
- UUID
- Team Name
- Team ID
- App ID Name
- Application Identifier
- Bundle ID and wildcard state
- Creation Date
- Expiration Date
- Platform
- Profile type
- Provisioned device UDIDs
- Entitlements
- Embedded developer certificates

### Validation Checks

- Certificate is currently valid
- Certificate revocation status is good, revoked, unknown, skipped, or errored when `--ocsp` is used
- Provisioning profile is currently valid
- Team IDs match
- Profile contains developer certificates
- `.p12` certificate fingerprint matches an embedded profile certificate, where possible

---

## 🔒 Privacy & Security

- Files stay on your machine.
- The CLI does not make network requests unless `--ocsp` is passed.
- No telemetry, analytics, or tracking.
- The `.p12` password is never printed.
- Private key material is never logged.
- Private keys are never saved to disk.
- OpenSSL fallback uses public certificate extraction with `-nokeys`.
- Temporary files are not used by the current implementation.

---

## 🧠 How It Works

### `.p12`

The tool first parses PKCS#12 data with `node-forge`.

If that is not enough, it falls back to OpenSSL:

```bash
openssl pkcs12 -nokeys
```

The password is passed through an environment variable instead of being printed in terminal output.

### OCSP Revocation

Revocation checking is available with `--ocsp` on `cert` and `check`.

```bash
ios-cert-checker cert --p12 cert.p12 --password "password" --ocsp
ios-cert-checker check --p12 cert.p12 --provision profile.mobileprovision --password "password" --ocsp
```

The app includes Apple WWDR intermediate issuer certificates G2 through G6, including G3 for Apple/iOS Development and Distribution certificates. For normal Apple signing certificates, you do not need to add an issuer certificate manually.

OCSP checks use OpenSSL and contact the OCSP responder URL advertised by the certificate. This is the only feature that intentionally makes a network request. The tool writes only temporary public certificate files in the OS temp directory for the OpenSSL OCSP command and deletes them immediately.

### `.mobileprovision`

Provisioning profiles are CMS/PKCS#7 signed plist files.

Primary extraction:

```bash
openssl smime -inform DER -verify -noverify -in profile.mobileprovision
```

Fallback extraction:

```bash
openssl cms -inform DER -verify -noverify -in profile.mobileprovision
```

---

## ⚠️ Limitations

- OCSP checks require an issuer certificate. Apple WWDR G2-G6 issuers are bundled; non-Apple certificates still need their issuer in the `.p12`.
- CRL checks are not implemented.
- XML plist payloads are supported.
- Binary plist payloads return a clear unsupported-format error.
- Team ID detection is best-effort.
- Profile type detection is best-effort.
- Certificate/profile matching depends on embedded `DeveloperCertificates`.
- The TUI is lightweight and terminal-friendly, not a full-screen terminal app.

---

## 🛠️ Development

```bash
npm install
npm run build
npm run typecheck
```

Run from source:

```bash
npm run dev -- wizard
```

Run the built CLI:

```bash
node dist/index.js wizard
```

Package dry run:

```bash
npm pack --dry-run
```

---

## 📁 Project Structure

```text
ios-cert-checker/
├── src/
│   ├── index.ts       # CLI commands, prompts, and TUI output
│   ├── cert.ts        # .p12 parsing
│   ├── provision.ts   # .mobileprovision parsing
│   ├── validate.ts    # compatibility checks
│   └── types.ts       # shared TypeScript types
├── package.json
├── package-lock.json
├── tsconfig.json
└── README.md
```

---

## 📜 License

MIT

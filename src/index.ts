#!/usr/bin/env node
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { Command, Option } from "commander";
import chalk from "chalk";
import { parseP12 } from "./cert.js";
import { parseMobileProvision } from "./provision.js";
import { checkOcspRevocation } from "./revocation.js";
import { validateCertificate, validatePair, validateProvision } from "./validate.js";
import type {
  CertReport,
  CertificateInfo,
  CheckReport,
  ProvisioningProfileInfo,
  ProvisionReport,
  RevocationInfo,
  ValidationCheck,
  ValidationResult,
} from "./types.js";

interface CertCommandOptions {
  p12?: string;
  password?: string;
  ocsp?: boolean;
  interactive?: boolean;
  json?: boolean;
}

interface ProvisionCommandOptions {
  interactive?: boolean;
  json?: boolean;
}

interface CheckCommandOptions {
  p12?: string;
  provision?: string;
  password?: string;
  ocsp?: boolean;
  interactive?: boolean;
  json?: boolean;
}

interface CertInput {
  p12: string;
  password: string;
  ocsp: boolean;
}

interface ProvisionInput {
  provision: string;
}

interface CheckInput extends CertInput, ProvisionInput {}

type WizardMode = "check" | "cert" | "provision";

const theme = {
  accent: chalk.hex("#7DD3FC"),
  accentStrong: chalk.hex("#38BDF8").bold,
  muted: chalk.hex("#94A3B8"),
  good: chalk.hex("#22C55E"),
  goodStrong: chalk.hex("#22C55E").bold,
  warn: chalk.hex("#F59E0B"),
  warnStrong: chalk.hex("#F59E0B").bold,
  bad: chalk.hex("#EF4444"),
  badStrong: chalk.hex("#EF4444").bold,
  title: chalk.hex("#E0F2FE").bold,
  label: chalk.hex("#A5B4FC"),
  value: chalk.hex("#F8FAFC"),
};

const program = new Command();

program
  .name("ios-cert-checker")
  .description(
    "Privacy-first local CLI for inspecting Apple iOS signing certificates and provisioning profiles.",
  )
  .version("0.1.0");

const jsonOption = new Option("--json", "print machine-readable JSON output");
const interactiveOption = new Option(
  "-i, --interactive",
  "prompt for missing input with an interactive terminal flow",
);
const ocspOption = new Option(
  "--ocsp",
  "check certificate revocation status with OCSP (contacts the certificate OCSP responder)",
);

program
  .command("wizard")
  .description("Launch an interactive TUI-style inspection wizard")
  .action(() =>
    runCli(false, async () => {
      await runWizard();
    }),
  );

program
  .command("cert")
  .description("Inspect a local .p12 certificate")
  .option("--p12 <path>", "path to .p12 file")
  .option("--password <password>", "PKCS#12 password")
  .addOption(ocspOption)
  .addOption(interactiveOption)
  .addOption(jsonOption)
  .action((options: CertCommandOptions) =>
    runCli(options.json, async () => {
      const input = await resolveCertInput(options, options.json);
      const report = buildCertReport(input, !options.json);

      if (options.json) {
        printJson(report);
      } else {
        printCertReport(report);
      }
    }),
  );

program
  .command("provision")
  .description("Inspect a local .mobileprovision profile")
  .argument("[profile]", "path to .mobileprovision file")
  .addOption(interactiveOption)
  .addOption(jsonOption)
  .action((profile: string | undefined, options: ProvisionCommandOptions) =>
    runCli(options.json, async () => {
      const input = await resolveProvisionInput(profile, options, options.json);
      const report = buildProvisionReport(input, !options.json);

      if (options.json) {
        printJson(report);
      } else {
        printProvisionReport(report);
      }
    }),
  );

program
  .command("check")
  .description("Validate a .p12 certificate against a .mobileprovision profile")
  .option("--p12 <path>", "path to .p12 file")
  .option("--provision <path>", "path to .mobileprovision file")
  .option("--password <password>", "PKCS#12 password")
  .addOption(ocspOption)
  .addOption(interactiveOption)
  .addOption(jsonOption)
  .action((options: CheckCommandOptions) =>
    runCli(options.json, async () => {
      const input = await resolveCheckInput(options, options.json);
      const report = buildCheckReport(input, !options.json);

      if (options.json) {
        printJson(report);
      } else {
        printCheckReport(report);
      }
    }),
  );

async function runWizard(): Promise<void> {
  printBanner("Interactive Wizard");

  const prompt = new PromptSession();
  try {
    const mode = await promptMode(prompt);

    if (mode === "cert") {
      const input = await promptCertInput(prompt, true);
      printCertReport(buildCertReport(input, true));
      return;
    }

    if (mode === "provision") {
      const input = await promptProvisionInput(prompt);
      printProvisionReport(buildProvisionReport(input, true));
      return;
    }

    const input = await promptCheckInput(prompt);
    printCheckReport(buildCheckReport(input, true));
  } finally {
    prompt.close();
  }
}

function buildCertReport(input: CertInput, tui: boolean): CertReport {
  if (tui) {
    printStep("Reading PKCS#12 certificate");
  }
  const parsed = parseP12(input.p12, input.password);
  if (input.ocsp) {
    if (tui) {
      printStep("Checking certificate revocation with OCSP");
    }
    parsed.info.revocation = checkOcspRevocation(parsed);
  }
  if (tui) {
    printStep("Inspecting certificate metadata");
  }
  const validation = validateCertificate(parsed.info);
  return { certificate: parsed.info, validation };
}

function buildProvisionReport(input: ProvisionInput, tui: boolean): ProvisionReport {
  if (tui) {
    printStep("Extracting provisioning profile plist");
  }
  const parsed = parseMobileProvision(input.provision);
  if (tui) {
    printStep("Inspecting profile entitlements");
  }
  const validation = validateProvision(parsed.info);
  return { provisioningProfile: parsed.info, validation };
}

function buildCheckReport(input: CheckInput, tui: boolean): CheckReport {
  if (tui) {
    printStep("Reading PKCS#12 certificate");
  }
  const certificate = parseP12(input.p12, input.password);
  if (input.ocsp) {
    if (tui) {
      printStep("Checking certificate revocation with OCSP");
    }
    certificate.info.revocation = checkOcspRevocation(certificate);
  }

  if (tui) {
    printStep("Extracting provisioning profile plist");
  }
  const provisioningProfile = parseMobileProvision(input.provision);

  if (tui) {
    printStep("Comparing certificate and profile");
  }
  const validation = validatePair(certificate, provisioningProfile);

  return {
    certificate: certificate.info,
    provisioningProfile: provisioningProfile.info,
    validation,
  };
}

async function resolveCertInput(
  options: CertCommandOptions,
  json: boolean | undefined,
): Promise<CertInput> {
  const shouldPrompt = canPrompt(json) && (options.interactive || !options.p12);
  if (!shouldPrompt) {
    return {
      p12: requireValue(options.p12, "--p12 <path>"),
      password: options.password ?? "",
      ocsp: options.ocsp === true,
    };
  }

  printBanner("Interactive Input");
  const prompt = new PromptSession();
  try {
    const p12 = options.p12 ?? (await prompt.text("Path to .p12"));
    const password =
      options.password ?? (options.interactive ? await prompt.password("P12 password") : "");
    const ocsp =
      options.ocsp === true ||
      Boolean(options.interactive && (await prompt.confirm("Check revocation with OCSP?")));
    return { p12, password, ocsp };
  } finally {
    prompt.close();
  }
}

async function resolveProvisionInput(
  profile: string | undefined,
  options: ProvisionCommandOptions,
  json: boolean | undefined,
): Promise<ProvisionInput> {
  const shouldPrompt = canPrompt(json) && (options.interactive || !profile);
  if (!shouldPrompt) {
    return { provision: requireValue(profile, "<profile>") };
  }

  printBanner("Interactive Input");
  const prompt = new PromptSession();
  try {
    return { provision: profile ?? (await prompt.text("Path to .mobileprovision")) };
  } finally {
    prompt.close();
  }
}

async function resolveCheckInput(
  options: CheckCommandOptions,
  json: boolean | undefined,
): Promise<CheckInput> {
  const shouldPrompt = canPrompt(json) && (options.interactive || !options.p12 || !options.provision);
  if (!shouldPrompt) {
    return {
      p12: requireValue(options.p12, "--p12 <path>"),
      provision: requireValue(options.provision, "--provision <path>"),
      password: options.password ?? "",
      ocsp: options.ocsp === true,
    };
  }

  printBanner("Interactive Input");
  const prompt = new PromptSession();
  try {
    const p12 = options.p12 ?? (await prompt.text("Path to .p12"));
    const provision =
      options.provision ?? (await prompt.text("Path to .mobileprovision"));
    const password =
      options.password ?? (options.interactive ? await prompt.password("P12 password") : "");
    const ocsp =
      options.ocsp === true ||
      Boolean(options.interactive && (await prompt.confirm("Check revocation with OCSP?")));
    return { p12, provision, password, ocsp };
  } finally {
    prompt.close();
  }
}

async function promptMode(prompt: PromptSession): Promise<WizardMode> {
  printMenu([
    ["1", "Check certificate + provisioning profile"],
    ["2", "Inspect certificate only"],
    ["3", "Inspect provisioning profile only"],
  ]);

  const choice = await prompt.text("Choose a mode", "1");
  if (choice === "2") {
    return "cert";
  }
  if (choice === "3") {
    return "provision";
  }
  return "check";
}

async function promptCheckInput(prompt: PromptSession): Promise<CheckInput> {
  const p12 = await prompt.text("Path to .p12");
  const provision = await prompt.text("Path to .mobileprovision");
  const password = await prompt.password("P12 password");
  const ocsp = await prompt.confirm("Check revocation with OCSP?");
  return { p12, provision, password, ocsp };
}

async function promptCertInput(prompt: PromptSession, includePassword: boolean): Promise<CertInput> {
  const p12 = await prompt.text("Path to .p12");
  const password = includePassword ? await prompt.password("P12 password") : "";
  const ocsp = await prompt.confirm("Check revocation with OCSP?");
  return { p12, password, ocsp };
}

async function promptProvisionInput(prompt: PromptSession): Promise<ProvisionInput> {
  return { provision: await prompt.text("Path to .mobileprovision") };
}

async function runCli(
  json: boolean | undefined,
  handler: () => void | Promise<void>,
): Promise<void> {
  try {
    await handler();
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    if (json) {
      printJson({
        validation: {
          status: "INVALID",
          checks: [{ name: "cli-error", status: "fail", message }],
        },
        error: message,
      });
    } else {
      printError(message);
    }
    process.exitCode = 1;
  }
}

function canPrompt(json: boolean | undefined): boolean {
  return !json && Boolean(stdin.isTTY);
}

function requireValue(value: string | undefined, label: string): string {
  if (!value) {
    throw new Error(`Missing required input: ${label}`);
  }
  return value;
}

function printJson(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

function printCertReport(report: CertReport): void {
  printStatus(report.validation);
  printCertificate(report.certificate);
  printValidation(report.validation);
}

function printProvisionReport(report: ProvisionReport): void {
  printStatus(report.validation);
  printProvisioningProfile(report.provisioningProfile);
  printValidation(report.validation);
}

function printCheckReport(report: CheckReport): void {
  printStatus(report.validation);
  printCertificate(report.certificate);
  printProvisioningProfile(report.provisioningProfile);
  printValidation(report.validation);
}

function printBanner(mode: string): void {
  printBox("ios-cert-checker", [
    theme.title("Local iOS signing inspector"),
    theme.muted(mode),
  ]);
}

function printMenu(items: Array<[string, string]>): void {
  console.log();
  console.log(theme.title("Choose Mode"));
  for (const [key, label] of items) {
    console.log(`${theme.accentStrong(key)}  ${theme.value(label)}`);
  }
  console.log();
}

function printStep(label: string): void {
  console.log(`${theme.accent("◆")} ${theme.muted(label)}`);
}

function printStatus(validation: ValidationResult): void {
  const status = colorStatus(validation.status)(`● ${validation.status}`);
  const detail =
    validation.status === "VALID"
      ? theme.good("All checks passed")
      : validation.status === "WARNING"
        ? theme.warn("Review the warnings below")
        : theme.bad("One or more checks failed");

  printBox("Status", [status, detail]);
}

function printCertificate(cert: CertificateInfo): void {
  printPanel("Certificate", [
    ["Common Name", cert.commonName],
    ["Team ID", cert.teamId],
    ["Valid From", formatDateTime(cert.validFrom)],
    ["Expiration", formatDateTime(cert.expiration)],
    ["Days Left", cert.daysUntilExpiration],
    ["Serial", cert.serialDecimal],
    ["Serial Hex", cert.serialHex],
    ["SHA-1", cert.sha1Fingerprint],
    ["SHA-256", cert.sha256Fingerprint],
    ["Currently Valid", cert.isCurrentlyValid ? "yes" : "no"],
  ]);

  if (cert.revocation) {
    printRevocation(cert.revocation);
  }
}

function printRevocation(revocation: RevocationInfo): void {
  const statusColor =
    revocation.status === "good"
      ? theme.good
      : revocation.status === "revoked"
        ? theme.bad
        : theme.warn;

  printPanel("Revocation", [
    ["Method", revocation.method],
    ["Status", statusColor(revocation.status)],
    ["Checked", revocation.checked ? "yes" : "no"],
    ["OCSP URL", revocation.ocspUrl],
    ["Checked At", formatDateTime(revocation.checkedAt)],
    ["This Update", formatDateTime(revocation.thisUpdate)],
    ["Next Update", formatDateTime(revocation.nextUpdate)],
    ["Revoked At", formatDateTime(revocation.revocationTime)],
    ["Reason", revocation.reason],
  ]);
}

function printProvisioningProfile(profile: ProvisioningProfileInfo): void {
  printPanel("Provisioning Profile", [
    ["Name", profile.name],
    ["Type", profile.profileType],
    ["Team", profile.teamName],
    ["Team ID", profile.teamId],
    ["App ID Name", profile.appIdName],
    ["App ID", profile.applicationIdentifier],
    ["Bundle ID", formatBundleId(profile.bundleId, profile.isWildcard)],
    ["UUID", profile.uuid],
    ["Platform", profile.platform.length > 0 ? profile.platform.join(", ") : null],
    ["Created", formatDateTime(profile.creationDate)],
    ["Expiration", formatDateTime(profile.expirationDate)],
    ["Days Left", profile.daysUntilExpiration],
    ["Registered Devices", profile.provisionedDevices.length],
    ["Developer Certificates", profile.developerCertificates.length],
  ]);

  if (profile.provisionedDevices.length > 0) {
    printBox("Provisioned Devices", profile.provisionedDevices.map((udid) => `• ${udid}`));
  }

  printEntitlements(profile.entitlements);
}

function printValidation(validation: ValidationResult): void {
  printBox(
    "Validation",
    validation.checks.map((check) => `${icon(check)} ${check.message}`),
  );
}

function printPanel(title: string, rows: Array<[string, unknown]>): void {
  const labelWidth = Math.min(Math.max(...rows.map(([label]) => label.length)), 24);
  const valueWidth = Math.max(18, boxContentWidth() - labelWidth - 3);
  const lines = rows.flatMap(([label, value]) =>
    formatPanelRow(label, formatValue(value), labelWidth, valueWidth),
  );
  printBox(title, lines);
}

function printEntitlements(entitlements: Record<string, unknown>): void {
  const entries = Object.entries(entitlements);
  if (entries.length === 0) {
    printBox("Entitlements", [theme.muted("none")]);
    return;
  }

  const valueWidth = Math.max(24, boxContentWidth() - 6);
  const lines = entries.flatMap(([key, value], index) => {
    const keyLines = wrapText(key, valueWidth);
    const valueLines = formatEntitlementValue(value, valueWidth);
    const spacer = index === entries.length - 1 ? [] : [""];
    return [
      ...keyLines.map((line, lineIndex) =>
        lineIndex === 0 ? `${theme.accent("◇")} ${theme.label(line)}` : `  ${theme.label(line)}`,
      ),
      ...valueLines.map((line) => `  ${line}`),
      ...spacer,
    ];
  });

  printBox("Entitlements", lines);
}

function formatPanelRow(
  label: string,
  value: string,
  labelWidth: number,
  valueWidth: number,
): string[] {
  const labelText = truncateMiddle(label, labelWidth);
  const valueLines = wrapText(value, valueWidth);
  const emptyLabel = " ".repeat(labelWidth);

  return valueLines.map((line, index) => {
    const rowLabel = index === 0 ? labelText.padEnd(labelWidth) : emptyLabel;
    return `${theme.label(rowLabel)} ${theme.muted("│")} ${theme.value(line)}`;
  });
}

function printError(message: string): void {
  printBox("Error", [theme.bad(message)]);
}

function printBox(title: string, lines: string[]): void {
  const width = Math.max(
    Math.min(Math.max(...[title, ...lines].map(visibleLength), visibleLength(title) + 1), boxContentWidth()),
    12,
  );
  const topTitle = title ? `─ ${title} ` : "";
  const topFill = "─".repeat(Math.max(0, width + 2 - visibleLength(topTitle)));
  const horizontal = "─".repeat(width + 2);

  console.log();
  console.log(theme.accent(`╭${topTitle}${topFill}╮`));
  for (const line of lines) {
    for (const wrappedLine of wrapLine(line, width)) {
      console.log(`${theme.accent("│")} ${padVisible(wrappedLine, width)} ${theme.accent("│")}`);
    }
  }
  console.log(theme.accent(`╰${horizontal}╯`));
}

function colorStatus(status: ValidationResult["status"]): (value: string) => string {
  if (status === "VALID") {
    return chalk.green.bold;
  }
  if (status === "WARNING") {
    return chalk.yellow.bold;
  }
  return chalk.red.bold;
}

function icon(check: ValidationCheck): string {
  if (check.status === "pass") {
    return theme.good("✓");
  }
  if (check.status === "warning") {
    return theme.warn("!");
  }
  return theme.bad("✗");
}

function formatDateTime(value: string | null): string {
  if (!value) {
    return "unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

function formatBundleId(bundleId: string | null, isWildcard: boolean): string {
  if (!bundleId) {
    return "unknown";
  }
  return isWildcard ? `${bundleId} (wildcard)` : `${bundleId} (explicit)`;
}

function formatValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.length === 0 ? "[]" : value.join(", ");
  }
  if (value instanceof Date) {
    return formatDateTime(value.toISOString());
  }
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function formatEntitlementValue(value: unknown, width: number): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return [theme.muted("[]")];
    }

    return value.flatMap((item) => {
      const itemText = formatValue(item);
      return wrapText(itemText, Math.max(12, width - 2)).map((line, index) =>
        index === 0 ? `${theme.muted("•")} ${theme.value(line)}` : `  ${theme.value(line)}`,
      );
    });
  }

  if (value && typeof value === "object" && !(value instanceof Date)) {
    return wrapText(JSON.stringify(value), width).map((line) => theme.value(line));
  }

  return wrapText(formatValue(value), width).map((line) => theme.value(line));
}

function visibleLength(value: string): number {
  return stripAnsi(value).length;
}

function padVisible(value: string, width: number): string {
  return value + " ".repeat(Math.max(0, width - visibleLength(value)));
}

function boxContentWidth(): number {
  const columns = stdout.columns ?? 100;
  return Math.max(36, Math.min(columns - 4, 116));
}

function wrapLine(value: string, width: number): string[] {
  if (visibleLength(value) <= width) {
    return [value];
  }

  return wrapText(stripAnsi(value), width);
}

function wrapText(value: string, width: number): string[] {
  const text = value.length > 0 ? value : "unknown";
  const words = text.split(/(\s+)/).filter((part) => part.length > 0);
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (/^\s+$/.test(word)) {
      continue;
    }

    if (word.length > width) {
      if (current) {
        lines.push(current);
        current = "";
      }
      lines.push(...wrapLongToken(word, width));
      continue;
    }

    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > width && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }

  if (current) {
    lines.push(current);
  }

  return lines.length > 0 ? lines : ["unknown"];
}

function wrapLongToken(token: string, width: number): string[] {
  if (token.includes(":")) {
    return wrapDelimitedToken(token, ":", width);
  }

  const lines: string[] = [];
  for (let index = 0; index < token.length; index += width) {
    lines.push(token.slice(index, index + width));
  }
  return lines;
}

function wrapDelimitedToken(token: string, delimiter: string, width: number): string[] {
  const parts = token.split(delimiter);
  const lines: string[] = [];
  let current = "";

  for (const part of parts) {
    const candidate = current ? `${current}${delimiter}${part}` : part;
    if (candidate.length > width && current) {
      lines.push(current);
      current = part;
    } else if (candidate.length > width) {
      lines.push(...wrapLongToken(part, width));
      current = "";
    } else {
      current = candidate;
    }
  }

  if (current) {
    lines.push(current);
  }

  return lines;
}

function truncateMiddle(value: string, width: number): string {
  if (value.length <= width) {
    return value;
  }
  if (width <= 3) {
    return value.slice(0, width);
  }
  const left = Math.ceil((width - 1) / 2);
  const right = Math.floor((width - 1) / 2);
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function stripAnsi(value: string): string {
  return value.replace(/\u001B\[[0-9;]*m/g, "");
}

class PromptSession {
  private readonly rl = createInterface({ input: stdin, output: stdout });

  async text(label: string, defaultValue?: string): Promise<string> {
    const suffix = defaultValue ? ` (${defaultValue})` : "";
    const answer = await this.rl.question(`${chalk.cyan("?")} ${label}${suffix}: `);
    const trimmed = answer.trim();
    return trimmed || defaultValue || "";
  }

  async password(label: string): Promise<string> {
    this.rl.pause();
    return askHidden(`${chalk.cyan("?")} ${label}`);
  }

  async confirm(label: string, defaultValue = false): Promise<boolean> {
    const suffix = defaultValue ? "Y/n" : "y/N";
    const answer = await this.rl.question(`${chalk.cyan("?")} ${label} (${suffix}): `);
    const normalized = answer.trim().toLowerCase();
    if (!normalized) {
      return defaultValue;
    }
    return normalized === "y" || normalized === "yes";
  }

  close(): void {
    this.rl.close();
  }
}

function askHidden(label: string): Promise<string> {
  if (!stdin.isTTY) {
    return Promise.resolve("");
  }

  return new Promise((resolve, reject) => {
    let value = "";
    const wasRaw = stdin.isRaw;

    const cleanup = (): void => {
      stdin.off("data", onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
    };

    const finish = (): void => {
      cleanup();
      stdout.write("\n");
      resolve(value);
    };

    const cancel = (): void => {
      cleanup();
      stdout.write("\n");
      reject(new Error("Cancelled."));
    };

    const onData = (chunk: Buffer): void => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\u0003") {
          cancel();
          return;
        }
        if (char === "\r" || char === "\n") {
          finish();
          return;
        }
        if (char === "\u007f" || char === "\b") {
          if (value.length > 0) {
            value = value.slice(0, -1);
            stdout.write("\b \b");
          }
          continue;
        }
        if (char >= " ") {
          value += char;
          stdout.write("*");
        }
      }
    };

    stdout.write(`${label}: `);
    stdin.resume();
    stdin.setRawMode(true);
    stdin.on("data", onData);
  });
}

await program.parseAsync();

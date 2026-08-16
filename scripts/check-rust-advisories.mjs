import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POLICY_PATH = resolve(ROOT, "security", "rust-advisory-policy.json");

function keyOf(entry) {
  return [entry.kind, entry.advisory, entry.package, entry.version].join("|");
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

export function flattenWarnings(warnings = {}) {
  return Object.entries(warnings).flatMap(([kind, entries]) =>
    (Array.isArray(entries) ? entries : []).map((entry) => ({
      kind,
      advisory: entry?.advisory?.id,
      package: entry?.package?.name,
      version: entry?.package?.version,
    })),
  );
}

export function parseLockedPackages(lockText) {
  if (typeof lockText !== "string") return [];
  return lockText.split("[[package]]").slice(1).map((block) => ({
    name: block.match(/^name = "([^"]+)"/m)?.[1],
    version: block.match(/^version = "([^"]+)"/m)?.[1],
    source: block.match(/^source = "([^"]+)"/m)?.[1],
  })).filter((entry) => entry.name && entry.version);
}

export function evaluateAudit(report, policy, options = {}) {
  const errors = [];
  if (policy?.schemaVersion !== 1) errors.push("unsupported advisory policy schema");

  const reviewBy = Date.parse(`${requireString(policy.reviewBy, "reviewBy")}T23:59:59Z`);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (!Number.isFinite(reviewBy)) errors.push("reviewBy must be an ISO calendar date");
  else if (now > reviewBy) errors.push(`advisory policy review expired on ${policy.reviewBy}`);

  const allowed = Array.isArray(policy.allowedWarnings) ? policy.allowedWarnings : [];
  const allowedByKey = new Map();
  for (const [index, entry] of allowed.entries()) {
    for (const field of ["kind", "advisory", "package", "version", "reason"]) {
      requireString(entry?.[field], `allowedWarnings[${index}].${field}`);
    }
    const key = keyOf(entry);
    if (allowedByKey.has(key)) errors.push(`duplicate policy entry ${key}`);
    allowedByKey.set(key, entry);
  }


  const lockedPackages = parseLockedPackages(options.lockText);
  for (const [index, required] of (policy.requiredPinnedPackages ?? []).entries()) {
    for (const field of ["package", "version", "source", "reason"]) {
      requireString(required?.[field], `requiredPinnedPackages[${index}].${field}`);
    }
    const exact = lockedPackages.filter((entry) =>
      entry.name === required.package
      && entry.version === required.version
      && entry.source === required.source
    );
    if (exact.length !== 1) {
      errors.push(`required pinned package ${required.package}@${required.version} is not locked to ${required.source}`);
    }
  }

  const vulnerabilities = Array.isArray(report?.vulnerabilities?.list)
    ? report.vulnerabilities.list
    : [];
  const vulnerabilityCount = Number(report?.vulnerabilities?.count ?? vulnerabilities.length);
  if (vulnerabilityCount !== 0 || vulnerabilities.length !== 0) {
    const ids = vulnerabilities.map((item) => item?.advisory?.id).filter(Boolean);
    const count = Math.max(vulnerabilityCount, vulnerabilities.length);
    errors.push(`cargo audit reported ${count} vulnerabilit${count === 1 ? "y" : "ies"}${ids.length ? `: ${ids.join(", ")}` : ""}`);
  }

  const observed = flattenWarnings(report?.warnings);
  const observedKeys = new Set();
  for (const entry of observed) {
    for (const field of ["kind", "advisory", "package", "version"]) {
      requireString(entry[field], `cargo audit warning ${field}`);
    }
    const key = keyOf(entry);
    if (observedKeys.has(key)) errors.push(`cargo audit returned duplicate warning ${key}`);
    observedKeys.add(key);
    const policyEntry = allowedByKey.get(key);
    if (!policyEntry) {
      errors.push(`unreviewed warning ${entry.advisory} ${entry.package}@${entry.version} (${entry.kind})`);
      continue;
    }
    if (options.releaseTarget && policyEntry.releaseBlockers?.includes(options.releaseTarget)) {
      errors.push(`${entry.advisory} blocks ${options.releaseTarget}: ${policyEntry.reason}`);
    }
  }

  for (const [key, entry] of allowedByKey) {
    if (!observedKeys.has(key)) {
      errors.push(`stale policy entry ${entry.advisory} ${entry.package}@${entry.version} (${entry.kind})`);
    }
  }

  return { errors, observed };
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function runCargoAudit(expectedVersion) {
  const version = spawnSync("cargo", ["audit", "--version"], {
    cwd: ROOT,
    encoding: "utf8",
    windowsHide: true,
  });
  if (version.error) throw new Error(`unable to run cargo audit: ${version.error.message}`);
  if (version.status !== 0) throw new Error(version.stderr.trim() || "cargo audit --version failed");
  const actualVersion = version.stdout.match(/\b(\d+\.\d+\.\d+)\b/)?.[1];
  if (actualVersion !== expectedVersion) {
    throw new Error(`cargo-audit ${actualVersion ?? "unknown"} is installed, expected ${expectedVersion}`);
  }

  const result = spawnSync("cargo", ["audit", "--json"], {
    cwd: ROOT,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw new Error(`unable to run cargo audit: ${result.error.message}`);
  if (!result.stdout.trim()) throw new Error(result.stderr.trim() || "cargo audit returned no JSON");
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`cargo audit returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function main() {
  const [, , command = "check", releaseTarget] = process.argv;
  if (command !== "check" && command !== "release") {
    throw new Error("usage: node scripts/check-rust-advisories.mjs <check|release> [release-target]");
  }
  if (command === "release" && !releaseTarget) {
    throw new Error("release mode requires a target such as windows-mainnet, android-mainnet, linux-desktop-mainnet, or linux-hub-mainnet");
  }

  const policy = loadJson(POLICY_PATH);
  const report = runCargoAudit(requireString(policy.cargoAuditVersion, "cargoAuditVersion"));
  const outcome = evaluateAudit(report, policy, {
    releaseTarget: command === "release" ? releaseTarget : undefined,
    lockText: readFileSync(resolve(ROOT, "Cargo.lock"), "utf8"),
  });
  for (const entry of outcome.observed) {
    process.stdout.write(`reviewed RustSec warning: ${entry.advisory} ${entry.package}@${entry.version} (${entry.kind})\n`);
  }
  if (outcome.errors.length > 0) {
    throw new Error(outcome.errors.join("\n"));
  }
  process.stdout.write(`Rust advisory policy passed: 0 vulnerabilities, ${outcome.observed.length} exact reviewed warnings\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`rust-advisories: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

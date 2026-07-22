import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LOCAL_RUST_PACKAGES = [
  "dust-whisper",
  "hacash-wallet",
  "hacash-wallet-core",
  "hacash-wallet-mobile",
  "l2-fast-pay-hub",
  "wallet-tauri-common",
];
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function fail(message) {
  process.stderr.write("release-version: " + message + "\n");
  process.exitCode = 1;
}

function load(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), "utf8");
}

function save(relativePath, source) {
  writeFileSync(resolve(ROOT, relativePath), source, "utf8");
}

function replaceExactly(relativePath, pattern, replacement, optional = false) {
  const absolutePath = resolve(ROOT, relativePath);
  if (!existsSync(absolutePath)) {
    if (optional) return;
    throw new Error("missing version file: " + relativePath);
  }
  const source = readFileSync(absolutePath, "utf8");
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const matches = source.match(new RegExp(pattern.source, flags));
  if (!matches || matches.length !== 1) {
    throw new Error(relativePath + " expected exactly one version field, found " + (matches ? matches.length : 0));
  }
  const next = source.replace(pattern, replacement);
  if (next !== source) writeFileSync(absolutePath, next, "utf8");
}

function cargoVersion() {
  const match = load("Cargo.toml").match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
  if (!match) throw new Error("workspace version is missing from Cargo.toml");
  return match[1];
}

function androidVersionCode(version) {
  const parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part) || part < 0)) {
    throw new Error("Android releases require a numeric x.y.z version");
  }
  return parts[0] * 10000 + parts[1] * 100 + parts[2];
}

function escapeRegExp(value) {
  return value.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
}

function setVersion(version) {
  if (!VERSION_PATTERN.test(version)) throw new Error("invalid semantic version: " + version);
  const jsonFiles = [
    "apps/desktop/package.json",
    "apps/mobile/package.json",
    "packages/wallet-ui/package.json",
    "apps/desktop/src-tauri/tauri.conf.json",
    "apps/mobile/src-tauri/tauri.conf.json",
  ];

  replaceExactly(
    "Cargo.toml",
    /(\[workspace\.package\][\s\S]*?\nversion\s*=\s*")[^"]+(")/,
    "$1" + version + "$2",
  );
  for (const relativePath of jsonFiles) {
    replaceExactly(relativePath, /("version"\s*:\s*")[^"]+(")/, "$1" + version + "$2");
  }
  replaceExactly(
    "apps/mobile/src-tauri/tauri.conf.json",
    /("versionCode"\s*:\s*)\d+/,
    "$1" + androidVersionCode(version),
  );
  replaceExactly(
    "apps/desktop/hacd-browser-bridge/manifest.json",
    /("version"\s*:\s*")[^"]+(")/,
    "$1" + version + "$2",
    true,
  );
  replaceExactly(
    "apps/desktop/hacd-browser-bridge/inject.js",
    /(info:\s*\{\s*name:\s*"Hacash Wallet",\s*version:\s*")[^"]+(")/,
    "$1" + version + "$2",
    true,
  );

  for (const lockPath of ["apps/desktop/yarn.lock", "apps/mobile/yarn.lock"]) {
    replaceExactly(
      lockPath,
      /("@hacash\/wallet-ui@file:[^"]+":\r?\n\s+version\s+")[^"]+(")/,
      "$1" + version + "$2",
    );
  }

  const cargoLockPath = "Cargo.lock";
  let cargoLock = load(cargoLockPath);
  for (const packageName of LOCAL_RUST_PACKAGES) {
    const escapedName = escapeRegExp(packageName);
    const pattern = new RegExp('(\\[\\[package\\]\\]\\r?\\nname = "' + escapedName + '"\\r?\\nversion = ")[^"]+(")');
    if (!pattern.test(cargoLock)) throw new Error("Cargo.lock package is missing: " + packageName);
    cargoLock = cargoLock.replace(pattern, "$1" + version + "$2");
  }
  save(cargoLockPath, cargoLock);

  const androidProperties = "apps/mobile/src-tauri/gen/android/app/tauri.properties";
  if (existsSync(resolve(ROOT, androidProperties))) {
    let properties = load(androidProperties);
    properties = properties.replace(/(tauri\.android\.versionName=)[^\r\n]+/, "$1" + version);
    properties = properties.replace(
      /(tauri\.android\.versionCode=)[^\r\n]+/,
      "$1" + androidVersionCode(version),
    );
    save(androidProperties, properties);
  }
}

function jsonVersion(relativePath) {
  const parsed = JSON.parse(load(relativePath));
  return parsed.version;
}

function checkVersion(expected, tag) {
  const checks = [
    ["Cargo.toml", cargoVersion()],
    ["apps/desktop/package.json", jsonVersion("apps/desktop/package.json")],
    ["apps/mobile/package.json", jsonVersion("apps/mobile/package.json")],
    ["packages/wallet-ui/package.json", jsonVersion("packages/wallet-ui/package.json")],
    ["apps/desktop/src-tauri/tauri.conf.json", jsonVersion("apps/desktop/src-tauri/tauri.conf.json")],
    ["apps/mobile/src-tauri/tauri.conf.json", jsonVersion("apps/mobile/src-tauri/tauri.conf.json")],
  ];
  for (const [relativePath, actual] of checks) {
    if (actual !== expected) fail(relativePath + " is " + actual + ", expected " + expected);
  }
  const mobileTauri = JSON.parse(load("apps/mobile/src-tauri/tauri.conf.json"));
  const configuredVersionCode = mobileTauri.bundle?.android?.versionCode;
  if (configuredVersionCode !== androidVersionCode(expected)) {
    fail(
      "apps/mobile/src-tauri/tauri.conf.json Android versionCode is " +
        configuredVersionCode +
        ", expected " +
        androidVersionCode(expected),
    );
  }

  for (const lockPath of ["apps/desktop/yarn.lock", "apps/mobile/yarn.lock"]) {
    const match = load(lockPath).match(/"@hacash\/wallet-ui@file:[^"]+":\r?\n\s+version\s+"([^"]+)"/);
    if (!match || match[1] !== expected) {
      fail(lockPath + " wallet-ui entry does not match " + expected);
    }
  }

  const cargoLock = load("Cargo.lock");
  for (const packageName of LOCAL_RUST_PACKAGES) {
    const escapedName = escapeRegExp(packageName);
    const pattern = new RegExp('\\[\\[package\\]\\]\\r?\\nname = "' + escapedName + '"\\r?\\nversion = "([^"]+)"');
    const actual = cargoLock.match(pattern)?.[1];
    if (actual !== expected) fail("Cargo.lock " + packageName + " is " + actual + ", expected " + expected);
  }

  const androidProperties = "apps/mobile/src-tauri/gen/android/app/tauri.properties";
  if (existsSync(resolve(ROOT, androidProperties))) {
    const properties = load(androidProperties);
    const versionName = properties.match(/tauri\.android\.versionName=([^\r\n]+)/)?.[1];
    const versionCode = Number(properties.match(/tauri\.android\.versionCode=([^\r\n]+)/)?.[1]);
    if (versionName !== expected) fail(androidProperties + " versionName is " + versionName);
    if (versionCode !== androidVersionCode(expected)) fail(androidProperties + " versionCode is " + versionCode);
  }

  if (tag) {
    const allowed = new Set(["v" + expected + "-desktop", "v" + expected + "-mobile"]);
    if (!allowed.has(tag)) fail("tag " + tag + " does not match version " + expected);
  }
}

const [, , command, requestedVersion, requestedTag] = process.argv;
try {
  if (command === "set") {
    if (!requestedVersion) throw new Error("usage: node scripts/release-version.mjs set x.y.z");
    setVersion(requestedVersion);
    checkVersion(requestedVersion);
    process.stdout.write("Release version synchronized: " + requestedVersion + "\n");
  } else if (command === "check") {
    const environmentTag = process.env.GITHUB_REF_TYPE === "tag"
      ? process.env.GITHUB_REF_NAME
      : undefined;
    const expected = requestedVersion || cargoVersion();
    checkVersion(expected, requestedTag || environmentTag);
    if (!process.exitCode) process.stdout.write("Release version verified: " + expected + "\n");
  } else {
    throw new Error("usage: node scripts/release-version.mjs <set|check> [x.y.z] [tag]");
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  constants,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = join(ROOT, "target", "release");

function fail(message) {
  throw new Error(`release-artifacts: ${message}`);
}

function version() {
  const desktop = JSON.parse(readFileSync(join(ROOT, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
  if (!/^\d+\.\d+\.\d+$/.test(desktop.version)) fail(`invalid desktop version ${desktop.version}`);
  return desktop.version;
}

function walk(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

function requireSingle(directory, predicate, label) {
  const matches = walk(directory).filter(predicate);
  if (matches.length !== 1) {
    fail(`${label}: expected exactly one build output under ${directory}, found ${matches.length}`);
  }
  return matches[0];
}

function prepareOutput(directory) {
  mkdirSync(directory, { recursive: true });
  const existing = readdirSync(directory);
  if (existing.length !== 0) fail(`output directory is not empty: ${directory}`);
}

function copyExclusive(source, destination) {
  if (!statSync(source).isFile() || statSync(source).size === 0) fail(`empty build output: ${source}`);
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
}

function header(path, length = 64) {
  const data = readFileSync(path);
  if (data.length < length) fail(`artifact is unexpectedly short: ${path}`);
  return data;
}

function verifyPe(path, requireX64 = true) {
  const data = header(path, 512);
  if (data[0] !== 0x4d || data[1] !== 0x5a) fail(`${basename(path)} is not a PE executable`);
  const pe = data.readUInt32LE(0x3c);
  if (pe + 6 > data.length || data.toString("ascii", pe, pe + 4) !== "PE\0\0") {
    fail(`${basename(path)} has an invalid PE header`);
  }
  if (requireX64 && data.readUInt16LE(pe + 4) !== 0x8664) {
    fail(`${basename(path)} is not Windows x64`);
  }
}

function verifyElfX64(path) {
  const data = header(path);
  if (data[0] !== 0x7f || data.toString("ascii", 1, 4) !== "ELF") fail(`${basename(path)} is not ELF`);
  if (data[4] !== 2 || data[5] !== 1 || data.readUInt16LE(18) !== 62) {
    fail(`${basename(path)} is not a little-endian Linux x64 executable`);
  }
}

function verifyMsi(path) {
  const data = header(path, 8);
  const ole = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  if (!data.subarray(0, 8).equals(ole)) fail(`${basename(path)} is not an MSI/OLE file`);
}

function verifyDeb(path) {
  const data = header(path, 8);
  if (data.toString("ascii", 0, 8) !== "!<arch>\n") fail(`${basename(path)} is not a Debian package`);
}

function verifyApk(path) {
  const data = header(path, 4);
  const signature = data.subarray(0, 4).toString("hex");
  const zipSignatures = new Set(["504b0304", "504b0506", "504b0708"]);
  if (!zipSignatures.has(signature)) {
    fail(`${basename(path)} is not an APK/ZIP file`);
  }
}

function verifyPinnedApkSigner(apkPath) {
  const verifier = join(ROOT, "apps", "mobile", "verify-release-apk.ps1");
  if (!existsSync(verifier)) fail(`Android release verifier is missing: ${verifier}`);

  const isWindows = process.platform === "win32";
  const executable = isWindows ? "powershell.exe" : "pwsh";
  const args = ["-NoProfile", "-NonInteractive"];
  if (isWindows) args.push("-ExecutionPolicy", "Bypass");
  args.push(
    "-File",
    verifier,
    "-ApkPath",
    apkPath,
    "-ExpectedVersion",
    version(),
  );
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error) {
    fail(`unable to execute the pinned Android signer verifier: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`pinned Android signer verification failed with exit code ${result.status ?? "unknown"}`);
  }
}

function desktopNames(releaseVersion) {
  return {
    windows: [
      `hacash-wallet-desktop-v${releaseVersion}-x64-setup.exe`,
      `hacash-wallet-desktop-v${releaseVersion}-x64.msi`,
      `hacash-wallet-desktop-v${releaseVersion}-x64-portable.exe`,
    ],
    linux: [
      `hacash-wallet-desktop-v${releaseVersion}-x64.deb`,
      `hacash-wallet-desktop-v${releaseVersion}-x64.AppImage`,
      `hacash-wallet-desktop-v${releaseVersion}-x64-binary`,
    ],
  };
}

function verifyDesktopFile(path, name) {
  if (name.endsWith(".msi")) verifyMsi(path);
  else if (name.endsWith(".deb")) verifyDeb(path);
  else if (name.endsWith(".AppImage") || name.endsWith("-binary")) verifyElfX64(path);
  else verifyPe(path, !name.endsWith("-setup.exe"));
}

function stageDesktop(platform, outputDirectory) {
  const releaseVersion = version();
  const names = desktopNames(releaseVersion)[platform];
  if (!names) fail(`unsupported desktop platform ${platform}`);
  prepareOutput(outputDirectory);

  if (platform === "windows") {
    const setup = requireSingle(
      join(TARGET, "bundle", "nsis"),
      (path) => path.toLowerCase().endsWith("-setup.exe") && basename(path).includes(releaseVersion),
      "Windows NSIS installer",
    );
    const msi = requireSingle(
      join(TARGET, "bundle", "msi"),
      (path) => path.toLowerCase().endsWith(".msi") && basename(path).includes(releaseVersion),
      "Windows MSI installer",
    );
    const portable = join(TARGET, "hacash-wallet.exe");
    if (!existsSync(portable)) fail(`Windows portable executable is missing: ${portable}`);
    [setup, msi, portable].forEach((source, index) => copyExclusive(source, join(outputDirectory, names[index])));
  } else {
    const deb = requireSingle(
      join(TARGET, "bundle", "deb"),
      (path) => path.endsWith(".deb") && basename(path).includes(releaseVersion),
      "Linux deb package",
    );
    const appImage = requireSingle(
      join(TARGET, "bundle", "appimage"),
      (path) => path.endsWith(".AppImage") && basename(path).includes(releaseVersion),
      "Linux AppImage",
    );
    const binary = join(TARGET, "hacash-wallet");
    if (!existsSync(binary)) fail(`Linux raw executable is missing: ${binary}`);
    [deb, appImage, binary].forEach((source, index) => copyExclusive(source, join(outputDirectory, names[index])));
  }

  for (const name of names) verifyDesktopFile(join(outputDirectory, name), name);
  process.stdout.write(`Staged ${platform} desktop v${releaseVersion}: ${names.join(", ")}\n`);
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function requireExactFiles(directory, expected) {
  const actual = readdirSync(directory).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`unexpected artifact set in ${directory}; expected ${wanted.join(", ")}, found ${actual.join(", ")}`);
  }
}

function verifyDesktop(directory) {
  const releaseVersion = version();
  const namesByPlatform = desktopNames(releaseVersion);
  const names = [...namesByPlatform.windows, ...namesByPlatform.linux];
  requireExactFiles(directory, names);
  for (const name of names) verifyDesktopFile(join(directory, name), name);
  const sumsName = `SHA256SUMS-v${releaseVersion}-desktop.txt`;
  const sums = [...names].sort().map((name) => `${sha256(join(directory, name))}  ${name}`).join("\n") + "\n";
  writeFileSync(join(directory, sumsName), sums, { encoding: "ascii", flag: "wx" });
  process.stdout.write(`Verified complete desktop v${releaseVersion} artifact set and wrote ${sumsName}\n`);
}

function stageMobile(apkPath, outputDirectory) {
  const releaseVersion = version();
  prepareOutput(outputDirectory);
  verifyApk(apkPath);
  verifyPinnedApkSigner(apkPath);
  const apkName = `hacash-wallet-mobile-v${releaseVersion}-arm64.apk`;
  copyExclusive(apkPath, join(outputDirectory, apkName));
  const sumsName = `SHA256SUMS-v${releaseVersion}-mobile.txt`;
  writeFileSync(
    join(outputDirectory, sumsName),
    `${sha256(join(outputDirectory, apkName))}  ${apkName}\n`,
    { encoding: "ascii", flag: "wx" },
  );
  process.stdout.write(`Staged mobile v${releaseVersion}: ${apkName}\n`);
}

function verifyMobile(directory) {
  const releaseVersion = version();
  const apkName = `hacash-wallet-mobile-v${releaseVersion}-arm64.apk`;
  const sumsName = `SHA256SUMS-v${releaseVersion}-mobile.txt`;
  requireExactFiles(directory, [apkName, sumsName]);
  const apkPath = join(directory, apkName);
  verifyApk(apkPath);
  verifyPinnedApkSigner(apkPath);
  const expected = `${sha256(join(directory, apkName))}  ${apkName}\n`;
  if (readFileSync(join(directory, sumsName), "ascii").replace(/\r\n/g, "\n") !== expected) {
    fail(`${sumsName} does not match ${apkName}`);
  }
  process.stdout.write(`Verified complete mobile v${releaseVersion} artifact set\n`);
}

const [, , command, first, second] = process.argv;
try {
  if (command === "stage-desktop") {
    if (!first || !second) fail("usage: stage-desktop <windows|linux> <output-directory>");
    stageDesktop(first, resolve(second));
  } else if (command === "verify-desktop") {
    if (!first) fail("usage: verify-desktop <artifact-directory>");
    verifyDesktop(resolve(first));
  } else if (command === "stage-mobile") {
    if (!first || !second) fail("usage: stage-mobile <verified-apk> <output-directory>");
    stageMobile(resolve(first), resolve(second));
  } else if (command === "verify-mobile") {
    if (!first) fail("usage: verify-mobile <artifact-directory>");
    verifyMobile(resolve(first));
  } else {
    fail("usage: <stage-desktop|verify-desktop|stage-mobile|verify-mobile> ...");
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

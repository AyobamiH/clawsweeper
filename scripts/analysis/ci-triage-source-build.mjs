// Offline build-provenance verifier. Built-in Node modules only: never import
// application output before its bytes have been compared with a HEAD build.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sourceEnv = { PATH: process.env.PATH, HOME: process.env.HOME, GIT_OPTIONAL_LOCKS: "0" };
function refuse(reason) {
  throw new Error("source_build_" + reason);
}
function git(root, ...args) {
  return execFileSync("git", ["-C", root, ...args], {
    env: sourceEnv,
    encoding: "utf8",
    timeout: 10000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}
function cleanSha(root) {
  try {
    git(root, "diff", "--quiet", "HEAD", "--");
    const sha = git(root, "rev-parse", "HEAD");
    if (!/^[a-f0-9]{40}$/.test(sha)) refuse("source_sha");
    return sha;
  } catch {
    refuse("source_dirty");
  }
}
function ownedDirectory(path) {
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.mode & 0o022 ||
    (process.getuid && stat.uid !== process.getuid()) ||
    realpathSync(path) !== resolve(path)
  )
    refuse("toolchain_unsafe");
}
function outputHashes(dir) {
  const files = {};
  function walk(current) {
    for (const item of readdirSync(current, { withFileTypes: true })) {
      const absolute = join(current, item.name);
      if (item.isDirectory()) walk(absolute);
      else if (item.isFile() && item.name.endsWith(".js")) {
        const name = relative(dir, absolute).split(sep).join("/");
        files[name] = digest(readFileSync(absolute));
      } else if (item.isSymbolicLink()) refuse("output_symlink");
    }
  }
  walk(join(dir, "dist"));
  return Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)));
}

export function sourceBoundBuild(
  root,
  toolchainRoot = process.env.CLAWSWEEPER_CI_TRIAGE_TOOLCHAIN_ROOT || root,
  trustedNativeCompilerSha256 = process.env.CLAWSWEEPER_CI_TRIAGE_NATIVE_COMPILER_SHA256,
) {
  root = resolve(root);
  if (!isAbsolute(toolchainRoot)) refuse("toolchain_absolute");
  toolchainRoot = resolve(toolchainRoot);
  ownedDirectory(toolchainRoot);
  const nodeModules = join(toolchainRoot, "node_modules");
  ownedDirectory(nodeModules);
  const sha = cleanSha(root);
  const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const lock = readFileSync(join(root, "pnpm-lock.yaml"));
  const lockText = lock.toString("utf8");
  const match =
    /^      typescript:\s*\n        specifier: ([^\n]+)\n        version: ([0-9]+\.[0-9]+\.[0-9]+)/m.exec(
      lockText,
    );
  const packageVersion = JSON.parse(
    readFileSync(join(nodeModules, "typescript/package.json"), "utf8"),
  ).version;
  if (!match || manifest.devDependencies?.typescript !== match[1] || packageVersion !== match[2])
    refuse("toolchain_lock_mismatch");
  const tsPackage = realpathSync(join(nodeModules, "typescript"));
  const compiler = realpathSync(join(tsPackage, "bin/tsc"));
  const nativeName = "typescript-" + process.platform + "-" + process.arch;
  const nativeRoot = realpathSync(join(dirname(tsPackage), "@typescript", nativeName));
  const nativeVersion = JSON.parse(readFileSync(join(nativeRoot, "package.json"), "utf8")).version;
  if (nativeVersion !== packageVersion) refuse("native_toolchain_version");
  const nativeCompiler = realpathSync(
    join(nativeRoot, "lib", process.platform === "win32" ? "tsc.exe" : "tsc"),
  );
  const compilerHash = digest(readFileSync(compiler));
  const nativeCompilerHash = digest(readFileSync(nativeCompiler));
  // The expected digest belongs to the signed, external release/toolchain policy.
  // A digest measured from whichever binary is installed is NOT a trust anchor.
  // Refuse before invoking an untrusted native compiler or issuing an attestation.
  if (
    typeof trustedNativeCompilerSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(trustedNativeCompilerSha256) ||
    nativeCompilerHash !== trustedNativeCompilerSha256
  )
    refuse("native_toolchain_untrusted");
  const temp = mkdtempSync(join(tmpdir(), "clawsweeper-ci-triage-build-"));
  try {
    const archive = execFileSync("git", ["-C", root, "archive", "--format=tar", sha], {
      env: sourceEnv,
      timeout: 30000,
      maxBuffer: 64 * 1024 * 1024,
    });
    execFileSync("tar", ["-xf", "-", "-C", temp], {
      input: archive,
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    symlinkSync(nodeModules, join(temp, "node_modules"), "dir");
    // Execute the hashed native compiler directly, never an unchecked JS launcher/resolver.
    execFileSync(nativeCompiler, ["-p", "tsconfig.repair.json"], {
      cwd: temp,
      timeout: 120000,
      maxBuffer: 4 * 1024 * 1024,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: "production" },
    });
    if (cleanSha(root) !== sha) refuse("source_changed");
    const files = outputHashes(temp);
    return Object.freeze({
      sourceSha: sha,
      files,
      toolchain: Object.freeze({
        typescriptVersion: packageVersion,
        compilerSha256: compilerHash,
        nativeCompilerSha256: nativeCompilerHash,
        lockfileSha256: digest(lock),
        nodeVersion: process.version,
      }),
      buildDigest: digest(JSON.stringify(files)),
    });
  } catch (error) {
    if (error?.message?.startsWith("source_build_")) throw error;
    refuse("unavailable");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

export function assertBuildOutput(proof, root, runtimeFiles) {
  if (!runtimeFiles || typeof runtimeFiles !== "object" || Array.isArray(runtimeFiles))
    refuse("file_set");
  for (const [name, actual] of Object.entries(runtimeFiles)) {
    if (
      !/^dist\/[a-zA-Z0-9_./-]+\.js$/.test(name) ||
      name.includes("..") ||
      !/^[a-f0-9]{64}$/.test(actual) ||
      proof.files[name] !== actual
    ) {
      refuse("compiled_output_mismatch");
    }
  }
  if (!Object.keys(runtimeFiles).length) refuse("empty_runtime");
  if (cleanSha(resolve(root)) !== proof.sourceSha) refuse("source_changed");
  return Object.freeze({
    schema: "clawsweeper.ci-triage-build.v1",
    sourceSha: proof.sourceSha,
    runtimeFilesSha256: digest(
      JSON.stringify(
        Object.fromEntries(Object.entries(runtimeFiles).sort(([a], [b]) => a.localeCompare(b))),
      ),
    ),
    emittedFilesSha256: proof.buildDigest,
    toolchain: proof.toolchain,
  });
}

#!/usr/bin/env node
// Bind a clean, committed build to an owner-private activation manifest.
// This command grants no approval, changes no service and makes no network call.
import {
  constants,
  openSync,
  closeSync,
  fsyncSync,
  writeFileSync,
  lstatSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceBoundBuild, assertBuildOutput } from "./ci-triage-source-build.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const destination = process.argv[2];
try {
  if (!destination || !isAbsolute(destination) || process.argv.length !== 3)
    throw new Error("usage");
  const parent = dirname(destination);
  const stat = lstatSync(parent);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o077) !== 0 ||
    realpathSync(parent) !== resolve(parent) ||
    (process.getuid && stat.uid !== process.getuid())
  )
    throw new Error("private_parent_required");
  // Rebuild the exact committed source offline before importing any application code.
  const proof = sourceBoundBuild(root);
  // Imported helper uses Node built-ins only, and has no CLI side effects.
  // The source-bound rebuild above checks the signed source before this import;
  // compiled application modules are never imported by the manifest issuer.
  const { runtimeDigests } = await import("./ci-triage-preimport.mjs");
  const files = runtimeDigests(root);
  const sourceBuild = assertBuildOutput(proof, root, files);
  const sha = proof.sourceSha;
  // Every executed module must have a canonical tracked TypeScript source.
  for (const name of Object.keys(files)) {
    execFileSync(
      "/usr/bin/git",
      [
        "-c",
        "core.fsmonitor=false",
        "-C",
        root,
        "ls-files",
        "--error-unmatch",
        name.replace(/^dist\//, "src/").replace(/\.js$/, ".ts"),
      ],
      {
        stdio: "ignore",
        timeout: 5000,
        env: {
          PATH: "/usr/bin:/bin",
          HOME: "/nonexistent",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_ATTR_NOSYSTEM: "1",
          GIT_TERMINAL_PROMPT: "0",
          GIT_OPTIONAL_LOCKS: "0",
        },
      },
    );
  }
  const value = {
    schema: "clawsweeper.ci-triage-runtime.v3",
    implementationSha: sha,
    sourceBuild,
    createdAt: new Date().toISOString(),
    files,
    scope: "owner-local exact-build identity; not release approval",
  };
  const manifestBytes = JSON.stringify(value, null, 2) + "\n";
  const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  const fd = openSync(
    destination,
    constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
    0o600,
  );
  try {
    writeFileSync(fd, manifestBytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const dirfd = openSync(parent, constants.O_DIRECTORY | constants.O_RDONLY);
  try {
    fsyncSync(dirfd);
  } finally {
    closeSync(dirfd);
  }
  console.log(
    JSON.stringify({
      implementationSha: sha,
      runtimeFiles: Object.keys(files).length,
      emittedFilesSha256: sourceBuild.emittedFilesSha256,
      manifestCreated: true,
      runtimeManifestSha256: manifestSha256,
    }),
  );
} catch {
  console.error(
    "CI triage manifest refused: require a clean committed build, a new absolute destination and a private parent directory.",
  );
  process.exitCode = 1;
}

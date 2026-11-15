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
  readFileSync,
} from "node:fs";
import { dirname, isAbsolute, resolve, join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
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
  const verifierInputs = ["dist/repair/ci-triage-runtime.js", "dist/repair/ci-triage-evidence.js"];
  const verifiedInputs = Object.fromEntries(
    verifierInputs.map((name) => [
      name,
      createHash("sha256")
        .update(readFileSync(join(root, name)))
        .digest("hex"),
    ]),
  );
  assertBuildOutput(proof, root, verifiedInputs);
  const { runtimeDigests } = await import(
    pathToFileURL(join(root, "dist/repair/ci-triage-runtime.js")).href
  );
  const files = runtimeDigests(root);
  const sourceBuild = assertBuildOutput(proof, root, files);
  const sha = proof.sourceSha;
  // Every executed module must have a canonical tracked TypeScript source.
  for (const name of Object.keys(files)) {
    execFileSync(
      "git",
      [
        "-C",
        root,
        "ls-files",
        "--error-unmatch",
        name.replace(/^dist\//, "src/").replace(/\.js$/, ".ts"),
      ],
      { stdio: "ignore", timeout: 5000 },
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
  const fd = openSync(
    destination,
    constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
    0o600,
  );
  try {
    writeFileSync(fd, JSON.stringify(value, null, 2) + "\n");
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
    }),
  );
} catch {
  console.error(
    "CI triage manifest refused: require a clean committed build, a new absolute destination and a private parent directory.",
  );
  process.exitCode = 1;
}

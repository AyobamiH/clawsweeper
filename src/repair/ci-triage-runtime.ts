import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { CiEvidenceError, object } from "./ci-triage-evidence.js";

export const CI_TRIAGE_RUNTIME_FILES = [
  "dist/repair/ci-triage-runtime.js",
  "dist/repair/ci-triage-evidence.js",
  "dist/repair/ci-triage-ledger.js",
  "dist/repair/ci-triage.js",
  "dist/repair/notify-github-activity.js",
  "dist/repair/observe-ci-triage.js",
  "dist/repair/openclaw-hook.js",
] as const;

export function cleanImplementationSha(root: string): string {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    GIT_OPTIONAL_LOCKS: "0",
  };
  try {
    execFileSync(
      "git",
      ["-C", root, "diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--"],
      {
        env,
        stdio: "pipe",
        timeout: 5000,
      },
    );
    return execFileSync("git", ["-C", root, "rev-parse", "HEAD"], {
      env,
      encoding: "utf8",
      timeout: 5000,
    }).trim();
  } catch {
    throw new CiEvidenceError("implementation_source_unverified", true);
  }
}

export function runtimeDigests(root: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const name of CI_TRIAGE_RUNTIME_FILES) {
    const path = join(root, name);
    const info = lstatSync(path);
    if (
      !info.isFile() ||
      info.isSymbolicLink() ||
      info.size > 1024 * 1024 ||
      realpathSync(path) !== resolve(path)
    )
      throw new CiEvidenceError("implementation_runtime_unsafe", true);
    files[name] = createHash("sha256").update(readFileSync(path)).digest("hex");
  }
  return files;
}

export function verifiedImplementationSha(root: string, manifestPath: string | undefined): string {
  if (!manifestPath || !isAbsolute(manifestPath))
    throw new CiEvidenceError("implementation_manifest_required", true);
  try {
    const info = lstatSync(manifestPath);
    if (
      !info.isFile() ||
      info.isSymbolicLink() ||
      info.nlink !== 1 ||
      info.size > 16384 ||
      (info.mode & 0o077) !== 0 ||
      (process.getuid && info.uid !== process.getuid()) ||
      realpathSync(manifestPath) !== resolve(manifestPath)
    ) {
      throw new CiEvidenceError("implementation_manifest_unsafe", true);
    }
    const manifest = object(JSON.parse(readFileSync(manifestPath, "utf8")));
    const sha = cleanImplementationSha(root);
    const files = object(manifest?.files);
    if (
      !manifest ||
      manifest.schema !== "clawsweeper.ci-triage-runtime.v1" ||
      manifest.implementationSha !== sha ||
      !files ||
      Object.keys(files).sort().join() !== [...CI_TRIAGE_RUNTIME_FILES].sort().join()
    ) {
      throw new CiEvidenceError("implementation_manifest_mismatch", true);
    }
    const actual = runtimeDigests(root);
    if (CI_TRIAGE_RUNTIME_FILES.some((name) => actual[name] !== files[name])) {
      throw new CiEvidenceError("implementation_runtime_changed", true);
    }
    return sha;
  } catch (error) {
    if (error instanceof CiEvidenceError) throw error;
    throw new CiEvidenceError("implementation_manifest_unavailable", true);
  }
}

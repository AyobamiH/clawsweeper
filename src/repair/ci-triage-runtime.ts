import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isBuiltin } from "node:module";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { CiEvidenceError, object } from "./ci-triage-evidence.js";

// Entrypoints, not the full closure. Every local executable import is followed
// before a manifest is issued or checked. The accepted closure is source-derived.
export const CI_TRIAGE_RUNTIME_FILES = [
  "dist/repair/ci-triage-runtime.js",
  "dist/repair/ci-triage-evidence.js",
  "dist/repair/ci-triage-ledger.js",
  "dist/repair/ci-triage.js",
  "dist/repair/notify-github-activity.js",
  "dist/repair/observe-ci-triage.js",
  "dist/repair/openclaw-hook.js",
] as const;

const MAX_RUNTIME_MODULES = 96;
const MAX_RUNTIME_BYTES = 1024 * 1024;
const IMPORT_DECLARATION =
  /^\s*import\s+(?:(?:[A-Za-z0-9_$*{},\s]+)\s+from\s+)?["']([^"']+)["']\s*;\s*$/;
const EXPORT_FROM =
  /^\s*export\s+(?:\*|\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]*\})\s+from\s+["']([^"']+)["']\s*;\s*$/;

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

function staticImports(code: string): string[] {
  // Compiled NodeNext ESM is deliberately restricted to one-line literal static
  // imports/exports and builtin node: modules. Unparsed/dynamic module loading
  // cannot be silently declared protected. No application dependency is loaded
  // while parsing this closure.
  if (/\bimport(?:\s|\/\*[\s\S]{0,64}?\*\/)*\(/.test(code) || /\bcreateRequire\s*\(/.test(code)) {
    throw new CiEvidenceError("implementation_runtime_dynamic_import", true);
  }
  const specifiers: string[] = [];
  for (const line of code.split("\n")) {
    if (/^\s*import\s+/.test(line)) {
      const declaration = IMPORT_DECLARATION.exec(line);
      if (!declaration?.[1])
        throw new CiEvidenceError("implementation_runtime_import_unsupported", true);
      specifiers.push(declaration[1]);
    } else if (/^\s*export\s+(?:\*|\{)/.test(line)) {
      const declaration = EXPORT_FROM.exec(line);
      if (declaration?.[1]) {
        specifiers.push(declaration[1]);
      } else if (!/^\s*export\s+\{[^}]*\}\s*;\s*$/.test(line)) {
        // In particular, multiline re-exports must never evade closure discovery.
        throw new CiEvidenceError("implementation_runtime_import_unsupported", true);
      }
    }
  }
  return specifiers;
}

export function runtimeDigests(root: string): Record<string, string> {
  const base = resolve(root);
  const dist = join(base, "dist");
  const pending: string[] = [...CI_TRIAGE_RUNTIME_FILES];
  const visited = new Set<string>();
  const files: Record<string, string> = {};
  while (pending.length > 0) {
    const name = pending.pop();
    if (!name || visited.has(name)) continue;
    if (visited.size >= MAX_RUNTIME_MODULES) {
      throw new CiEvidenceError("implementation_runtime_closure_limit", true);
    }
    const absolute = resolve(base, name);
    if (!absolute.startsWith(dist + sep) || !name.endsWith(".js")) {
      throw new CiEvidenceError("implementation_runtime_import_unsafe", true);
    }
    const info = lstatSync(absolute);
    if (
      !info.isFile() ||
      info.isSymbolicLink() ||
      info.nlink !== 1 ||
      info.size > MAX_RUNTIME_BYTES ||
      realpathSync(absolute) !== absolute
    ) {
      throw new CiEvidenceError("implementation_runtime_unsafe", true);
    }
    const bytes = readFileSync(absolute);
    const imports = staticImports(bytes.toString("utf8"));
    files[name] = createHash("sha256").update(bytes).digest("hex");
    visited.add(name);
    for (const specifier of imports) {
      if (specifier.startsWith("node:") && isBuiltin(specifier)) continue;
      if (!/^\.\.?\//.test(specifier) || !specifier.endsWith(".js")) {
        throw new CiEvidenceError("implementation_runtime_package_unsupported", true);
      }
      const target = resolve(dirname(absolute), specifier);
      if (!target.startsWith(dist + sep)) {
        throw new CiEvidenceError("implementation_runtime_import_unsafe", true);
      }
      const next = relative(base, target).split(sep).join("/");
      if (!visited.has(next)) pending.push(next);
    }
  }
  return Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)));
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
    const actual = runtimeDigests(root);
    const names = Object.keys(actual).sort();
    const sourceBuild = object(manifest?.sourceBuild);
    const toolchain = object(sourceBuild?.toolchain);
    const runtimeFilesSha256 = createHash("sha256").update(JSON.stringify(actual)).digest("hex");
    if (
      !manifest ||
      manifest.schema !== "clawsweeper.ci-triage-runtime.v3" ||
      manifest.implementationSha !== sha ||
      !files ||
      Object.keys(files).sort().join() !== names.join()
    ) {
      throw new CiEvidenceError("implementation_manifest_mismatch", true);
    }
    if (names.some((name) => actual[name] !== files[name])) {
      throw new CiEvidenceError("implementation_runtime_changed", true);
    }
    if (
      sourceBuild?.schema !== "clawsweeper.ci-triage-build.v1" ||
      sourceBuild.sourceSha !== sha ||
      sourceBuild.runtimeFilesSha256 !== runtimeFilesSha256 ||
      typeof sourceBuild.emittedFilesSha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(sourceBuild.emittedFilesSha256) ||
      typeof toolchain?.typescriptVersion !== "string" ||
      !/^[a-f0-9]{64}$/.test(String(toolchain?.compilerSha256 ?? "")) ||
      !/^[a-f0-9]{64}$/.test(String(toolchain?.nativeCompilerSha256 ?? "")) ||
      !/^[a-f0-9]{64}$/.test(String(toolchain?.lockfileSha256 ?? ""))
    ) {
      throw new CiEvidenceError("implementation_build_provenance_invalid", true);
    }
    return sha;
  } catch (error) {
    if (error instanceof CiEvidenceError) throw error;
    throw new CiEvidenceError("implementation_manifest_unavailable", true);
  }
}

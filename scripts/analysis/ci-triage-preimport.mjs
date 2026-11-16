#!/usr/bin/env node
// Trusted release launcher must independently pin this builtins-only bootstrap
// and exact signed source. Verification runs BEFORE any application import.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isBuiltin, registerHooks } from "node:module";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const roots = [
  "ci-triage-runtime",
  "ci-triage-evidence",
  "ci-triage-ledger",
  "ci-triage",
  "notify-github-activity",
  "observe-ci-triage",
  "openclaw-hook",
].map((n) => "dist/repair/" + n + ".js");
function fail(reason) {
  throw new Error("preimport_" + reason);
}
const importRe = /^\s*import\s+(?:(?:[A-Za-z0-9_$*{},\s]+)\s+from\s+)?["']([^"']+)["']\s*;\s*$/;
const exportRe =
  /^\s*export\s+(?:\*|\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]*\})\s+from\s+["']([^"']+)["']\s*;\s*$/;

// Preserve all string contents while replacing comments with whitespace.
// This is a fail-closed guard: the original line grammar still parses imports.
function stripCommentsForImportGuard(code) {
  const out = [];
  let state = "code";
  let quote = "";
  let escaped = false;
  for (let i = 0; i < code.length; i++) {
    const ch = code[i],
      next = code[i + 1];
    if (state === "line") {
      if (ch === "\n" || ch === "\r") {
        out.push(ch);
        state = "code";
      } else out.push(" ");
      continue;
    }
    if (state === "block") {
      if (ch === "*" && next === "/") {
        out.push(" ", " ");
        i++;
        state = "code";
      } else out.push(ch === "\n" || ch === "\r" ? ch : " ");
      continue;
    }
    if (state === "string") {
      out.push(ch);
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) state = "code";
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      state = "string";
      out.push(ch);
      continue;
    }
    if (ch === "/" && next === "/") {
      out.push(" ", " ");
      i++;
      state = "line";
      continue;
    }
    if (ch === "/" && next === "*") {
      out.push(" ", " ");
      i++;
      state = "block";
      continue;
    }
    out.push(ch);
  }
  return out.join("");
}

function imports(code) {
  if (/\bimport(?:\s|\/\*[\s\S]{0,64}?\*\/)*\(/.test(code) || /\bcreateRequire\s*\(/.test(code))
    fail("dynamic_import");
  // Valid noncanonical static ESM (including import/*comment*/"./x.js"
  // and export*from"./x.js") must never escape the bounded closure parser.
  const scrubbed = stripCommentsForImportGuard(code);
  // Template interpolations contain executable code, but the comment scrubber
  // preserves their text. Reject comment-separated import tokens regardless
  // of comment length, even inside nested template interpolations.
  if (/\bimport\s+\/\*/.test(code)) fail("import");
  // Long valid comments cannot hide a dynamic module load from the guard.
  if (/\b(?:import|createRequire)\s*\(/.test(scrubbed)) fail("dynamic_import");
  // Any comment-masked import/re-export at the start of a visual line must
  // not disappear merely because the raw line begins with a comment.
  const visibleLines = scrubbed.split("\n");
  const rawLines = code.split("\n");
  for (let i = 0; i < visibleLines.length; i++) {
    const visible = visibleLines[i],
      raw = rawLines[i];
    if (
      (/^\s*import\s+/.test(visible) && !/^\s*import\s+/.test(raw)) ||
      (/^\s*export\s+(?:\*|\{)/.test(visible) && !/^\s*export\s+(?:\*|\{)/.test(raw))
    )
      fail("import");
  }
  if (
    /^\s*(?:import|export)\s*$/m.test(scrubbed) ||
    /\bimport(?=\/[/*]|["'{*])|\bexport(?=\/[/*]|[*{])/.test(scrubbed) ||
    /[;}][ \t]*(?:import[ \t]+(?:["'{*])|export[ \t]+(?:[*{]))/.test(scrubbed)
  )
    fail("import");
  const out = [];
  for (const line of code.split("\n")) {
    if (/^\s*import\s+/.test(line)) {
      const m = importRe.exec(line);
      if (!m?.[1]) {
        fail("import");
      }
      out.push(m[1]);
    } else if (/^\s*export\s+(?:\*|\{)/.test(line)) {
      const m = exportRe.exec(line);
      if (m?.[1]) out.push(m[1]);
      else if (!/^\s*export\s+\{[^}]*\}\s*;\s*$/.test(line)) fail("export");
    }
  }
  return out;
}
export function runtimeDigests(targetRoot = root) {
  const dist = join(targetRoot, "dist"),
    pending = [...roots],
    seen = new Set(),
    files = {};
  while (pending.length) {
    const name = pending.pop();
    if (seen.has(name)) continue;
    if (seen.size >= 96) fail("closure_limit");
    const full = resolve(targetRoot, name);
    if (!full.startsWith(dist + sep) || !name.endsWith(".js")) fail("path");
    const st = lstatSync(full);
    if (
      !st.isFile() ||
      st.isSymbolicLink() ||
      st.nlink !== 1 ||
      st.size > 1048576 ||
      realpathSync(full) !== full
    )
      fail("file");
    const data = readFileSync(full);
    files[name] = createHash("sha256").update(data).digest("hex");
    seen.add(name);
    for (const dep of imports(data.toString("utf8"))) {
      if (dep.startsWith("node:") && isBuiltin(dep)) continue;
      if (!/^\.\.?\//.test(dep) || !dep.endsWith(".js")) fail("package");
      const next = resolve(dirname(full), dep);
      if (!next.startsWith(dist + sep)) fail("traversal");
      const rel = relative(targetRoot, next).split(sep).join("/");
      if (!seen.has(rel)) pending.push(rel);
    }
  }
  return Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)));
}
function verify() {
  const sha = process.env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA;
  const pin = process.env.CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256;
  const manifestPath = process.env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST;
  const manifestPin = process.env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256;
  if (
    !/^[a-f0-9]{40}$/.test(sha ?? "") ||
    !/^[a-f0-9]{64}$/.test(pin ?? "") ||
    !/^[a-f0-9]{64}$/.test(manifestPin ?? "")
  )
    fail("pin_required");
  if (
    createHash("sha256")
      .update(readFileSync(fileURLToPath(import.meta.url)))
      .digest("hex") !== pin
  )
    fail("bootstrap_changed");
  if (!manifestPath || !isAbsolute(manifestPath)) fail("manifest_required");
  const st = lstatSync(manifestPath);
  if (
    !st.isFile() ||
    st.isSymbolicLink() ||
    st.nlink !== 1 ||
    st.size > 16384 ||
    st.mode & 0o077 ||
    realpathSync(manifestPath) !== resolve(manifestPath) ||
    (process.getuid && st.uid !== process.getuid())
  )
    fail("manifest_unsafe");
  // This immutable value must come from the separately signed release policy.
  // A self-consistent, rewritten manifest is NOT signed source-build provenance.
  const manifestBytes = readFileSync(manifestPath);
  if (createHash("sha256").update(manifestBytes).digest("hex") !== manifestPin)
    fail("manifest_changed");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  // Pre-import verification must not execute an attacker-controlled git from
  // PATH or invoke a repository-configured external diff/fsmonitor process.
  // This production path is Linux-only, with a trusted system Git executable.
  const gitBinary = "/usr/bin/git";
  const env = {
    PATH: "/usr/bin:/bin",
    HOME: "/nonexistent",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
  const gitPrefix = ["-c", "core.fsmonitor=false", "-C", root];
  execFileSync(
    gitBinary,
    [...gitPrefix, "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--"],
    { env, stdio: "pipe", timeout: 5000 },
  );
  const current = execFileSync(gitBinary, [...gitPrefix, "rev-parse", "HEAD"], {
    env,
    encoding: "utf8",
    timeout: 5000,
  }).trim();
  if (
    current !== sha ||
    manifest?.schema !== "clawsweeper.ci-triage-runtime.v3" ||
    manifest?.implementationSha !== sha
  )
    fail("source_mismatch");
  if (!manifest.files || typeof manifest.files !== "object" || Array.isArray(manifest.files))
    fail("files");
  const actual = runtimeDigests(),
    names = Object.keys(actual);
  const build = manifest.sourceBuild;
  if (
    build?.schema !== "clawsweeper.ci-triage-build.v1" ||
    build.sourceSha !== sha ||
    build.runtimeFilesSha256 !==
      createHash("sha256").update(JSON.stringify(actual)).digest("hex") ||
    !/^[a-f0-9]{64}$/.test(build.emittedFilesSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(build.toolchain?.compilerSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(build.toolchain?.nativeCompilerSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(build.toolchain?.lockfileSha256 ?? "")
  )
    fail("build_provenance");
  if (
    Object.keys(manifest.files).sort().join() !== names.join() ||
    names.some((n) => actual[n] !== manifest.files[n])
  )
    fail("runtime_changed");
  return actual;
}

// A second, runtime-enforced boundary: even if the static grammar misses an
// exotic executable import, Node may load ONLY the manifest's verified bytes.
// The synchronous loader supplies those exact bytes, avoiding verify/load races.
function installVerifiedLoadFence(files) {
  const allowed = new Map(
    Object.entries(files).map(([name, hash]) => [pathToFileURL(resolve(root, name)).href, hash]),
  );
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      if (resolved.url.startsWith("node:") && isBuiltin(resolved.url)) return resolved;
      if (!allowed.has(resolved.url)) fail("unlisted_module");
      return resolved;
    },
    load(url, context, nextLoad) {
      if (url.startsWith("node:") && isBuiltin(url)) return nextLoad(url, context);
      const expected = allowed.get(url);
      if (!expected) fail("unlisted_module");
      const filename = fileURLToPath(url);
      const st = lstatSync(filename);
      if (
        !st.isFile() ||
        st.isSymbolicLink() ||
        st.nlink !== 1 ||
        st.size > 1048576 ||
        realpathSync(filename) !== filename
      )
        fail("runtime_changed");
      const bytes = readFileSync(filename);
      if (createHash("sha256").update(bytes).digest("hex") !== expected) fail("runtime_changed");
      return { format: "module", source: bytes, shortCircuit: true };
    },
  });
}
async function run() {
  const mode = process.argv[2];
  if (mode !== "observer" && mode !== "notifier") fail("mode");
  const allowed = verify();
  installVerifiedLoadFence(allowed);
  // No application dependencies are imported until every check above passed.
  const path = join(
    root,
    "dist/repair",
    mode === "observer" ? "observe-ci-triage.js" : "notify-github-activity.js",
  );
  const app = await import(pathToFileURL(path).href);
  if (mode === "observer") await app.runCiTriageObserverCli(process.argv.slice(3));
  else await app.runCiTriageNotifierCli(process.argv.slice(3));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((e) => {
    const reason = /^preimport_[a-z_]+$/.test(e?.message ?? "")
      ? e.message
      : "preimport_unavailable";
    console.error(JSON.stringify({ state: "held", reason }));
    process.exitCode = 1;
  });
}

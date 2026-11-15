import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertBuildOutput,
  sourceBoundBuild,
} from "../../scripts/analysis/ci-triage-source-build.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const toolchain = process.env.CLAWSWEEPER_CI_TRIAGE_TOOLCHAIN_ROOT || project;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-source-build-test-"));
  const git = (...args) =>
    execFileSync("git", ["-C", root, ...args], {
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" },
      encoding: "utf8",
    }).trim();
  git("init", "-q");
  writeFileSync(join(root, ".gitignore"), "dist/\nnode_modules\n");
  mkdirSync(join(root, "src/repair"), { recursive: true });
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ type: "module", devDependencies: { typescript: "^7.0.2" } }),
  );
  writeFileSync(
    join(root, "pnpm-lock.yaml"),
    "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      typescript:\n        specifier: ^7.0.2\n        version: 7.0.2\n",
  );
  writeFileSync(
    join(root, "tsconfig.repair.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2024",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        rootDir: "src",
        outDir: "dist",
        strict: true,
        types: [],
      },
      include: ["src/repair/**/*.ts"],
    }),
  );
  writeFileSync(join(root, "src/repair/config.ts"), "export const value = 1;\n");
  writeFileSync(
    join(root, "src/repair/entry.ts"),
    'import { value } from "./config.js";\nexport { value };\n',
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "source-bound-fixture",
  );
  symlinkSync(join(toolchain, "node_modules"), join(root, "node_modules"), "dir");
  execFileSync(
    process.execPath,
    [resolve(toolchain, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.repair.json"],
    { cwd: root, timeout: 30000 },
  );
  return { root, git, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("offline reproducible compiler binds compiled JavaScript to exact committed source", () => {
  const f = fixture();
  try {
    const proof = sourceBoundBuild(f.root, toolchain);
    const runtimeFiles = Object.fromEntries(
      ["config", "entry"].map((name) => {
        const file = "dist/repair/" + name + ".js";
        return [file, hash(readFileSync(join(f.root, file)))];
      }),
    );
    const attestation = assertBuildOutput(proof, f.root, runtimeFiles);
    assert.equal(attestation.sourceSha, f.git("rev-parse", "HEAD"));
    assert.equal(attestation.toolchain.typescriptVersion, "7.0.2");
    assert.match(attestation.emittedFilesSha256, /^[a-f0-9]{64}$/);
    assert.match(attestation.runtimeFilesSha256, /^[a-f0-9]{64}$/);
    writeFileSync(
      join(f.root, "dist/repair/config.js"),
      "export const value = 'tampered but HEAD clean';\n",
    );
    const changed = {
      ...runtimeFiles,
      "dist/repair/config.js": hash(readFileSync(join(f.root, "dist/repair/config.js"))),
    };
    assert.equal(f.git("status", "--porcelain"), "");
    assert.throws(
      () => assertBuildOutput(proof, f.root, changed),
      /source_build_compiled_output_mismatch/,
    );
    const independentProof = sourceBoundBuild(f.root, toolchain);
    assert.throws(
      () => assertBuildOutput(independentProof, f.root, changed),
      /source_build_compiled_output_mismatch/,
    );
  } finally {
    f.cleanup();
  }
});

test("offline build rejects stale dist after clean HEAD changes and dirty tracked source", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.root, "src/repair/config.ts"), "export const value = 2;\n");
    assert.throws(() => sourceBoundBuild(f.root, toolchain), /source_build_source_dirty/);
    f.git("add", "src/repair/config.ts");
    f.git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-qm",
      "second-fixture-source",
    );
    const proof = sourceBoundBuild(f.root, toolchain);
    assert.throws(
      () =>
        assertBuildOutput(proof, f.root, {
          "dist/repair/config.js": hash(readFileSync(join(f.root, "dist/repair/config.js"))),
        }),
      /source_build_compiled_output_mismatch/,
    );
  } finally {
    f.cleanup();
  }
});

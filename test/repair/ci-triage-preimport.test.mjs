import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync, execFileSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { runtimeDigests } from "../../dist/repair/ci-triage-runtime.js";
import { runtimeDigests as bootstrapDigests } from "../../scripts/analysis/ci-triage-preimport.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "triage-preimport-"));
  const git = (...args) =>
    execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" },
    }).trim();
  git("init", "-q");
  writeFileSync(join(root, "tracked.txt"), "signed-source-fixture\n");
  git("add", "tracked.txt");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "fixture",
  );
  const source = git("rev-parse", "HEAD");
  writeFileSync(join(root, "package.json"), '{"type":"module"}\n');
  mkdirSync(join(root, "config"), { recursive: true });
  copyFileSync(
    join(project, "config/automation-limits.json"),
    join(root, "config/automation-limits.json"),
  );
  const original = runtimeDigests(project);
  for (const file of Object.keys(original)) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    copyFileSync(join(project, file), join(root, file));
  }
  const bootRel = "scripts/analysis/ci-triage-preimport.mjs";
  mkdirSync(dirname(join(root, bootRel)), { recursive: true });
  copyFileSync(join(project, bootRel), join(root, bootRel));
  const boot = join(root, bootRel);
  const pin = createHash("sha256").update(readFileSync(boot)).digest("hex");
  const privateDir = join(root, "private");
  mkdirSync(privateDir, { mode: 0o700 });
  const manifest = join(privateDir, "runtime.json");
  writeFileSync(
    manifest,
    JSON.stringify({
      schema: "clawsweeper.ci-triage-runtime.v3",
      implementationSha: source,
      files: runtimeDigests(root),
      sourceBuild: {
        schema: "clawsweeper.ci-triage-build.v1",
        sourceSha: source,
        runtimeFilesSha256: createHash("sha256")
          .update(JSON.stringify(runtimeDigests(root)))
          .digest("hex"),
        emittedFilesSha256: "a".repeat(64),
        toolchain: {
          typescriptVersion: "7.0.2",
          compilerSha256: "b".repeat(64),
          nativeCompilerSha256: "d".repeat(64),
          lockfileSha256: "c".repeat(64),
        },
      },
    }),
    { mode: 0o600 },
  );
  const env = {
    ...process.env,
    CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: source,
    CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256: pin,
    CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST: manifest,
    CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: createHash("sha256")
      .update(readFileSync(manifest))
      .digest("hex"),
  };
  const run = (mode = "observer", args = ["--help"], extra = {}) =>
    spawnSync(process.execPath, [boot, mode, ...args], {
      env: { ...env, ...extra },
      encoding: "utf8",
      timeout: 60000,
    });
  return {
    root,
    source,
    boot,
    manifest,
    env,
    run,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}
test("builtins-only bootstrap executes verified observer help", () => {
  const f = fixture();
  try {
    const out = f.run();
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /observe-ci-triage/);
  } finally {
    f.cleanup();
  }
});
test("preimport source verification never executes an inherited-PATH git shim", () => {
  const f = fixture();
  try {
    const bin = join(f.root, "untrusted-bin");
    mkdirSync(bin);
    const marker = join(f.root, "UNTRUSTED_GIT_SHIM_EXECUTED");
    const shim = join(bin, "git");
    writeFileSync(shim, "#!/bin/sh\nprintf unsafe > " + JSON.stringify(marker) + "\nexit 72\n");
    chmodSync(shim, 0o700);
    const hostilePath = bin + ":" + (process.env.PATH ?? "");
    const control = spawnSync("git", ["--version"], {
      env: { ...process.env, PATH: hostilePath },
      encoding: "utf8",
    });
    assert.equal(control.status, 72, control.stderr);
    assert.equal(existsSync(marker), true, "hostile shim must be a real executable");
    rmSync(marker);
    const out = f.run("observer", ["--help"], {
      PATH: hostilePath,
      GIT_CONFIG_GLOBAL: join(f.root, "untrusted-global-gitconfig"),
    });
    assert.equal(existsSync(marker), false, "git binary must be trusted, not PATH-resolved");
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /observe-ci-triage/);
  } finally {
    f.cleanup();
  }
});

test("tampered transitive ESM config refuses BEFORE import-time side effects", () => {
  const f = fixture();
  try {
    const marker = join(f.root, "MUST_NOT_RUN");
    appendFileSync(
      join(f.root, "dist/repair/config.js"),
      "\nimport {writeFileSync} from 'node:fs';\nwriteFileSync(" +
        JSON.stringify(marker) +
        ",'violated');\n",
    );
    const out = f.run();
    assert.notEqual(out.status, 0);
    assert.match(out.stderr, /preimport_(runtime_changed|build_provenance)/);
    assert.equal(existsSync(marker), false);
    const notifier = f.run("notifier", []);
    assert.notEqual(notifier.status, 0);
    assert.equal(existsSync(marker), false);
  } finally {
    f.cleanup();
  }
});
test("forged manifest cannot approve altered config.js even when Git HEAD is clean", () => {
  const f = fixture();
  try {
    const marker = join(f.root, "FORGED_MANIFEST_SIDE_EFFECT");
    appendFileSync(
      join(f.root, "dist/repair/config.js"),
      '\nimport {writeFileSync} from "node:fs";\nwriteFileSync(' +
        JSON.stringify(marker) +
        ', "violated");\n',
    );
    const manifest = JSON.parse(readFileSync(f.manifest, "utf8"));
    manifest.files = runtimeDigests(f.root);
    manifest.sourceBuild.runtimeFilesSha256 = createHash("sha256")
      .update(JSON.stringify(manifest.files))
      .digest("hex");
    // A forged self-consistent build receipt must not become its own trust root.
    writeFileSync(f.manifest, JSON.stringify(manifest), { mode: 0o600 });
    const out = f.run();
    assert.notEqual(out.status, 0);
    assert.match(out.stderr, /preimport_manifest_changed/);
    assert.equal(existsSync(marker), false);
  } finally {
    f.cleanup();
  }
});

test("missing manifest, invalid bootstrap pin, mismatched signed source all refuse before application load", () => {
  const f = fixture();
  try {
    const cases = [
      { CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST: "/not/found" },
      { CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256: "0".repeat(64) },
      { CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: "0".repeat(40) },
      { CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: "" },
    ];
    for (const override of cases) {
      const out = f.run("observer", ["--help"], override);
      assert.notEqual(out.status, 0);
      assert.match(out.stderr, /preimport_/);
    }
  } finally {
    f.cleanup();
  }
});

test("both closure scanners reject valid but unparsed static ESM import forms", () => {
  const f = fixture();
  try {
    const target = join(f.root, "dist/repair/observe-ci-triage.js");
    const original = readFileSync(target, "utf8");
    writeFileSync(join(f.root, "dist/repair/unlisted.js"), "globalThis.unlistedExecuted=true;\n");
    const cases = [
      'import/*gap*/"./unlisted.js";',
      'import"./unlisted.js";',
      'export*from"./unlisted.js";',
      'import\n"./unlisted.js";',
      'export\n*from"./unlisted.js";',
      'const x=1;import "./unlisted.js";',
      'const x=1;export * from "./unlisted.js";',
      'const x=1; /* gap */ import "./unlisted.js";',
      'const x=1; /* gap */ export * from "./unlisted.js";',
      '/* gap */ import "./unlisted.js";',
      'const x=1;\n/* gap */import "./unlisted.js";',
    ];
    for (const statement of cases) {
      writeFileSync(target, original + "\n" + statement + "\n");
      assert.throws(
        () => runtimeDigests(f.root),
        /implementation_runtime_import_unsupported/,
        statement,
      );
      assert.throws(() => bootstrapDigests(f.root), /preimport_import/, statement);
    }
  } finally {
    f.cleanup();
  }
});

test("long-comment dynamic imports are rejected by both runtime scanners", () => {
  const f = fixture();
  try {
    const target = join(f.root, "dist/repair/observe-ci-triage.js");
    appendFileSync(target, "\nawait import/*" + "x".repeat(128) + '*/("./unlisted.js");\n');
    assert.throws(() => runtimeDigests(f.root), /implementation_runtime_dynamic_import/);
    assert.throws(() => bootstrapDigests(f.root), /preimport_dynamic_import/);
  } finally {
    f.cleanup();
  }
});

test("template interpolation refuses hidden long-comment dynamic imports", () => {
  const f = fixture();
  try {
    const target = join(f.root, "dist/repair/observe-ci-triage.js");
    appendFileSync(
      target,
      "\nconst report = `${import /*" + "x".repeat(128) + '*/("./unlisted.js")}`;\n',
    );
    // Prove the hidden dynamic import is valid Node ESM, not a malformed fixture.
    const parsed = spawnSync(process.execPath, ["--check", target], { encoding: "utf8" });
    assert.equal(parsed.status, 0, parsed.stderr);
    assert.throws(() => runtimeDigests(f.root), /implementation_runtime_import_unsupported/);
    assert.throws(() => bootstrapDigests(f.root), /preimport_import/);
  } finally {
    f.cleanup();
  }
});

test("verified synchronous module fence refuses unlisted imports even when static parsing misses eval-built syntax", () => {
  const f = fixture();
  try {
    const target = join(f.root, "dist/repair/observe-ci-triage.js");
    const marker = join(f.root, "UNLISTED_MODULE_EXECUTED");
    writeFileSync(
      join(f.root, "dist/repair/unlisted.js"),
      'import { writeFileSync } from "node:fs";\nwriteFileSync(' +
        JSON.stringify(marker) +
        ', "unsafe");\n',
    );
    // Runtime-only import assembled from two strings: not a static import
    // declaration and deliberately invisible to the bounded closure parser.
    appendFileSync(target, '\nawait eval("im" + "port(\\"./unlisted.js\\")");\n');
    const hashes = runtimeDigests(f.root);
    assert.equal(hashes["dist/repair/unlisted.js"], undefined);
    const manifest = JSON.parse(readFileSync(f.manifest, "utf8"));
    manifest.files = hashes;
    manifest.sourceBuild.runtimeFilesSha256 = createHash("sha256")
      .update(JSON.stringify(hashes))
      .digest("hex");
    writeFileSync(f.manifest, JSON.stringify(manifest), { mode: 0o600 });

    // Synthetic trusted-fixture manifest only: re-pin to reach the later
    // module fence. Production pins must come from the signed release.
    const result = f.run("observer", ["--help"], {
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: createHash("sha256")
        .update(readFileSync(f.manifest))
        .digest("hex"),
    });
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /preimport_unlisted_module/);
    assert.equal(existsSync(marker), false, "unlisted module must not execute");
  } finally {
    f.cleanup();
  }
});

test("verified module fence refuses alias-created CommonJS loads outside the manifest", () => {
  const f = fixture();
  try {
    const target = join(f.root, "dist/repair/observe-ci-triage.js");
    const marker = join(f.root, "UNLISTED_CJS_EXECUTED");
    writeFileSync(
      join(f.root, "dist/repair/unlisted.cjs"),
      'require("node:fs").writeFileSync(' + JSON.stringify(marker) + ', "unsafe");\n',
    );
    appendFileSync(
      target,
      '\nconst nativeModule = process.getBuiltinModule("node:module");\n' +
        "const makeRequire = nativeModule.createRequire;\n" +
        'makeRequire(import.meta.url)("./unlisted.cjs");\n',
    );
    const hashes = runtimeDigests(f.root);
    const manifest = JSON.parse(readFileSync(f.manifest, "utf8"));
    manifest.files = hashes;
    manifest.sourceBuild.runtimeFilesSha256 = createHash("sha256")
      .update(JSON.stringify(hashes))
      .digest("hex");
    writeFileSync(f.manifest, JSON.stringify(manifest), { mode: 0o600 });
    // Synthetic trusted-fixture manifest only: re-pin to reach the later
    // module fence. Production pins must come from the signed release.
    const result = f.run("observer", ["--help"], {
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: createHash("sha256")
        .update(readFileSync(f.manifest))
        .digest("hex"),
    });
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /preimport_unlisted_module/);
    assert.equal(existsSync(marker), false, "unlisted CommonJS module must not execute");
  } finally {
    f.cleanup();
  }
});

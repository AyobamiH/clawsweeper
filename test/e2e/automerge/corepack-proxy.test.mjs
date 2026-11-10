import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { seedHermeticE2EPnpm, runE2ECorepackProxy } from "./corepack-proxy.mjs";

function fixture(t) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-e2e-proxy-test-"));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-target-user-"));
  t.after(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
    fs.rmSync(profile, { recursive: true, force: true });
  });
  const sourceRoot = path.join(scratch, "trusted-pnpm");
  for (const version of ["11.10.0", "11.2.2"]) {
    const dir = path.join(sourceRoot, version);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, ".corepack"), JSON.stringify({ name: "pnpm", version }));
    fs.writeFileSync(path.join(dir, "actual-bits"), "static-content-" + version);
  }
  return { scratch, sourceRoot, home: path.join(profile, "corepack") };
}

test("fixture-only cache seed supplies exact approved pnpm versions", (t) => {
  const f = fixture(t);
  const env = { COREPACK_HOME: f.home };
  assert.equal(
    seedHermeticE2EPnpm(["prepare", "pnpm@11.10.0", "--activate"], env, f.sourceRoot),
    true,
  );
  assert.equal(
    fs.readFileSync(path.join(f.home, "v1/pnpm/11.10.0/actual-bits"), "utf8"),
    "static-content-11.10.0",
  );
  assert.equal(
    seedHermeticE2EPnpm(["prepare", "pnpm@11.2.2+sha512." + "a".repeat(128)], env, f.sourceRoot),
    true,
  );
  assert.equal(
    fs.readFileSync(path.join(f.home, "v1/pnpm/11.2.2/actual-bits"), "utf8"),
    "static-content-11.2.2",
  );
});

test("no seed for unapproved versions, commands or non-disposable targets", (t) => {
  const f = fixture(t);
  const env = { COREPACK_HOME: f.home };
  assert.equal(seedHermeticE2EPnpm(["prepare", "pnpm@11.2.3"], env, f.sourceRoot), false);
  assert.equal(seedHermeticE2EPnpm(["prepare", "yarn@4.0.0"], env, f.sourceRoot), false);
  assert.equal(seedHermeticE2EPnpm(["enable", "pnpm"], env, f.sourceRoot), false);
  assert.equal(
    seedHermeticE2EPnpm(
      ["prepare", "pnpm@11.10.0"],
      { COREPACK_HOME: "/home/user/.cache/corepack" },
      f.sourceRoot,
    ),
    false,
  );
  assert.equal(fs.existsSync(path.join(f.home, "v1")), false);
});

test("missing or symlinked pinned cache fails closed and never escapes target", (t) => {
  const f = fixture(t);
  const env = { COREPACK_HOME: f.home };
  assert.equal(
    seedHermeticE2EPnpm(["prepare", "pnpm@11.10.0"], env, path.join(f.scratch, "missing")),
    false,
  );
  fs.rmSync(path.join(f.sourceRoot, "11.10.0"), { recursive: true });
  fs.symlinkSync(path.join(f.sourceRoot, "11.2.2"), path.join(f.sourceRoot, "11.10.0"));
  assert.throws(
    () => seedHermeticE2EPnpm(["prepare", "pnpm@11.10.0"], env, f.sourceRoot),
    /unsafe E2E Corepack source/,
  );
});

test("delegated Corepack must run with network disabled after verified seed", (t) => {
  const f = fixture(t);
  const executable = path.join(f.scratch, "fake-corepack.sh");
  fs.writeFileSync(
    executable,
    '#!/bin/sh\ntest "$COREPACK_ENABLE_NETWORK" = 0 || exit 44\ntest "$COREPACK_HOME" != "" || exit 45\ntest "$1" = prepare || exit 46\n',
  );
  fs.chmodSync(executable, 0o700);
  assert.equal(
    runE2ECorepackProxy(
      ["prepare", "pnpm@11.10.0", "--activate"],
      {
        COREPACK_HOME: f.home,
        CLAWSWEEPER_E2E_REAL_COREPACK: executable,
      },
      f.sourceRoot,
    ),
    0,
  );
});

test("hermetic E2E refuses unseeded package managers before delegation", (t) => {
  const f = fixture(t);
  const fake = path.join(f.scratch, "should-not-run.sh");
  fs.writeFileSync(fake, "#!/bin/sh\necho unexpectedly delegated >&2;exit 99\n");
  fs.chmodSync(fake, 0o700);
  assert.throws(
    () =>
      runE2ECorepackProxy(
        ["prepare", "pnpm@11.10.0", "--activate"],
        {
          COREPACK_HOME: f.home,
          CLAWSWEEPER_E2E_REAL_COREPACK: fake,
          CLAWSWEEPER_E2E_REQUIRE_OFFLINE_COREPACK: "1",
        },
        path.join(f.scratch, "missing"),
      ),
    /pinned E2E Corepack seed unavailable/,
  );
});

test("symlinked Corepack entrypoint delegates both CLI commands", (t) => {
  const f = fixture(t);
  const entrypoint = path.join(f.scratch, "corepack");
  fs.symlinkSync(fileURLToPath(new URL("./corepack-proxy.mjs", import.meta.url)), entrypoint);
  const marker = path.join(f.scratch, "delegated-arguments");
  const fake = path.join(f.scratch, "record-corepack.sh");
  fs.writeFileSync(fake, '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CLAWSWEEPER_TEST_DELEGATED_PATH"\n');
  fs.chmodSync(fake, 0o700);
  for (const args of [
    ["enable", "--install-directory", path.join(f.home, "bin"), "pnpm"],
    ["prepare", "pnpm@11.10.0", "--activate"],
  ]) {
    const result = spawnSync(process.execPath, [entrypoint, ...args], {
      encoding: "utf8",
      env: {
        ...process.env,
        COREPACK_HOME: f.home,
        CLAWSWEEPER_E2E_REAL_COREPACK: fake,
        CLAWSWEEPER_TEST_DELEGATED_PATH: marker,
      },
    });
    assert.equal(result.status, 0, result.stderr);
  }
  assert.equal(
    fs.readFileSync(marker, "utf8"),
    "enable --install-directory " +
      path.join(f.home, "bin") +
      " pnpm\nprepare pnpm@11.10.0 --activate\n",
  );
});

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runE2ECorepackProxy } from "./corepack-proxy.mjs";

function fixture(t) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-offline-proof-"));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-target-user-"));
  t.after(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
    fs.rmSync(profile, { recursive: true, force: true });
  });
  const fake = path.join(scratch, "corepack-stub.sh");
  const marker = path.join(scratch, "delegated.log");
  fs.writeFileSync(
    fake,
    '#!/bin/sh\nprintf "%s|%s\\n" "$COREPACK_ENABLE_NETWORK" "$*" >> "$CSW_MARKER"\nexit 0\n',
  );
  fs.chmodSync(fake, 0o700);
  return {
    scratch,
    marker,
    env: {
      COREPACK_HOME: path.join(profile, "corepack"),
      CLAWSWEEPER_E2E_REAL_COREPACK: fake,
      CLAWSWEEPER_E2E_REQUIRE_OFFLINE_COREPACK: "1",
      CSW_MARKER: marker,
    },
  };
}

test("hermetic image refuses unsupported Yarn prepare before delegation", (t) => {
  const f = fixture(t);
  assert.throws(
    () =>
      runE2ECorepackProxy(
        ["prepare", "yarn@4.0.0", "--activate"],
        f.env,
        path.join(f.scratch, "missing"),
      ),
    /pinned E2E Corepack seed unavailable/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

test("hermetic image refuses enable yarn before delegation", (t) => {
  const f = fixture(t);
  assert.throws(
    () => runE2ECorepackProxy(["enable", "yarn"], f.env, path.join(f.scratch, "missing")),
    /unsupported hermetic E2E Corepack command/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

test("hermetic enable pnpm delegates with network disabled", (t) => {
  const f = fixture(t);
  assert.equal(runE2ECorepackProxy(["enable", "pnpm"], f.env, path.join(f.scratch, "missing")), 0);
  assert.equal(fs.readFileSync(f.marker, "utf8"), "0|enable pnpm\n");
});

test("hermetic pin refuses unsupported pnpm versions", (t) => {
  const f = fixture(t);
  assert.throws(
    () => runE2ECorepackProxy(["prepare", "pnpm@999.0.0"], f.env, path.join(f.scratch, "missing")),
    /pinned E2E Corepack seed unavailable/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

test("hermetic pin allows seeded, genuine pnpm prepare without network", (t) => {
  const f = fixture(t);
  const sourceRoot = path.join(f.scratch, "trusted-cache");
  const source = path.join(sourceRoot, "11.10.0");
  fs.mkdirSync(source, { recursive: true });
  fs.writeFileSync(
    path.join(source, ".corepack"),
    JSON.stringify({ name: "pnpm", version: "11.10.0" }),
  );
  assert.equal(
    runE2ECorepackProxy(["prepare", "pnpm@11.10.0", "--activate"], f.env, sourceRoot),
    0,
  );
  assert.equal(fs.readFileSync(f.marker, "utf8"), "0|prepare pnpm@11.10.0 --activate\n");
});

test("hermetic enable rejects an arbitrary install destination", (t) => {
  const f = fixture(t);
  assert.throws(
    () =>
      runE2ECorepackProxy(
        ["enable", "--install-directory", "/etc/corepack", "pnpm"],
        f.env,
        path.join(f.scratch, "missing"),
      ),
    /unsupported hermetic E2E Corepack command/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

test("hermetic prepare rejects unreviewed flags before delegation", (t) => {
  const f = fixture(t);
  const sourceRoot = path.join(f.scratch, "trusted-cache");
  const seed = path.join(sourceRoot, "11.10.0");
  fs.mkdirSync(seed, { recursive: true });
  fs.writeFileSync(
    path.join(seed, ".corepack"),
    JSON.stringify({ name: "pnpm", version: "11.10.0" }),
  );
  assert.throws(
    () =>
      runE2ECorepackProxy(
        ["prepare", "pnpm@11.10.0", "--activate", "--unreviewed-flag"],
        f.env,
        sourceRoot,
      ),
    /pinned E2E Corepack seed unavailable/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

test("hermetic enable rejects non-disposable Corepack homes", (t) => {
  const f = fixture(t);
  assert.throws(
    () =>
      runE2ECorepackProxy(
        ["enable", "pnpm"],
        { ...f.env, COREPACK_HOME: "/etc/corepack" },
        path.join(f.scratch, "missing"),
      ),
    /hermetic E2E Corepack requires disposable target home/,
  );
  assert.equal(fs.existsSync(f.marker), false);
});

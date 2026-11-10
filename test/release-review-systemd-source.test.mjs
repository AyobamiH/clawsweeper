import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  sourceBundle,
  assertLiveReleaseReviewBudget,
} from "../scripts/commercial/source-review.mjs";

function git(root, ...args) {
  return execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
    },
  }).trim();
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-review-units-"));
  git(root, "init", "-q");
  git(
    root,
    "config",
    "--local",
    "remote.origin.url",
    "https://github.com/AyobamiH/clawsweeper.git",
  );
  git(root, "config", "--local", "user.name", "Isolated Reviewer Fixture");
  git(root, "config", "--local", "user.email", "review-fixture@example.invalid");
  git(root, "config", "--local", "commit.gpgsign", "false");
  fs.mkdirSync(path.join(root, "scripts", "ci"), { recursive: true });
  const service = "scripts/ci/clawsweeper-selfhosted.service";
  const timer = "scripts/ci/clawsweeper-selfhosted.timer";
  fs.writeFileSync(path.join(root, service), "[Service]\nExecStart=/usr/bin/true\n");
  fs.writeFileSync(path.join(root, timer), "[Timer]\nOnCalendar=hourly\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "fixture baseline");
  const base = git(root, "rev-parse", "HEAD");
  fs.writeFileSync(path.join(root, service), "[Service]\nExecStart=/usr/bin/false\n");
  fs.writeFileSync(path.join(root, timer), "[Timer]\nOnCalendar=*:0/5\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "change systemd deployment authority");
  return { root, base, service, timer };
}

test("bounded release source review includes exact changed systemd service and timer bytes", async (t) => {
  const { root, base, service, timer } = fixture();
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const bundle = await sourceBundle(root, base, false);
  assert.equal(bundle.files.length, 2);
  assert.deepEqual(
    bundle.files.map((f) => f.path),
    [service, timer],
  );
  assert.match(bundle.files[0].before, /ExecStart=\/usr\/bin\/true/);
  assert.match(bundle.files[0].after, /ExecStart=\/usr\/bin\/false/);
  assert.match(bundle.files[1].after, /OnCalendar=\*:0\/5/);
  assert.equal(bundle.head, git(root, "rev-parse", "HEAD"));
  // Making previously refused files reviewable must not permit spending model
  // inference without the existing fixed eight-call approval boundary.
  assert.throws(
    () => assertLiveReleaseReviewBudget(bundle, {}),
    (e) => e.code === "preflight_refused" && e.phase === "inference_budget",
  );
});

test("systemd extension approval never permits untracked credential or binary data", async (t) => {
  const { root, base } = fixture();
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.writeFileSync(path.join(root, "auth.json"), '{"privateKey":"no"}\n');
  await assert.rejects(() => sourceBundle(root, base, true), /unsupported source review path/);
  fs.rmSync(path.join(root, "auth.json"));
  fs.writeFileSync(path.join(root, "secrets.service"), "Environment=PASSWORD=value\n");
  // A suffix alone never licenses a clearly sensitive path.
  await assert.rejects(() => sourceBundle(root, base, true), /unsupported source review path/);
});

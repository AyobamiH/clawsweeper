import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { ownerGithubRead, runObservationLoop } from "../../dist/repair/observe-ci-triage.js";
import { CiEvidenceError } from "../../dist/repair/ci-triage-evidence.js";

function fakeGithub(root: string, denied: boolean) {
  const counter = join(root, "calls.txt");
  const executable = join(root, "gh");
  writeFileSync(
    executable,
    `#!/usr/bin/env node
const fs=require('node:fs');
const counter=${JSON.stringify(counter)};
const count=fs.existsSync(counter)?Number(fs.readFileSync(counter,'utf8'))+1:1;
fs.writeFileSync(counter,String(count));
if(process.env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN) { process.stderr.write('private hook token leaked'); process.exit(9); }
if(${denied} || count===1) {
 process.stderr.write(${JSON.stringify(denied ? "HTTP 401: unauthorised" : "dial tcp: network is unreachable")});
 process.exit(1);
}
process.stdout.write(JSON.stringify({workflow_runs:[],total_count:0}));
`,
  );
  chmodSync(executable, 0o755);
  return counter;
}

test("owned GitHub GET safely retries one transport failure without leaking hook credentials", async () => {
  const root = mkdtempSync(join(tmpdir(), "ci-owner-get-"));
  try {
    const counter = fakeGithub(root, false);
    const read = ownerGithubRead({
      ...process.env,
      PATH: `${root}${delimiter}${process.env.PATH}`,
      CLAWSWEEPER_OPENCLAW_HOOK_TOKEN: "never-forward-this",
    });
    assert.deepEqual(
      await read("repos/ayobamih/clawsweeper/actions/runs?status=completed&per_page=100"),
      { workflow_runs: [], total_count: 0 },
    );
    assert.equal(readFileSync(counter, "utf8"), "2");
    await assert.rejects(() => read("https://untrusted.invalid/steal"), /unsafe_github_endpoint/);
    assert.equal(readFileSync(counter, "utf8"), "2");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("authentication refusals are not blindly retried", async () => {
  const root = mkdtempSync(join(tmpdir(), "ci-owner-denial-"));
  try {
    const counter = fakeGithub(root, true);
    const read = ownerGithubRead({
      ...process.env,
      PATH: `${root}${delimiter}${process.env.PATH}`,
    });
    await assert.rejects(
      () => read("repos/ayobamih/clawsweeper/actions/runs/123"),
      /github_owner_auth_refused/,
    );
    assert.equal(readFileSync(counter, "utf8"), "1");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("timed observation resumes after a held read cycle and reports the recovery", async () => {
  let now = 0;
  let calls = 0;
  const emitted: Record<string, unknown>[] = [];
  const summary = await runObservationLoop({
    durationMs: 30,
    intervalMs: 10,
    clock: () => now,
    delay: async (ms) => {
      now += ms;
    },
    emit: (value) => emitted.push(value),
    observe: async () => {
      if (++calls === 1) throw new CiEvidenceError("github_owner_read_unavailable");
      return { state: "observed", modelInvocations: 0 };
    },
  });
  assert.deepEqual(summary, { cycles: 3, heldReadCycles: 1, endedWithReadFailure: false });
  assert.equal(emitted[0]!.state, "held");
  assert.equal(emitted[1]!.state, "observed");
});

test("unresolved reads are not success, and source-integrity faults stop immediately", async () => {
  const summary = await runObservationLoop({
    durationMs: 0,
    intervalMs: 10,
    emit: () => {},
    observe: async () => {
      throw new CiEvidenceError("github_owner_read_unavailable");
    },
  });
  assert.equal(summary.endedWithReadFailure, true);
  let calls = 0;
  await assert.rejects(
    () =>
      runObservationLoop({
        durationMs: 100,
        intervalMs: 10,
        emit: () => {},
        observe: async () => {
          calls++;
          throw new CiEvidenceError("implementation_runtime_changed", true);
        },
      }),
    /implementation_runtime_changed/,
  );
  assert.equal(calls, 1);
});

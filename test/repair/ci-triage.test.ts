import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { CiTriageLedger } from "../../dist/repair/ci-triage-ledger.js";
import {
  CiEvidenceError,
  readCiEvidence,
  decisionId,
} from "../../dist/repair/ci-triage-evidence.js";
import { runGithubActivityNotifier } from "../../dist/repair/notify-github-activity.js";

const SOURCE = "a".repeat(40);
const IMPL = "b".repeat(40);
const REPO = "ayobamih/clawsweeper";
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-"));
  const state = join(root, "state");
  mkdirSync(state, { mode: 0o700 });
  const identity = { repository: REPO, runId: 1234, runAttempt: 1, sourceSha: SOURCE };
  const run: Record<string, unknown> = {
    id: 1234,
    run_number: 98,
    run_attempt: 1,
    head_sha: SOURCE,
    status: "completed",
    conclusion: "failure",
    name: "CI",
    repository: { full_name: REPO },
  };
  const job: Record<string, unknown> = {
    id: 2001,
    run_id: 1234,
    run_attempt: 1,
    head_sha: SOURCE,
    status: "completed",
    conclusion: "failure",
    runner_name: "",
    runner_id: 0,
    steps: [],
  };
  let jobs: unknown[] = [job];
  let count = 1;
  let hooks = 0;
  let ghReads = 0;
  const input = join(root, "event.json");
  const env: NodeJS.ProcessEnv = {
    CLAWSWEEPER_CI_TRIAGE_ENABLED: "1",
    CLAWSWEEPER_CI_TRIAGE_STATE_DIR: state,
    CLAWSWEEPER_CI_TRIAGE_REPOSITORIES: REPO,
    CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: IMPL,
    CLAWSWEEPER_OPENCLAW_HOOK_URL: "http://127.0.0.1:1/hooks/agent",
    CLAWSWEEPER_OPENCLAW_HOOK_TOKEN: "fixture-private-token",
    CLAWSWEEPER_DISCORD_TARGET: "fixture-channel",
    GH_TOKEN: "fixture-github-token",
  };
  const read = async (endpoint: string): Promise<unknown> => {
    ghReads++;
    return structuredClone(endpoint.includes("/jobs?") ? { total_count: count, jobs } : run);
  };
  const fetcher: typeof fetch = async (_url, init) => {
    hooks++;
    assert.equal(init?.method, "POST");
    const data = JSON.parse(String(init?.body));
    assert.equal(data.deliver, false);
    assert.equal(
      data.idempotencyKey,
      `ci-triage:${decisionId({ ...identity, runAttempt: Number(run.run_attempt) })}`,
    );
    return new Response(JSON.stringify({ runId: "accepted-agent-1" }), { status: 200 });
  };
  const runtime = {
    root,
    env,
    fetch: fetcher,
    log: () => {},
    ciTriage: { readGithub: read, implementationRevision: () => IMPL, clock: () => Date.now() },
  };
  const execute = () => {
    writeFileSync(
      input,
      JSON.stringify({ action: "completed", repository: { full_name: REPO }, workflow_run: run }),
    );
    return runGithubActivityNotifier(["--input", input, "--event", "workflow_run"], runtime);
  };
  return {
    root,
    state,
    identity,
    run,
    job,
    env,
    runtime,
    execute,
    setJobs: (value: unknown[], total = value.length) => {
      jobs = value;
      count = total;
    },
    hooks: () => hooks,
    reads: () => ghReads,
    receipts: () => {
      const ledger = new CiTriageLedger(state);
      try {
        return ledger.receipts();
      } finally {
        ledger.close();
      }
    },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("normal notifier resolves authentic no-step failures before any hook/model", async () => {
  const f = fixture();
  try {
    delete f.env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN;
    const result = await f.execute();
    assert.equal(result.exitCode, 0);
    assert.equal(result.reason, "ci_triage_no_runner_no_steps");
    assert.equal(f.hooks(), 0);
    assert.ok(f.reads() >= 2);
    const receipt = f.receipts()[0]!;
    assert.equal(receipt.route, "deterministic");
    assert.equal(receipt.modelInvocations, 0);
    assert.equal(receipt.sourceJobStepsExecuted, false);
    assert.equal(receipt.rootCauseVerified, false);
    assert.equal(receipt.actualCostUsd, null);
    assert.deepEqual(receipt.jobIds, [2001]);
    assert.deepEqual(receipt.identity, f.identity);
    assert.equal(receipt.implementationSha, IMPL);
    assert.doesNotMatch(
      JSON.stringify(receipt),
      /fixture-private-token|fixture-github-token|fixture-channel/,
    );
  } finally {
    f.cleanup();
  }
});

test("executed failure keeps the existing agent hook and durable correlation", async () => {
  const f = fixture();
  try {
    f.job.runner_name = "runner-1";
    f.job.runner_id = 9;
    f.job.steps = [{ status: "completed", conclusion: "failure" }];
    const result = await f.execute();
    assert.equal(result.exitCode, 0);
    assert.equal(f.hooks(), 1);
    const receipt = f.receipts()[0]!;
    assert.equal(receipt.state, "forwarded");
    assert.equal(receipt.hookRunId, "accepted-agent-1");
    assert.equal(receipt.agentDispatchAttempts, 1);
    assert.equal(receipt.modelInvocations, null); // Handoff != verified inference.
    assert.equal(receipt.decisionId, decisionId(f.identity));
    await f.execute();
    assert.equal(f.hooks(), 1);
  } finally {
    f.cleanup();
  }
});

test("missing runner fields, malformed steps and partial pagination never suppress investigation", async () => {
  for (const kind of ["runner", "steps", "page"]) {
    const f = fixture();
    try {
      if (kind === "runner") delete f.job.runner_name;
      if (kind === "steps") f.job.steps = [null];
      if (kind === "page") f.setJobs([f.job], 101);
      const result = await f.execute();
      assert.equal(result.exitCode, 0, kind);
      assert.equal(f.hooks(), 1, kind);
      assert.equal(f.receipts()[0]!.route, "existing_agent");
      assert.equal(f.receipts()[0]!.authenticatedEvidence, false);
    } finally {
      f.cleanup();
    }
  }
});

test("transport uncertainty retains agent fallback without a false classification", async () => {
  const f = fixture();
  try {
    f.runtime.ciTriage.readGithub = async () => {
      throw new CiEvidenceError("github_transport_unavailable");
    };
    await f.execute();
    assert.equal(f.hooks(), 1);
    assert.equal(f.receipts()[0]!.authenticatedEvidence, false);
  } finally {
    f.cleanup();
  }
});

test("stale run source or attempt is held before dispatch", async () => {
  for (const changed of [{ head_sha: "c".repeat(40) }, { run_attempt: 2 }]) {
    const f = fixture();
    try {
      f.runtime.ciTriage.readGithub = async () => ({ ...f.run, ...changed });
      const result = await f.execute();
      assert.equal(result.exitCode, 1);
      assert.equal(result.reason, "run_identity_or_attempt_changed");
      assert.equal(f.hooks(), 0);
    } finally {
      f.cleanup();
    }
  }
});

test("changed implementation refuses both classification and handoff", async () => {
  const f = fixture();
  try {
    let calls = 0;
    f.runtime.ciTriage.implementationRevision = () => (++calls === 1 ? IMPL : "d".repeat(40));
    const result = await f.execute();
    assert.equal(result.exitCode, 1);
    assert.equal(f.hooks(), 0);
    assert.equal(f.receipts()[0]!.reason, "implementation_source_changed");
  } finally {
    f.cleanup();
  }
});

test("new attempts have independent identities; duplicate deliveries do not", async () => {
  const f = fixture();
  try {
    await f.execute();
    await f.execute();
    assert.equal(f.receipts().length, 1);
    f.run.run_attempt = 2;
    f.job.run_attempt = 2;
    await f.execute();
    assert.equal(f.receipts().length, 2);
    assert.notEqual(f.receipts()[0]!.decisionId, f.receipts()[1]!.decisionId);
  } finally {
    f.cleanup();
  }
});

test("concurrent deliveries claim one existing-agent effect", async () => {
  const f = fixture();
  try {
    f.job.runner_name = "runner";
    f.job.runner_id = 9;
    await Promise.all([f.execute(), f.execute(), f.execute()]);
    assert.equal(f.hooks(), 1);
    assert.equal(f.receipts().length, 1);
  } finally {
    f.cleanup();
  }
});

test("lost hook response is durable uncertainty, never retried or reported as accepted", async () => {
  const f = fixture();
  try {
    let calls = 0;
    f.job.runner_name = "runner";
    f.env.CLAWSWEEPER_OPENCLAW_HOOK_RETRY_ATTEMPTS = "3";
    f.runtime.fetch = async () => {
      calls++;
      throw new TypeError("fetch failed PRIVATE_RESPONSE");
    };
    const first = await f.execute();
    assert.equal(first.exitCode, 1);
    assert.equal(calls, 1);
    const replay = await f.execute();
    assert.equal(replay.exitCode, 1);
    assert.equal(calls, 1);
    assert.equal(f.receipts()[0]!.state, "dispatching");
    assert.doesNotMatch(JSON.stringify(f.receipts()), /PRIVATE_RESPONSE/);
  } finally {
    f.cleanup();
  }
});

test("rollback preserves dedup and uses existing agent for new decisions", async () => {
  const f = fixture();
  try {
    await f.execute();
    f.env.CLAWSWEEPER_CI_TRIAGE_ENABLED = "0";
    await f.execute();
    assert.equal(f.hooks(), 0);
    f.run.run_attempt = 2;
    f.job.run_attempt = 2;
    await f.execute();
    assert.equal(f.hooks(), 1);
  } finally {
    f.cleanup();
  }
});

test("missing fallback configuration yields an explicit held receipt", async () => {
  const f = fixture();
  try {
    f.job.runner_name = "runner";
    delete f.env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN;
    const result = await f.execute();
    assert.equal(result.exitCode, 1);
    assert.equal(f.receipts()[0]!.reason, "existing_agent_not_configured");
    assert.equal(f.hooks(), 0);
  } finally {
    f.cleanup();
  }
});

test("real process kill before dispatch is recoverable; after intent it is fenced", async () => {
  const ledgerUrl = new URL("../../dist/repair/ci-triage-ledger.js", import.meta.url).href;
  for (const afterIntent of [false, true]) {
    const f = fixture();
    try {
      const child = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
        import {CiTriageLedger} from ${JSON.stringify(ledgerUrl)};
        const l=new CiTriageLedger(${JSON.stringify(f.state)});
        const c=l.claim(${JSON.stringify(f.identity)},${JSON.stringify(IMPL)},1000);
        if(${afterIntent}) l.receipt(c,null,'dispatching','agent_handoff_intent',null,1000);
        process.kill(process.pid,'SIGKILL');
      `,
        ],
        { encoding: "utf8", timeout: 5000 },
      );
      assert.equal(child.signal, "SIGKILL", child.stderr);
      f.runtime.ciTriage.clock = () => 200000;
      const result = await f.execute();
      assert.equal(result.exitCode, afterIntent ? 1 : 0);
      assert.equal(f.hooks(), 0);
      assert.equal(f.receipts()[0]!.state, afterIntent ? "dispatching" : "resolved");
    } finally {
      f.cleanup();
    }
  }
});

test("complete multi-page evidence is required and job IDs are unique", async () => {
  const f = fixture();
  try {
    const records = Array.from({ length: 101 }, (_, index) => ({ ...f.job, id: 2001 + index }));
    const read = async (endpoint: string) =>
      endpoint.includes("/jobs?")
        ? {
            total_count: 101,
            jobs: endpoint.endsWith("page=1") ? records.slice(0, 100) : records.slice(100),
          }
        : f.run;
    const evidence = await readCiEvidence(f.identity, read);
    assert.equal(evidence.jobs.length, 101);
    assert.equal(evidence.classification, "no_runner_no_steps");
    records[100]!.id = 2001;
    await assert.rejects(
      () => readCiEvidence(f.identity, read),
      /job_identity_or_metadata_incomplete/,
    );
  } finally {
    f.cleanup();
  }
});

test("restored existing hook resumes only an unsent configuration hold", async () => {
  const f = fixture();
  try {
    f.job.runner_name = "runner";
    delete f.env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN;
    await f.execute();
    const before = f.receipts()[0]!;
    assert.equal(before.state, "held");
    assert.equal(before.agentDispatchAttempts, 0);
    f.env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN = "restored-existing-token";
    const resumed = await f.execute();
    assert.equal(resumed.exitCode, 0);
    assert.equal(f.hooks(), 1);
    assert.equal(f.receipts()[0]!.decisionId, before.decisionId);
    assert.equal(f.receipts()[0]!.state, "forwarded");
    await f.execute();
    assert.equal(f.hooks(), 1);
  } finally {
    f.cleanup();
  }
});

test("incomplete current-run metadata retains investigation rather than declaring staleness", async () => {
  const f = fixture();
  try {
    f.runtime.ciTriage.readGithub = async () => ({ id: 1234, run_attempt: 1 });
    const result = await f.execute();
    assert.equal(result.exitCode, 0);
    assert.equal(f.hooks(), 1);
    assert.equal(f.receipts()[0]!.authenticatedEvidence, false);
  } finally {
    f.cleanup();
  }
});

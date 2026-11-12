import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runGithubActivityNotifier } from "../../dist/repair/notify-github-activity.js";
import { observeCiTriage } from "../../dist/repair/observe-ci-triage.js";
import { CiTriageLedger } from "../../dist/repair/ci-triage-ledger.js";

const implementation = "b".repeat(40);
const source = "a".repeat(40);
const repository = "ayobamih/clawsweeper";

test("real HTTP notifier: automatic collection -> zero inference or existing hook -> durable readback", async () => {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-http-"));
  const state = join(root, "state");
  mkdirSync(state, { mode: 0o700 });
  const runs = [1, 2].map((attempt) => ({
    id: 1234 + attempt,
    run_number: 41 + attempt,
    run_attempt: 1,
    head_sha: source,
    status: "completed",
    conclusion: "failure",
    event: "schedule",
    name: "fixture CI",
    repository: { full_name: repository },
    updated_at: `2026-11-11T10:0${attempt}:00Z`,
  }));
  const postKeys: string[] = [];
  let gets = 0;
  const server = createServer(async (req, res) => {
    if (req.method === "GET") {
      gets++;
      assert.equal(req.headers.authorization, "Bearer fixture-read-only");
      res.setHeader("content-type", "application/json");
      if (req.url?.includes("?status=completed")) {
        res.end(JSON.stringify({ total_count: 2, workflow_runs: runs }));
        return;
      }
      const run = runs.find((candidate) => req.url?.includes(`/runs/${candidate.id}`));
      if (!run) {
        res.writeHead(404);
        res.end("{}");
        return;
      }
      if (req.url?.includes("/jobs?")) {
        const ambiguous = run.id === 1236;
        res.end(
          JSON.stringify({
            total_count: 1,
            jobs: [
              {
                id: run.id + 100,
                run_id: run.id,
                run_attempt: 1,
                head_sha: source,
                status: "completed",
                conclusion: "failure",
                runner_name: ambiguous ? "real-shape-runner" : "",
                runner_id: ambiguous ? 7 : 0,
                steps: ambiguous ? [{ status: "completed", conclusion: "failure" }] : [],
              },
            ],
          }),
        );
        return;
      }
      res.end(JSON.stringify(run));
      return;
    }
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/hooks/agent");
    assert.equal(req.headers.authorization, "Bearer fixture-hook-token");
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(body.deliver, false);
    assert.match(body.message, /CI decision ID: [a-f0-9]{64}/);
    postKeys.push(body.idempotencyKey);
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ runId: "http-agent-accepted" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  const env = {
    CLAWSWEEPER_CI_TRIAGE_ENABLED: "1",
    CLAWSWEEPER_CI_TRIAGE_STATE_DIR: state,
    CLAWSWEEPER_CI_TRIAGE_REPOSITORIES: repository,
    CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: implementation,
    CLAWSWEEPER_OPENCLAW_HOOK_URL: `${base}/hooks/agent`,
    CLAWSWEEPER_OPENCLAW_HOOK_TOKEN: "fixture-hook-token",
    CLAWSWEEPER_DISCORD_TARGET: "fixture-target",
  };
  const read = async (endpoint: string) => {
    const response = await fetch(`${base}/${endpoint}`, {
      headers: { authorization: "Bearer fixture-read-only" },
    });
    assert.equal(response.status, 200);
    return await response.json();
  };
  try {
    const first = await observeCiTriage({
      root,
      env,
      notBefore: "2026-11-11T10:00:00.000Z",
      readGithub: read,
      implementationRevision: () => implementation,
    });
    assert.equal(first.newlyProcessed, 2);
    assert.equal(first.externalWorkflowDispatches, 0);
    assert.equal(postKeys.length, 1);
    const ledger = new CiTriageLedger(state);
    const receipts = ledger.receipts();
    ledger.close();
    assert.equal(receipts.length, 2);
    const resolved = receipts.find((receipt) => receipt.state === "resolved")!;
    const forwarded = receipts.find((receipt) => receipt.state === "forwarded")!;
    assert.equal(resolved.identity.runId, 1235);
    assert.equal(resolved.modelInvocations, 0);
    assert.equal(resolved.agentDispatchAttempts, 0);
    assert.equal(forwarded.identity.runId, 1236);
    assert.equal(forwarded.hookRunId, "http-agent-accepted");
    assert.equal(postKeys[0], `ci-triage:${forwarded.decisionId}`);
    assert.equal(forwarded.modelInvocations, null);
    assert.ok(gets >= 8);
    const repeated = await observeCiTriage({
      root,
      env,
      notBefore: "2026-11-11T10:00:00.000Z",
      readGithub: read,
      implementationRevision: () => implementation,
    });
    assert.equal(repeated.newlyProcessed, 0);
    assert.equal(postKeys.length, 1);
    const freshOnly = await observeCiTriage({
      root,
      env,
      notBefore: "2026-11-11T10:03:00.000Z",
      readGithub: read,
      implementationRevision: () => implementation,
    });
    assert.equal(freshOnly.candidates, 0);
    assert.equal(postKeys.length, 1);
    assert.doesNotMatch(
      JSON.stringify(receipts),
      /fixture-hook-token|fixture-read-only|fixture-target/,
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    rmSync(root, { recursive: true, force: true });
  }
});

test("real HTTP lost acceptance is fenced across normal notifier retries", async () => {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-http-loss-"));
  const state = join(root, "state");
  mkdirSync(state, { mode: 0o700 });
  const run = {
    id: 999,
    run_attempt: 1,
    head_sha: source,
    status: "completed",
    conclusion: "failure",
    repository: { full_name: repository },
  };
  const input = join(root, "event.json");
  writeFileSync(
    input,
    JSON.stringify({
      action: "completed",
      repository: { full_name: repository },
      workflow_run: run,
    }),
  );
  let accepted = 0;
  const server = createServer(async (req) => {
    for await (const _chunk of req) {
      /* Receive the entire effect before response loss. */
    }
    accepted++;
    req.socket.destroy();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const env = {
    CLAWSWEEPER_CI_TRIAGE_ENABLED: "1",
    CLAWSWEEPER_CI_TRIAGE_STATE_DIR: state,
    CLAWSWEEPER_CI_TRIAGE_REPOSITORIES: repository,
    CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: implementation,
    CLAWSWEEPER_OPENCLAW_HOOK_URL: `http://127.0.0.1:${address.port}/agent`,
    CLAWSWEEPER_OPENCLAW_HOOK_TOKEN: "local-fixture",
    CLAWSWEEPER_DISCORD_TARGET: "fixture",
  };
  const runtime = {
    root,
    env,
    log: () => {},
    ciTriage: {
      implementationRevision: () => implementation,
      readGithub: async () => {
        throw new Error("fixture provider GET unavailable");
      },
    },
  };
  try {
    const first = await runGithubActivityNotifier(
      ["--event", "workflow_run", "--input", input],
      runtime,
    );
    assert.equal(first.exitCode, 1);
    assert.equal(accepted, 1);
    const second = await runGithubActivityNotifier(
      ["--event", "workflow_run", "--input", input],
      runtime,
    );
    assert.equal(second.exitCode, 1);
    assert.equal(accepted, 1);
    const ledger = new CiTriageLedger(state);
    const receipts = ledger.receipts();
    ledger.close();
    assert.equal(receipts[0]!.state, "dispatching");
    assert.equal(receipts[0]!.agentDispatchAttempts, 1);
    assert.equal(receipts[0]!.hookRunId, null);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    rmSync(root, { recursive: true, force: true });
  }
});

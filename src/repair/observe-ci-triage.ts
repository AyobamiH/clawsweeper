#!/usr/bin/env node
import { verifiedImplementationSha } from "./ci-triage-runtime.js";
import { execFileSync } from "node:child_process";
import {
  constants,
  existsSync,
  fsyncSync,
  openSync,
  closeSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  lstatSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { CiTriageLedger } from "./ci-triage-ledger.js";
import { CiEvidenceError, object, repositoryName, type GithubRead } from "./ci-triage-evidence.js";
import { runGithubActivityNotifier } from "./notify-github-activity.js";

export function ownerGithubRead(env: NodeJS.ProcessEnv): GithubRead {
  // The GitHub reader never needs the OpenClaw hook token or other provider secrets.
  const readEnv: NodeJS.ProcessEnv = {};
  for (const key of [
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "XDG_CONFIG_HOME",
    "GH_CONFIG_DIR",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
  ]) {
    if (env[key] !== undefined) readEnv[key] = env[key];
  }
  return async (endpoint) => {
    if (
      !/^repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs(?:\?status=completed&per_page=100|\/\d+(?:\/attempts\/\d+\/jobs\?per_page=100&page=\d+)?)$/.test(
        endpoint,
      )
    ) {
      throw new CiEvidenceError("unsafe_github_endpoint");
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return JSON.parse(
          execFileSync("gh", ["api", endpoint, "--method", "GET"], {
            env: readEnv,
            encoding: "utf8",
            timeout: 15_000,
            maxBuffer: 2 * 1024 * 1024,
            stdio: ["ignore", "pipe", "pipe"],
          }),
        ) as unknown;
      } catch (error) {
        const details =
          error && typeof error === "object" && "stderr" in error
            ? String(error.stderr).slice(0, 2048)
            : "";
        if (/HTTP 40[13]/i.test(details)) throw new CiEvidenceError("github_owner_auth_refused");
        const transient =
          /TLS handshake timeout|connection reset|network is unreachable|connection refused|unexpected EOF|HTTP 50[234]|i\/o timeout|context deadline exceeded/i.test(
            details,
          );
        if (attempt === 0 && transient) {
          await sleep(300);
          continue;
        }
        throw new CiEvidenceError("github_owner_read_unavailable");
      }
    }
    throw new CiEvidenceError("github_owner_read_unavailable");
  };
}

export async function observeCiTriage(options: {
  root: string;
  env: NodeJS.ProcessEnv;
  notBefore: string;
  readGithub?: GithubRead;
  maxEvents?: number;
  implementationRevision?: () => string;
}): Promise<Record<string, unknown>> {
  const repo = repositoryName(options.env.CLAWSWEEPER_CI_TRIAGE_REPOSITORIES);
  if (!repo) throw new Error("observer_requires_one_explicit_repository");
  const since = Date.parse(options.notBefore);
  if (!Number.isFinite(since) || new Date(since).toISOString() !== options.notBefore) {
    throw new Error("observer_requires_canonical_watermark");
  }
  const maxEvents = options.maxEvents ?? 5;
  if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > 10)
    throw new Error("observer_budget_invalid");
  const state = options.env.CLAWSWEEPER_CI_TRIAGE_STATE_DIR;
  if (!state) throw new Error("observer_requires_private_state");
  const ledger = new CiTriageLedger(state);
  ledger.close();
  const verify =
    options.implementationRevision ??
    (() =>
      verifiedImplementationSha(options.root, options.env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST));
  if (verify() !== options.env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA) {
    throw new Error("observer_implementation_source_changed");
  }
  const read = options.readGithub ?? ownerGithubRead(options.env);
  const page = object(await read(`repos/${repo}/actions/runs?status=completed&per_page=100`));
  if (!page || !Array.isArray(page.workflow_runs) || page.workflow_runs.length > 100) {
    throw new Error("observer_invalid_run_inventory");
  }
  const candidates = page.workflow_runs
    .map(object)
    .filter(
      (run): run is Record<string, unknown> =>
        run !== null &&
        run.status === "completed" &&
        run.conclusion === "failure" &&
        typeof run.updated_at === "string" &&
        Number.isFinite(Date.parse(run.updated_at)) &&
        Date.parse(run.updated_at) >= since,
    )
    .sort((a, b) => String(a.updated_at).localeCompare(String(b.updated_at)));
  const decisions: Record<string, unknown>[] = [];
  let newlyProcessed = 0;
  for (const run of candidates) {
    if (newlyProcessed >= maxEvents) break;
    const filename = join(state, `event-${randomUUID()}.json`);
    // Payload is read from the provider automatically, never a hand-picked
    // synthetic failure or an instruction to create a workflow run.
    const fd = openSync(
      filename,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      writeFileSync(
        fd,
        JSON.stringify({ action: "completed", repository: { full_name: repo }, workflow_run: run }),
      );
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      const result = await runGithubActivityNotifier(
        ["--event", "workflow_run", "--input", filename],
        {
          root: options.root,
          env: options.env,
          ciTriage: {
            readGithub: read,
            ...(options.implementationRevision
              ? { implementationRevision: options.implementationRevision }
              : {}),
          },
          log: () => {},
        },
      );
      const duplicate = result.reason === "ci_triage_duplicate";
      if (!duplicate) newlyProcessed++;
      decisions.push({
        runId: run.id,
        runAttempt: run.run_attempt,
        sourceSha: run.head_sha,
        providerEvent: run.event,
        providerUpdatedAt: run.updated_at,
        decisionId: result.ciTriage?.decisionId ?? null,
        state: result.ciTriage?.state ?? "held",
        route: result.ciTriage?.route ?? "held",
        reason: result.reason,
        modelInvocations: result.ciTriage?.modelInvocations ?? null,
        duplicate,
        exitCode: result.exitCode,
      });
    } finally {
      unlinkSync(filename);
    }
  }
  return {
    schema: "clawsweeper.ci-triage-observation.v1",
    observedAt: new Date().toISOString(),
    repository: repo,
    notBefore: options.notBefore,
    implementationSha: options.env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA ?? null,
    coverage: "latest_100_completed_runs_bounded_sample",
    inventoryMayBeTruncated: page.workflow_runs.length === 100,
    candidates: candidates.length,
    newlyProcessed,
    decisions,
    externalWorkflowDispatches: 0,
    sourceOrPublishingMutations: 0,
  };
}

function initialWatermark(state: string, repo: string, sha: string, lookback: number): string {
  const ledger = new CiTriageLedger(state);
  ledger.close();
  const filename = join(state, "observer-watermark.json");
  if (existsSync(filename)) {
    const file = lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0)
      throw new Error("observer_watermark_unsafe");
    const data = JSON.parse(readFileSync(filename, "utf8"));
    if (data.repository !== repo || data.implementationSha !== sha)
      throw new Error("observer_watermark_source_changed");
    return String(data.notBefore);
  }
  const notBefore = new Date(Date.now() - lookback * 60_000).toISOString();
  const fd = openSync(
    filename,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(
      fd,
      JSON.stringify({
        repository: repo,
        implementationSha: sha,
        notBefore,
        provenance: lookback ? "explicit_historical_catchup" : "new_events_after_activation",
      }),
    );
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const directory = openSync(state, constants.O_DIRECTORY | constants.O_RDONLY);
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
  return notBefore;
}
export async function runObservationLoop(options: {
  observe: () => Promise<Record<string, unknown>>;
  durationMs: number;
  intervalMs: number;
  emit: (value: Record<string, unknown>) => void;
  clock?: () => number;
  delay?: (ms: number) => Promise<void>;
}): Promise<{ cycles: number; heldReadCycles: number; endedWithReadFailure: boolean }> {
  const clock = options.clock ?? Date.now;
  const delay = options.delay ?? sleep;
  const end = clock() + options.durationMs;
  let cycles = 0;
  let heldReadCycles = 0;
  let endedWithReadFailure = false;
  do {
    cycles++;
    try {
      options.emit(await options.observe());
      endedWithReadFailure = false;
    } catch (error) {
      // A read-only collection failure is retryable; source, policy, storage
      // and manifest failures must still stop immediately and fail closed.
      if (!(error instanceof CiEvidenceError) || error.reason !== "github_owner_read_unavailable")
        throw error;
      heldReadCycles++;
      endedWithReadFailure = true;
      options.emit({
        schema: "clawsweeper.ci-triage-observation-error.v1",
        observedAt: new Date(clock()).toISOString(),
        reason: error.reason,
        state: "held",
        externalWorkflowDispatches: 0,
        modelInvocations: 0,
      });
    }
    if (!options.durationMs || clock() >= end) break;
    await delay(Math.min(options.intervalMs, end - clock()));
  } while (clock() < end);
  return { cycles, heldReadCycles, endedWithReadFailure };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const numberOption = (name: string, fallback: number) => {
    const index = args.indexOf(name);
    return index === -1 ? fallback : Number(args[index + 1]);
  };
  if (args.includes("--help")) {
    console.log(
      "observe-ci-triage [--watch-seconds 0..300] [--interval-seconds 10..60] [--catch-up-minutes 0..1440] [--max-events 1..10]\nUses existing owner gh authentication, private state, source pin and repository allowlist. No workflow dispatch. Zero lookback means only events after the persisted activation watermark.",
    );
    return;
  }
  const watch = numberOption("--watch-seconds", 0);
  const interval = numberOption("--interval-seconds", 30);
  const lookback = numberOption("--catch-up-minutes", 0);
  if (
    ![watch, interval, lookback].every(Number.isSafeInteger) ||
    watch < 0 ||
    watch > 300 ||
    interval < 10 ||
    interval > 60 ||
    lookback < 0 ||
    lookback > 1440
  )
    throw new Error("observer_bounds_invalid");
  const env = process.env;
  const repo = repositoryName(env.CLAWSWEEPER_CI_TRIAGE_REPOSITORIES);
  const state = env.CLAWSWEEPER_CI_TRIAGE_STATE_DIR;
  const sha = env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA ?? "";
  if (!repo || !state || !/^[a-f0-9]{40}$/.test(sha)) throw new Error("observer_policy_missing");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  if (verifiedImplementationSha(root, env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST) !== sha) {
    throw new Error("observer_implementation_source_changed");
  }
  const notBefore = initialWatermark(state, repo, sha, lookback);
  const summary = await runObservationLoop({
    observe: () =>
      observeCiTriage({ root, env, notBefore, maxEvents: numberOption("--max-events", 5) }),
    durationMs: watch * 1000,
    intervalMs: interval * 1000,
    emit: (value) => console.log(JSON.stringify(value)),
  });
  console.log(JSON.stringify({ schema: "clawsweeper.ci-triage-watch-summary.v1", ...summary }));
  if (summary.endedWithReadFailure) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    const reason =
      error instanceof CiEvidenceError
        ? error.reason
        : error instanceof Error && /^[a-z_]{1,80}$/.test(error.message)
          ? error.message
          : "observer_unexpected_error";
    console.error(JSON.stringify({ state: "held", reason }));
    process.exitCode = 1;
  });
}

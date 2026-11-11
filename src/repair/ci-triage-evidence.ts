import { createHash } from "node:crypto";

export type CiIdentity = {
  repository: string;
  runId: number;
  runAttempt: number;
  sourceSha: string;
};
export type CiJob = {
  id: number;
  status: string;
  conclusion: string | null;
  runnerName: string | null;
  runnerId: number | null;
  steps: { status: string; conclusion: string | null }[];
};
export type CiEvidence = {
  identity: CiIdentity;
  observedAt: string;
  authenticated: boolean;
  classification: "no_runner_no_steps" | "needs_investigation";
  reason: string;
  jobs: CiJob[];
  digest: string;
};
export type GithubRead = (endpoint: string) => Promise<unknown>;
export class CiEvidenceError extends Error {
  constructor(
    readonly reason: string,
    readonly stale = false,
  ) {
    super(reason);
  }
}
export function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
export function positiveId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
export function repositoryName(value: unknown): string | null {
  return typeof value === "string" &&
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value) &&
    !value.split("/").some((part) => part === "." || part === "..")
    ? value.toLowerCase()
    : null;
}
export function identityFromRun(repository: unknown, value: unknown): CiIdentity | null {
  const run = object(value);
  const repo = repositoryName(repository);
  if (
    !repo ||
    !run ||
    !positiveId(run.id) ||
    !positiveId(run.run_attempt) ||
    typeof run.head_sha !== "string" ||
    !/^[a-f0-9]{40}$/.test(run.head_sha)
  )
    return null;
  return { repository: repo, runId: run.id, runAttempt: run.run_attempt, sourceSha: run.head_sha };
}
export function decisionId(identity: CiIdentity): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        "clawsweeper.ci-triage.v1",
        identity.repository,
        identity.runId,
        identity.runAttempt,
        identity.sourceSha,
      ]),
    )
    .digest("hex");
}
export function githubReader(env: NodeJS.ProcessEnv, fetcher: typeof fetch = fetch): GithubRead {
  const token = env.GH_TOKEN || env.GITHUB_TOKEN;
  return async (endpoint) => {
    if (!token) throw new CiEvidenceError("github_auth_unavailable");
    if (
      !/^repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/\d+(?:\/attempts\/\d+\/jobs\?per_page=100&page=\d+)?$/.test(
        endpoint,
      )
    ) {
      throw new CiEvidenceError("unsafe_github_endpoint");
    }
    let response: Response;
    try {
      response = await fetcher(`https://api.github.com/${endpoint}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" },
        signal: AbortSignal.timeout(10_000),
        redirect: "error",
      });
    } catch {
      throw new CiEvidenceError("github_transport_unavailable");
    }
    if (!response.ok) throw new CiEvidenceError(`github_http_${response.status}`);
    // Bound bytes while streaming, rather than trusting Content-Length.
    const reader = response.body?.getReader();
    if (!reader) throw new CiEvidenceError("github_empty_response");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2 * 1024 * 1024) {
          await reader.cancel();
          throw new CiEvidenceError("github_response_too_large");
        }
        chunks.push(value);
      }
      return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    } catch (error) {
      if (error instanceof CiEvidenceError) throw error;
      throw new CiEvidenceError("github_invalid_response");
    } finally {
      reader.releaseLock();
    }
  };
}
function verifyRun(identity: CiIdentity, value: unknown): void {
  const run = object(value);
  const repo = repositoryName(object(run?.repository)?.full_name);
  if (
    !run ||
    !positiveId(run.id) ||
    !positiveId(run.run_attempt) ||
    !repo ||
    typeof run.head_sha !== "string" ||
    !/^[a-f0-9]{40}$/.test(run.head_sha) ||
    typeof run.status !== "string" ||
    !(run.conclusion === null || typeof run.conclusion === "string")
  ) {
    throw new CiEvidenceError("run_identity_incomplete");
  }
  if (
    run.id !== identity.runId ||
    run.run_attempt !== identity.runAttempt ||
    run.head_sha !== identity.sourceSha ||
    repo !== identity.repository
  ) {
    throw new CiEvidenceError("run_identity_or_attempt_changed", true);
  }
  if (run.status !== "completed" || run.conclusion !== "failure") {
    throw new CiEvidenceError("run_no_longer_failed", true);
  }
}

export async function assertCurrentRun(identity: CiIdentity, read: GithubRead): Promise<void> {
  verifyRun(identity, await read(`repos/${identity.repository}/actions/runs/${identity.runId}`));
}
function jobFromRecord(identity: CiIdentity, value: unknown): CiJob | null {
  const row = object(value);
  if (
    !row ||
    !positiveId(row.id) ||
    row.run_id !== identity.runId ||
    row.head_sha !== identity.sourceSha ||
    (row.run_attempt !== undefined && row.run_attempt !== identity.runAttempt) ||
    row.status !== "completed" ||
    typeof row.conclusion !== "string" ||
    !Object.hasOwn(row, "runner_name") ||
    !(row.runner_name === null || typeof row.runner_name === "string") ||
    !Object.hasOwn(row, "runner_id") ||
    !(
      row.runner_id === null ||
      (Number.isSafeInteger(row.runner_id) && Number(row.runner_id) >= 0)
    ) ||
    !Array.isArray(row.steps) ||
    row.steps.length > 1000
  )
    return null;
  const steps: CiJob["steps"] = [];
  for (const raw of row.steps) {
    const step = object(raw);
    if (
      !step ||
      typeof step.status !== "string" ||
      !(step.conclusion === null || typeof step.conclusion === "string")
    )
      return null;
    steps.push({ status: step.status, conclusion: step.conclusion });
  }
  return {
    id: row.id,
    status: row.status,
    conclusion: row.conclusion,
    runnerName: row.runner_name,
    runnerId: row.runner_id as number | null,
    steps,
  };
}
export function classifyJobs(jobs: readonly CiJob[]): CiEvidence["classification"] {
  // This diagnoses execution, not the root cause or successful source tests.
  return jobs.some((job) => job.conclusion === "failure") &&
    jobs.every(
      (job) =>
        job.status === "completed" &&
        ["failure", "skipped", "neutral"].includes(job.conclusion ?? "") &&
        (job.runnerName === "" || job.runnerName === null) &&
        (job.runnerId === 0 || job.runnerId === null) &&
        job.steps.length === 0,
    )
    ? "no_runner_no_steps"
    : "needs_investigation";
}
export function ambiguousEvidence(
  identity: CiIdentity,
  reason: string,
  now = new Date(),
): CiEvidence {
  return {
    identity,
    observedAt: now.toISOString(),
    authenticated: false,
    classification: "needs_investigation",
    reason,
    jobs: [],
    digest: createHash("sha256")
      .update(JSON.stringify([identity, reason]))
      .digest("hex"),
  };
}
export async function readCiEvidence(
  identity: CiIdentity,
  read: GithubRead,
  now: () => Date = () => new Date(),
): Promise<CiEvidence> {
  await assertCurrentRun(identity, read);
  const jobs: CiJob[] = [];
  let expected: number | undefined;
  for (let page = 1; page <= 10; page++) {
    const result = object(
      await read(
        `repos/${identity.repository}/actions/runs/${identity.runId}/attempts/${identity.runAttempt}/jobs?per_page=100&page=${page}`,
      ),
    );
    if (
      !result ||
      !Number.isSafeInteger(result.total_count) ||
      Number(result.total_count) < 1 ||
      Number(result.total_count) > 1000 ||
      !Array.isArray(result.jobs) ||
      result.jobs.length > 100
    )
      throw new CiEvidenceError("incomplete_job_inventory");
    if (expected !== undefined && expected !== result.total_count) {
      throw new CiEvidenceError("job_inventory_changed", true);
    }
    expected = Number(result.total_count);
    for (const raw of result.jobs) {
      const job = jobFromRecord(identity, raw);
      if (!job || jobs.some((prior) => prior.id === job.id)) {
        throw new CiEvidenceError("job_identity_or_metadata_incomplete");
      }
      jobs.push(job);
    }
    if (jobs.length === expected) break;
    if (jobs.length > expected || result.jobs.length !== 100 || page === 10) {
      throw new CiEvidenceError("incomplete_job_pagination");
    }
  }
  await assertCurrentRun(identity, read);
  const classification = classifyJobs(jobs);
  return {
    identity,
    observedAt: now().toISOString(),
    authenticated: true,
    classification,
    reason:
      classification === "no_runner_no_steps"
        ? "all_failed_run_jobs_unexecuted"
        : "executed_or_ambiguous_jobs",
    jobs,
    digest: createHash("sha256")
      .update(JSON.stringify(jobs.slice().sort((a, b) => a.id - b.id)))
      .digest("hex"),
  };
}

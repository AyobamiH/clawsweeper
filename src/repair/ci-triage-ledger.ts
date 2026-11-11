import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { chmodSync, existsSync, lstatSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { decisionId, type CiEvidence, type CiIdentity } from "./ci-triage-evidence.js";

export type CiReceipt = {
  schema: "clawsweeper.ci-triage-receipt.v1";
  decisionId: string;
  identity: CiIdentity;
  implementationSha: string;
  observedAt: string;
  recordedAt: string;
  elapsedMs: number;
  state: "resolved" | "forwarded" | "held" | "dispatching";
  route: "deterministic" | "existing_agent" | "held";
  reason: string;
  authenticatedEvidence: boolean;
  evidenceDigest: string | null;
  jobIds: number[];
  agentDispatchAttempts: number;
  modelInvocations: 0 | null;
  inputTokens: 0 | null;
  outputTokens: 0 | null;
  actualCostUsd: null;
  rootCauseVerified: false;
  sourceJobStepsExecuted: false | null;
  hookRunId: string | null;
};
type DecisionRow = {
  id: string;
  identity_json: string;
  implementation_sha: string;
  state: string;
  owner: string;
  lease_until: number;
  attempts: number;
  started_at: number;
  receipt_json: string | null;
};
export type Claim =
  | { owned: true; id: string; owner: string }
  | {
      owned: false;
      id: string;
      reason: "duplicate" | "in_progress" | "uncertain";
      receipt: CiReceipt | null;
    };

export class CiTriageLedger {
  private readonly db: DatabaseSync;
  constructor(directory: string) {
    if (!isAbsolute(directory)) throw new Error("ci_triage_state_path_not_absolute");
    if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
    const info = lstatSync(directory);
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      (info.mode & 0o077) !== 0 ||
      realpathSync(directory) !== resolve(directory) ||
      (process.getuid && info.uid !== process.getuid())
    ) {
      throw new Error("ci_triage_state_directory_unsafe");
    }
    const filename = join(directory, "decisions.sqlite3");
    if (existsSync(filename)) {
      const file = lstatSync(filename);
      if (
        !file.isFile() ||
        file.isSymbolicLink() ||
        file.nlink !== 1 ||
        (file.mode & 0o077) !== 0 ||
        (process.getuid && file.uid !== process.getuid())
      )
        throw new Error("ci_triage_database_unsafe");
    }
    const previous = process.umask(0o077);
    try {
      this.db = new DatabaseSync(filename);
      chmodSync(filename, 0o600);
      this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000;
        CREATE TABLE IF NOT EXISTS decisions (
          id TEXT PRIMARY KEY, identity_json TEXT NOT NULL, implementation_sha TEXT NOT NULL,
          state TEXT NOT NULL, owner TEXT NOT NULL, lease_until INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0, started_at INTEGER NOT NULL, receipt_json TEXT
        );
        CREATE TABLE IF NOT EXISTS transitions (
          sequence INTEGER PRIMARY KEY, decision_id TEXT NOT NULL,
          state TEXT NOT NULL, recorded_at INTEGER NOT NULL, reason TEXT NOT NULL
        );`);
      if ((statSync(filename).mode & 0o077) !== 0)
        throw new Error("ci_triage_database_permissions");
    } finally {
      process.umask(previous);
    }
  }
  close(): void {
    this.db.close();
  }
  private transaction<T>(action: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = action();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  private row(id: string): DecisionRow | undefined {
    return this.db.prepare("SELECT * FROM decisions WHERE id=?").get(id) as DecisionRow | undefined;
  }
  private transition(id: string, state: string, reason: string, now: number): void {
    this.db
      .prepare("INSERT INTO transitions(decision_id,state,recorded_at,reason) VALUES(?,?,?,?)")
      .run(id, state, now, reason);
  }
  claim(
    identity: CiIdentity,
    implementationSha: string,
    now = Date.now(),
    retryUnsent = false,
  ): Claim {
    if (!/^[a-f0-9]{40}$/.test(implementationSha))
      throw new Error("ci_triage_implementation_invalid");
    const id = decisionId(identity);
    return this.transaction(() => {
      const prior = this.row(id);
      if (prior) {
        if (prior.identity_json !== JSON.stringify(identity))
          throw new Error("ci_triage_identity_collision");
        const receipt = prior.receipt_json ? (JSON.parse(prior.receipt_json) as CiReceipt) : null;
        const resumableHold =
          retryUnsent &&
          prior.state === "held" &&
          prior.attempts === 0 &&
          receipt?.reason === "existing_agent_not_configured";
        if (["resolved", "forwarded", "held"].includes(prior.state) && !resumableHold) {
          return { owned: false, id, reason: "duplicate", receipt };
        }
        if (prior.state === "dispatching") {
          // An expired network effect is uncertain, not permission to replay.
          return {
            owned: false,
            id,
            reason: prior.lease_until > now ? "in_progress" : "uncertain",
            receipt,
          };
        }
        if (!resumableHold && prior.lease_until > now)
          return { owned: false, id, reason: "in_progress", receipt };
        if ((!resumableHold && prior.state !== "observing") || prior.attempts !== 0)
          throw new Error("ci_triage_invalid_recovery_state");
      } else {
        const total = this.db.prepare("SELECT COUNT(*) AS n FROM decisions").get() as { n: number };
        if (total.n >= 20000) throw new Error("ci_triage_ledger_capacity");
      }
      const owner = randomUUID();
      this.db
        .prepare(`INSERT INTO decisions(id,identity_json,implementation_sha,state,owner,lease_until,attempts,started_at)
        VALUES(?,?,?,'observing',?,?,0,?) ON CONFLICT(id) DO UPDATE SET
        implementation_sha=excluded.implementation_sha,state='observing',owner=excluded.owner,lease_until=excluded.lease_until,started_at=excluded.started_at,receipt_json=NULL`)
        .run(id, JSON.stringify(identity), implementationSha, owner, now + 180_000, now);
      this.transition(id, "observing", prior ? "recovered_before_effect" : "claimed", now);
      return { owned: true, id, owner };
    });
  }
  private owned(claim: Extract<Claim, { owned: true }>, state: string): DecisionRow {
    const row = this.row(claim.id);
    if (!row || row.owner !== claim.owner || row.state !== state)
      throw new Error("ci_triage_claim_lost");
    return row;
  }
  receipt(
    claim: Extract<Claim, { owned: true }>,
    evidence: CiEvidence | null,
    state: CiReceipt["state"],
    reason: string,
    hookRunId: string | null = null,
    now = Date.now(),
  ): CiReceipt {
    if (!/^[a-z0-9_]{1,80}$/.test(reason)) throw new Error("ci_triage_unsafe_reason");
    if (hookRunId !== null && !/^[A-Za-z0-9_.:-]{1,128}$/.test(hookRunId)) {
      throw new Error("ci_triage_unsafe_hook_identity");
    }
    return this.transaction(() => {
      const row = this.owned(claim, state === "forwarded" ? "dispatching" : "observing");
      if (
        state === "resolved" &&
        (!evidence?.authenticated || evidence.classification !== "no_runner_no_steps")
      ) {
        throw new Error("ci_triage_unverified_resolution");
      }
      const result: CiReceipt = {
        schema: "clawsweeper.ci-triage-receipt.v1",
        decisionId: claim.id,
        identity: JSON.parse(row.identity_json) as CiIdentity,
        implementationSha: row.implementation_sha,
        observedAt: evidence?.observedAt ?? new Date(now).toISOString(),
        recordedAt: new Date(now).toISOString(),
        elapsedMs: Math.max(0, now - row.started_at),
        state,
        route:
          state === "resolved" ? "deterministic" : state === "held" ? "held" : "existing_agent",
        reason,
        authenticatedEvidence: evidence?.authenticated ?? false,
        evidenceDigest: evidence?.digest ?? null,
        jobIds: evidence?.jobs.map((job) => job.id) ?? [],
        agentDispatchAttempts: state === "dispatching" ? 1 : row.attempts,
        modelInvocations: state === "resolved" ? 0 : null,
        inputTokens: state === "resolved" ? 0 : null,
        outputTokens: state === "resolved" ? 0 : null,
        actualCostUsd: null,
        rootCauseVerified: false,
        sourceJobStepsExecuted: state === "resolved" ? false : null,
        hookRunId,
      };
      this.db
        .prepare(
          "UPDATE decisions SET state=?,receipt_json=?,attempts=?,lease_until=? WHERE id=? AND owner=?",
        )
        .run(
          state,
          JSON.stringify(result),
          result.agentDispatchAttempts,
          now + 180_000,
          claim.id,
          claim.owner,
        );
      this.transition(claim.id, state, reason, now);
      return result;
    });
  }
  uncertain(claim: Extract<Claim, { owned: true }>, now = Date.now()): CiReceipt {
    return this.transaction(() => {
      const row = this.owned(claim, "dispatching");
      const receipt = JSON.parse(row.receipt_json!) as CiReceipt;
      receipt.reason = "agent_delivery_uncertain";
      receipt.recordedAt = new Date(now).toISOString();
      this.db
        .prepare("UPDATE decisions SET receipt_json=?,lease_until=? WHERE id=? AND owner=?")
        .run(JSON.stringify(receipt), now, claim.id, claim.owner);
      this.transition(claim.id, "dispatching", "agent_delivery_uncertain", now);
      return receipt;
    });
  }
  receipts(): CiReceipt[] {
    return this.db
      .prepare(
        "SELECT receipt_json FROM decisions WHERE receipt_json IS NOT NULL ORDER BY rowid DESC LIMIT 1000",
      )
      .all()
      .map((row) => JSON.parse(String(row.receipt_json)) as CiReceipt);
  }
}

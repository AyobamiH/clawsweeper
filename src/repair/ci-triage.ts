import { verifiedImplementationSha } from "./ci-triage-runtime.js";
import { CiTriageLedger, type CiReceipt, type Claim } from "./ci-triage-ledger.js";
import {
  ambiguousEvidence,
  assertCurrentRun,
  CiEvidenceError,
  githubReader,
  identityFromRun,
  readCiEvidence,
  repositoryName,
  type CiEvidence,
  type CiIdentity,
  type GithubRead,
} from "./ci-triage-evidence.js";

type OwnedClaim = Extract<Claim, { owned: true }>;
export type CiTriageRuntime = {
  readGithub?: GithubRead;
  implementationRevision?: () => string;
  clock?: () => number;
};
export type TriageResult =
  | { kind: "terminal"; reason: string; receipt: CiReceipt | null; held: boolean }
  | { kind: "forward"; session: CiTriageSession }
  | { kind: "not_applicable" };

export class CiTriageSession {
  private dispatched = false;
  constructor(
    private readonly ledger: CiTriageLedger,
    private readonly claim: OwnedClaim,
    readonly evidence: CiEvidence,
    private readonly readGithub: GithubRead,
    private readonly expectedImplementation: string,
    private readonly currentImplementation: () => string,
    private readonly clock: () => number,
  ) {}
  get decisionId(): string {
    return this.claim.id;
  }
  hold(reason: string): CiReceipt {
    return this.ledger.receipt(this.claim, this.evidence, "held", reason, null, this.clock());
  }
  async beforeDispatch(): Promise<CiReceipt | null> {
    if (this.dispatched) throw new Error("ci_triage_dispatch_already_started");
    if (this.currentImplementation() !== this.expectedImplementation)
      return this.hold("implementation_source_changed");
    try {
      await assertCurrentRun(this.evidence.identity, this.readGithub);
    } catch (error) {
      if (error instanceof CiEvidenceError && error.stale) return this.hold(error.reason);
      // An unavailable GET cannot prove the failure. The existing diagnostic
      // agent is the fallback; it receives no authority to retry/deploy.
    }
    this.ledger.receipt(
      this.claim,
      this.evidence,
      "dispatching",
      "agent_handoff_intent",
      null,
      this.clock(),
    );
    this.dispatched = true;
    return null;
  }
  delivered(runId: string | null): CiReceipt {
    if (!this.dispatched) throw new Error("ci_triage_dispatch_intent_missing");
    if (!runId || !/^[A-Za-z0-9_.:-]{1,128}$/.test(runId)) return this.uncertain();
    return this.ledger.receipt(
      this.claim,
      this.evidence,
      "forwarded",
      "existing_agent_accepted",
      runId,
      this.clock(),
    );
  }
  uncertain(): CiReceipt {
    if (!this.dispatched) throw new Error("ci_triage_dispatch_intent_missing");
    return this.ledger.uncertain(this.claim, this.clock());
  }
  deliveryFailed(): CiReceipt {
    return this.dispatched ? this.uncertain() : this.hold("pre_dispatch_validation_failed");
  }
  close(): void {
    this.ledger.close();
  }
}

export async function beginCiTriage(options: {
  root: string;
  env: NodeJS.ProcessEnv;
  eventType: string;
  repository: string;
  workflowRun: unknown;
  dryRun: boolean;
  runtime?: CiTriageRuntime;
}): Promise<TriageResult> {
  const { env } = options;
  const configured = Boolean(env.CLAWSWEEPER_CI_TRIAGE_STATE_DIR);
  const enabled = env.CLAWSWEEPER_CI_TRIAGE_ENABLED === "1";
  if ((!configured && !enabled) || options.eventType !== "workflow_run" || options.dryRun)
    return { kind: "not_applicable" };
  const repo = repositoryName(options.repository);
  const allowed = (env.CLAWSWEEPER_CI_TRIAGE_REPOSITORIES ?? "")
    .split(",")
    .map((entry) => repositoryName(entry.trim()))
    .filter(Boolean);
  const expectedImplementation = env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA ?? "";
  if (
    !configured ||
    !repo ||
    !allowed.includes(repo) ||
    allowed.length > 10 ||
    !/^[a-f0-9]{40}$/.test(expectedImplementation)
  ) {
    return { kind: "terminal", reason: "ci_triage_policy_unverified", receipt: null, held: true };
  }
  const identity = identityFromRun(repo, options.workflowRun);
  if (!identity)
    return {
      kind: "terminal",
      reason: "ci_triage_event_identity_incomplete",
      receipt: null,
      held: true,
    };
  const revision =
    options.runtime?.implementationRevision ??
    (() => verifiedImplementationSha(options.root, env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST));
  const clock = options.runtime?.clock ?? Date.now;
  const read = options.runtime?.readGithub ?? githubReader(env);
  let ledger: CiTriageLedger | undefined;
  let ownedClaim: OwnedClaim | undefined;
  try {
    if (revision() !== expectedImplementation)
      throw new CiEvidenceError("implementation_source_changed", true);
    ledger = new CiTriageLedger(env.CLAWSWEEPER_CI_TRIAGE_STATE_DIR!);
    const hasFallback = Boolean(
      env.CLAWSWEEPER_OPENCLAW_HOOK_URL &&
      env.CLAWSWEEPER_OPENCLAW_HOOK_TOKEN &&
      env.CLAWSWEEPER_DISCORD_TARGET,
    );
    const claim = ledger.claim(identity, expectedImplementation, clock(), hasFallback);
    if (!claim.owned) {
      ledger.close();
      const accepted =
        claim.reason === "duplicate" &&
        ["resolved", "forwarded"].includes(claim.receipt?.state ?? "");
      return {
        kind: "terminal",
        reason: `ci_triage_${claim.reason}`,
        receipt: claim.receipt,
        held: !accepted,
      };
    }
    ownedClaim = claim;
    let evidence: CiEvidence;
    try {
      evidence = enabled
        ? await readCiEvidence(identity, read, () => new Date(clock()))
        : ambiguousEvidence(identity, "feature_rollback_existing_route", new Date(clock()));
    } catch (error) {
      if (error instanceof CiEvidenceError && error.stale) {
        const receipt = ledger.receipt(claim, null, "held", error.reason, null, clock());
        ledger.close();
        return { kind: "terminal", reason: error.reason, receipt, held: true };
      }
      evidence = ambiguousEvidence(
        identity,
        error instanceof CiEvidenceError ? error.reason : "github_evidence_unavailable",
        new Date(clock()),
      );
    }
    if (revision() !== expectedImplementation) {
      const receipt = ledger.receipt(
        claim,
        evidence,
        "held",
        "implementation_source_changed",
        null,
        clock(),
      );
      ledger.close();
      return { kind: "terminal", reason: "implementation_source_changed", receipt, held: true };
    }
    if (enabled && evidence.authenticated && evidence.classification === "no_runner_no_steps") {
      const receipt = ledger.receipt(
        claim,
        evidence,
        "resolved",
        "failed_run_jobs_executed_no_steps",
        null,
        clock(),
      );
      ledger.close();
      return { kind: "terminal", reason: "ci_triage_no_runner_no_steps", receipt, held: false };
    }
    return {
      kind: "forward",
      session: new CiTriageSession(
        ledger,
        claim,
        evidence,
        read,
        expectedImplementation,
        revision,
        clock,
      ),
    };
  } catch (error) {
    const reason = error instanceof CiEvidenceError ? error.reason : "ci_triage_state_unavailable";
    let receipt: CiReceipt | null = null;
    try {
      if (ledger && ownedClaim)
        receipt = ledger.receipt(ownedClaim, null, "held", reason, null, clock());
    } catch {
      /* Storage failure is never permission to dispatch. */
    }
    try {
      ledger?.close();
    } catch {
      /* Preserve refusal. */
    }
    return { kind: "terminal", reason, receipt, held: true };
  }
}

export function triageIdentityForLog(identity: CiIdentity): CiIdentity {
  return {
    repository: identity.repository,
    runId: identity.runId,
    runAttempt: identity.runAttempt,
    sourceSha: identity.sourceSha,
  };
}

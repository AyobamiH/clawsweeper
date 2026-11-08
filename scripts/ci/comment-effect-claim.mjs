/**
 * Create-only Git ref as a durable claim for a non-idempotent GitHub comment.
 * This code never posts a public comment. An uncertain claim remains held;
 * do not issue a second create POST, even if the first response was lost.
 *
 * GitHub notes refs are deliberately used instead of tags or branches to avoid
 * accidental push/sweep workflows. Their GitHub REST support must be accepted
 * on an owner-controlled test repository before enabling this workflow.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SHA = /^[0-9a-f]{40}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const EFFECTS = new Set(["pr_ack", "command_status"]);
const MAX_API_BYTES = 1_000_000;

function ensureString(x, regex, reason) {
  if (typeof x !== "string" || !regex.test(x)) throw new Error(reason);
  return x;
}

export function buildClaim({ repo, number, sourceId, effect }) {
  ensureString(repo, REPO, "invalid_repo");
  ensureString(String(number), /^[1-9][0-9]{0,12}$/, "invalid_item_number");
  ensureString(String(sourceId), /^[1-9][0-9]{0,16}$/, "invalid_source_id");
  if (!EFFECTS.has(effect)) throw new Error("unknown_comment_effect");
  const identity = JSON.stringify({
    version: 1,
    repo: repo.toLowerCase(),
    number: String(number),
    effect,
    sourceId: String(sourceId),
  });
  const key = createHash("sha256").update(identity).digest("hex");
  return { ref: `refs/notes/clawsweeper-comment-claims/${key}`, identityDigest: key };
}

function validExisting(record, ref) {
  if (
    record?.ref !== ref ||
    record?.object?.type !== "commit" ||
    typeof record?.object?.sha !== "string" ||
    !SHA.test(record.object.sha)
  ) {
    throw new Error("unverifiable_comment_claim_ref");
  }
  return "already_claimed";
}

/**
 * getRef is a read-only operation and should return null only on exact HTTP
 * 404. createRef must perform at most ONE POST; errors are reconciled through
 * getRef and are never blindly retried.
 */
export async function claimCommentEffect(input, { getRef, createRef }) {
  const { ref } = buildClaim(input);
  ensureString(input.commitSha, SHA, "invalid_source_sha");
  const existing = await getRef(ref);
  if (existing) return validExisting(existing, ref);
  let posted;
  try {
    posted = await createRef(ref, input.commitSha);
  } catch {
    // The remote operation may have succeeded despite lost HTTP response.
    // A missing/unavailable readback is an uncertainty hold, not a retry.
    try {
      const after = await getRef(ref);
      if (after) return validExisting(after, ref);
    } catch {
      // Preserve uncertainty without disclosing provider diagnostics.
    }
    throw new Error("comment_claim_creation_uncertain");
  }
  if (
    !posted ||
    posted.ref !== ref ||
    posted.object?.sha !== input.commitSha ||
    posted.object?.type !== "commit"
  ) {
    throw new Error("comment_claim_creation_unverified");
  }
  const independent = await getRef(ref);
  if (
    !independent ||
    independent.ref !== ref ||
    independent.object?.sha !== input.commitSha ||
    independent.object?.type !== "commit"
  ) {
    throw new Error("comment_claim_readback_unverified");
  }
  return "claimed";
}

/** Complete bounded comment pagination; never turn partial visibility into absence. */
export async function findExistingCommentMarker(input, getPage, maxPages = 20) {
  const { repo, number, sourceId, effect } = input;
  buildClaim({ repo, number, sourceId, effect });
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 20) {
    throw new Error("invalid_comment_scan_bound");
  }
  const marker =
    effect === "pr_ack"
      ? new RegExp(
          `<!--\\s*clawsweeper-pr-ack:(?:opened|ready_for_review) item=${String(number)}\\s*-->`,
        )
      : new RegExp(`<!--\\s*clawsweeper-command-ack:${String(sourceId)}\\s*-->`);
  for (let page = 1; page <= maxPages; page++) {
    const comments = await getPage(page);
    if (!Array.isArray(comments) || comments.length > 100) {
      throw new Error("comment_inventory_unverifiable");
    }
    for (const comment of comments) {
      if (typeof comment?.body === "string" && marker.test(comment.body)) return "present";
    }
    if (comments.length < 100) return "absent";
  }
  throw new Error("comment_inventory_unbounded");
}

/** GitHub matching-refs explicitly covers non-branch refs such as notes. */
export function exactMatchingReference(ref, records) {
  if (!Array.isArray(records) || records.length > 25)
    throw new Error("unbounded_comment_claim_refs");
  const matches = records.filter((record) => record?.ref === ref);
  if (matches.length > 1) throw new Error("ambiguous_comment_claim_ref");
  return matches[0] || null;
}

function ghApi(method, endpoint, body) {
  const args = ["api", "--method", method, endpoint];
  if (body) args.push("--input", "-");
  try {
    const out = execFileSync("gh", args, {
      input: body ? JSON.stringify(body) : undefined,
      encoding: "utf8",
      maxBuffer: MAX_API_BYTES,
      timeout: 20_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return JSON.parse(out);
  } catch (error) {
    // Never include API response, environment or token in logged diagnostics.
    const diagnostic = String(error?.stderr ?? "");
    if (method === "GET" && /(?:HTTP 404|404 Not Found|Not Found \(404\))/.test(diagnostic))
      return null;
    // GitHub CLI stderr/cause may include tokens or URLs. Deliberately
    // discard the provider error rather than attach it to a public CI record.
    // eslint-disable-next-line preserve-caught-error -- Retaining provider errors could leak secrets.
    throw new Error("comment_claim_github_api_unavailable");
  }
}

export async function runClaimCLI(argv, env = process.env) {
  if (argv.length !== 5 || !env.GH_TOKEN) throw new Error("comment_claim_args_or_auth_missing");
  const [repo, number, sourceId, effect, commitSha] = argv;
  if (repo.toLowerCase() !== String(env.GITHUB_REPOSITORY ?? "").toLowerCase()) {
    throw new Error("comment_claim_repository_mismatch");
  }
  return claimCommentEffect(
    { repo, number, sourceId, effect, commitSha },
    {
      getRef: (ref) =>
        exactMatchingReference(
          ref,
          ghApi("GET", `repos/${repo}/git/matching-refs/${ref.substring(5)}`),
        ),
      createRef: (ref, sha) => ghApi("POST", `repos/${repo}/git/refs`, { ref, sha }),
    },
  );
}

export async function runScanCLI(argv, env = process.env) {
  if (argv.length !== 4 || !env.GH_TOKEN) throw new Error("comment_scan_args_or_auth_missing");
  const [repo, number, effect, sourceId] = argv;
  if (repo.toLowerCase() !== String(env.GITHUB_REPOSITORY ?? "").toLowerCase()) {
    throw new Error("comment_scan_repository_mismatch");
  }
  return findExistingCommentMarker({ repo, number, sourceId, effect }, (page) =>
    ghApi("GET", `repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`),
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const [command, ...args] = process.argv.slice(2);
    const result =
      command === "claim"
        ? await runClaimCLI(args)
        : command === "scan"
          ? await runScanCLI(args)
          : (() => {
              throw new Error("unknown_comment_claim_command");
            })();
    process.stdout.write(`${result}\n`);
  } catch {
    // No GitHub API stderr, headers, token or arbitrary payloads in output.
    process.stderr.write("comment_claim_unavailable\n");
    process.exitCode = 1;
  }
}

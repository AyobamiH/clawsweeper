#!/usr/bin/env node
/**
 * Audit a provider-exported Cloudflare Worker trace sample without echoing or
 * persisting any of its potentially sensitive attribute values.
 *
 * Content-only results are NEVER sufficient for production admission; account,
 * Worker version, source-bundle and independently witnessed collection still
 * require separate provider evidence.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_SPANS = 5000;
const SAFE_CANARY_PATHS = new Set(["/api/health", "/__local/trace-capability"]);
const SAFE_ATTRIBUTE_KEYS = new Set([
  "cloud.provider",
  "cloud.platform",
  "service.name",
  "faas.name",
  "faas.invocation_id",
  "faas.version",
  "faas.invoked_region",
  "cloudflare.colo",
  "cloudflare.script_name",
  "cloudflare.script_tags",
  "cloudflare.script_version.id",
  "http.request.method",
  "http.response.status_code",
  "http.route",
  "url.full",
  "url.path",
  "cache.request.url",
  "clawsweeper.source_revision_claim",
  "clawsweeper.module",
  "clawsweeper.route_family",
  "clawsweeper.trace_schema",
]);
const SENSITIVE_FIELDS = [
  /^url\.query$/,
  /^db\.query\.text$/,
  /^cloudflare\.kv\.query\.keys$/,
  /^cloudflare\.r2\.(?:object|query)\.key/,
  /^cloudflare\.durable_object\.id$/,
  /^cloudflare\.email\.(?:from|to)$/,
  /^cloudflare\.warning\.message$/,
  /^cloudflare\.(?:d1|kv|r2|durable_object)\./,
  /^http\.(?:request|response)\.header\./,
  /^exception\./,
  /^error\.(?:message|stack)$/,
  /^http\.request\.header\.authorization$/,
  /^http\.request\.header\.cookie$/,
];

function scalar(value) {
  if (value == null) return "";
  if (typeof value !== "object") return value;
  for (const key of ["stringValue", "intValue", "doubleValue", "boolValue", "value"]) {
    if (value[key] != null) return scalar(value[key]);
  }
  return JSON.stringify(value);
}
function attributesOf(value) {
  if (!value) return {};
  if (!Array.isArray(value)) return typeof value === "object" ? value : {};
  const items = Object.create(null);
  for (const attr of value) {
    if (typeof attr?.key !== "string") continue;
    items[attr.key] = scalar(attr.value);
  }
  return items;
}
export function spansFromProviderExport(input) {
  if (Array.isArray(input))
    return input.map((x) => ({ ...x, attributes: attributesOf(x.attributes) }));
  if (Array.isArray(input?.spans)) return spansFromProviderExport(input.spans);
  if (!Array.isArray(input?.resourceSpans)) throw Error("unrecognised_provider_trace_format");
  const all = [];
  for (const resource of input.resourceSpans) {
    const common = attributesOf(resource.resource?.attributes);
    for (const scope of resource.scopeSpans ?? []) {
      for (const span of scope.spans ?? []) {
        all.push({ ...span, attributes: { ...common, ...attributesOf(span.attributes) } });
      }
    }
  }
  return all;
}
const privateMarkers =
  /(synthetic-privacy-canary-secret|bearer\s+[\w.=-]{8,}|token=|authorization=|api[_-]?key=)/i;

function urlProblem(urlText) {
  try {
    const url = new URL(String(urlText));
    if (url.search || url.hash) return "query_or_fragment_present";
    if (!SAFE_CANARY_PATHS.has(url.pathname)) return "url_path_outside_public_canary";
    return null;
  } catch {
    return "unparseable_url";
  }
}
export function auditNativeTracePrivacy(input, options = {}) {
  const spans = spansFromProviderExport(input);
  if (spans.length === 0 || spans.length > MAX_SPANS)
    throw Error("empty_or_unbounded_trace_sample");
  const findings = [];
  let custom = 0;
  let automatic = 0;
  let withVersion = 0;
  const seenNames = new Set();
  for (let index = 0; index < spans.length; index++) {
    const span = spans[index];
    const name = String(span.name || "");
    const attributes = attributesOf(span.attributes);
    // Check the *entire* span name before abbreviating it anywhere; a long
    // route name must not conceal a sensitive suffix beyond 100 characters.
    if (
      privateMarkers.test(name) ||
      name.includes("?") ||
      name.length > 120 ||
      /\b(?:GET|POST|PUT|PATCH|DELETE)\s+\//.test(name)
    )
      findings.push({ index, code: "sensitive_span_name", attribute: null });
    const approvedCustom =
      name === "clawsweeper.http.health" || name === "clawsweeper.cron.health_sample";
    const approvedAutomatic = name === "fetch handler" || name === "fetch";
    if (!approvedCustom && !approvedAutomatic)
      findings.push({ index, code: "unreviewed_span_name", attribute: null });
    if (name.startsWith("clawsweeper.")) custom++;
    else automatic++;
    seenNames.add(name);
    const version = attributes["cloudflare.script_version.id"];
    if (version && version === options.expectedVersionId) withVersion++;
    if (
      options.expectedScriptName &&
      attributes["cloudflare.script_name"] &&
      attributes["cloudflare.script_name"] !== options.expectedScriptName
    ) {
      findings.push({ index, code: "wrong_worker_identity", attribute: "cloudflare.script_name" });
    }
    for (const [key, value] of Object.entries(attributes)) {
      if (
        SENSITIVE_FIELDS.some((pattern) => pattern.test(key)) &&
        value !== "" &&
        value !== undefined
      ) {
        findings.push({ index, code: "sensitive_auto_attribute_present", attribute: key });
        continue;
      }
      if (!SAFE_ATTRIBUTE_KEYS.has(key)) {
        findings.push({ index, code: "unreviewed_platform_attribute", attribute: null });
        continue;
      }
      if (key === "url.full" || key === "cache.request.url") {
        const reason = urlProblem(value);
        if (reason) findings.push({ index, code: reason, attribute: key });
      }
      if ((key === "url.path" || key === "http.route") && !SAFE_CANARY_PATHS.has(String(value))) {
        findings.push({ index, code: "sensitive_or_unexpected_url_path", attribute: key });
      }
      if (privateMarkers.test(String(value))) {
        findings.push({ index, code: "privacy_probe_marker_present", attribute: key });
      }
    }
  }
  if (!custom) findings.push({ code: "custom_source_span_missing", attribute: null });
  if (!automatic) findings.push({ code: "automatic_platform_span_missing", attribute: null });
  if (options.expectedVersionId && withVersion === 0)
    findings.push({
      code: "provider_worker_version_unobserved",
      attribute: "cloudflare.script_version.id",
    });

  return {
    schema: "clawsweeper-trace-privacy-content-audit/v1",
    state: findings.length === 0 ? "CONTENT_PASS_NOT_PROVIDER_AUTHENTICATED" : "HOLD",
    spanCount: spans.length,
    automaticSpanCount: automatic,
    customSpanCount: custom,
    versionBoundSpanCount: withVersion,
    distinctSpanNameCount: seenNames.size,
    findingCounts: findings.reduce((acc, f) => {
      acc[f.code] = (acc[f.code] || 0) + 1;
      return acc;
    }, {}),
    findings,
    limitation:
      "Even CONTENT_PASS is not production privacy approval. Provider-authenticated source/version and genuine automatic spans from an isolated canary must be independently verified; sensitive operation paths remain excluded.",
  };
}

const self = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (self) {
  const filepath = process.argv[2];
  if (!filepath)
    throw Error("usage: node scripts/audit-native-trace-privacy.mjs <provider-export.json>");
  const stat = fs.statSync(filepath);
  if (!stat.isFile() || stat.size > MAX_BYTES) throw Error("trace_export_too_large");
  const bytes = fs.readFileSync(filepath);
  const input = JSON.parse(bytes.toString("utf8"));
  // No raw attribute values are written or printed.
  const report = auditNativeTracePrivacy(input, {
    expectedScriptName: process.env.CLAWSWEEPER_TRACE_EXPECTED_SCRIPT || undefined,
    expectedVersionId: process.env.CLAWSWEEPER_TRACE_EXPECTED_VERSION || undefined,
  });
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  console.log(JSON.stringify({ ...report, inputSha256: digest }, null, 2));
  if (report.state !== "CONTENT_PASS_NOT_PROVIDER_AUTHENTICATED") process.exitCode = 2;
}

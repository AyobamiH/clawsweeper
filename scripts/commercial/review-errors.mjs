// Bounded, sanitised release error taxonomy. Never include provider bodies,
// prompts, model output, tokens, URLs or arbitrary exception messages.
export const REVIEW_ERROR_CODES = Object.freeze({
  PROVIDER_NETWORK: "provider_network",
  PROVIDER_HTTP: "provider_http",
  PROVIDER_RESPONSE: "provider_response",
  PROVIDER_INCOMPLETE: "provider_incomplete",
  PROVIDER_JSON: "provider_json",
  PROVIDER_SCHEMA: "provider_schema",
  FINDING_UNBOUND: "unbound_finding",
  REVIEW_INCOMPLETE: "review_incomplete",
  PREFLIGHT: "preflight_refused",
  UNEXPECTED: "unexpected_error",
});
export class ReviewFailure extends Error {
  constructor(code, { phase = "inference", retryEligible = false, statusClass = null } = {}) {
    if (!Object.values(REVIEW_ERROR_CODES).includes(code))
      throw new TypeError("invalid review failure code");
    super(`Review refused: ${code}`);
    this.name = "ReviewFailure";
    this.code = code;
    this.phase = phase;
    this.retryEligible = retryEligible;
    this.statusClass = statusClass;
  }
}
export function classifyReviewFailure(error) {
  if (error instanceof ReviewFailure)
    return {
      category: error.code,
      phase: error.phase,
      retryEligible: error.retryEligible,
      ...(error.statusClass ? { statusClass: error.statusClass } : {}),
    };
  if (error?.name === "SourceFindingError")
    return {
      category: "unbound_finding",
      reason: error.reason,
      ...error.context,
      retryEligible: false,
    };
  return { category: "unexpected_error", retryEligible: false };
}

export type ProviderUsage = {
  inputTokens?: number;
  outputTokens?: number;
  cachedInputTokens?: number;
};
function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
function counter(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}
function fields(input: unknown, output: unknown, cached: unknown): ProviderUsage | undefined {
  const inputTokens = counter(input);
  const outputTokens = counter(output);
  const cachedInputTokens = counter(cached);
  if (inputTokens === undefined && outputTokens === undefined && cachedInputTokens === undefined)
    return undefined;
  return {
    ...(inputTokens === undefined ? {} : { inputTokens }),
    ...(outputTokens === undefined ? {} : { outputTokens }),
    ...(cachedInputTokens === undefined ? {} : { cachedInputTokens }),
  };
}
export function structuredProviderUsage(value: unknown): ProviderUsage | undefined {
  const row = record(value);
  return row ? fields(row.inputTokens, row.outputTokens, row.cachedInputTokens) : undefined;
}
export function codexJsonlUsage(stdout: string): ProviderUsage | undefined {
  if (Buffer.byteLength(stdout) > 256 * 1024) return undefined;
  const totals: ProviderUsage = {};
  let observed = false;
  for (const line of stdout.split(/\r?\n/)) {
    let event: Record<string, unknown> | null;
    try {
      event = record(JSON.parse(line));
    } catch {
      continue;
    }
    // Never inspect agent-message text, prompts or arbitrary usage claims.
    if (event?.type !== "turn.completed") continue;
    const usage = record(event.usage);
    if (!usage) continue;
    const counts = fields(usage.input_tokens, usage.output_tokens, usage.cached_input_tokens);
    if (!counts) continue;
    observed = true;
    for (const key of ["inputTokens", "outputTokens", "cachedInputTokens"] as const) {
      if (counts[key] !== undefined) {
        const sum = (totals[key] ?? 0) + counts[key];
        if (!Number.isSafeInteger(sum)) return undefined;
        totals[key] = sum;
      }
    }
  }
  return observed ? totals : undefined;
}
export function openclawEnvelopeUsage(envelope: unknown): ProviderUsage | undefined {
  const root = record(envelope);
  const result = record(root?.result) ?? root;
  const meta = record(result?.meta);
  const agentMeta = record(meta?.agentMeta);
  const usage = record(agentMeta?.usage);
  // OpenClaw metadata, not payload text. Cache-read remains separate because
  // providers may already include it in input: never add it to billing totals.
  return usage ? fields(usage.input, usage.output, usage.cacheRead) : undefined;
}

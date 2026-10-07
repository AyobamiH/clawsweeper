import assert from "node:assert/strict";
import test from "node:test";
import { repairDispatchAuthorizationInputs } from "../../dist/repair/repair-dispatch-authorization.js";

test("repair dispatch passes bounded execution authority for a classified maintainer or bot", () => {
  for (const command of [
    { maintainer_authorized: true },
    { trusted_bot: true },
    { maintainer_authorized: true, trusted_bot: true },
  ]) {
    assert.deepEqual(repairDispatchAuthorizationInputs(command), [
      "-f",
      "authorize_execute=true",
      "-f",
      "authorize_fix_pr=true",
    ]);
  }
});

test("repair dispatch rejects missing, false and merely truthy authority", () => {
  for (const command of [
    {},
    { maintainer_authorized: false, trusted_bot: false },
    { maintainer_authorized: "true" },
    { trusted_bot: "true" },
    { maintainer_authorized: 1, trusted_bot: 1 },
    { maintainer_authorized: null, trusted_bot: {} },
  ]) {
    assert.throws(
      () => repairDispatchAuthorizationInputs(command),
      /requires maintainer authorization/,
    );
  }
});

test("repair authority is returned independently for each dispatch and never grants merge", () => {
  const first = repairDispatchAuthorizationInputs({ maintainer_authorized: true });
  first.push("mutated-by-caller");
  const next = repairDispatchAuthorizationInputs({ maintainer_authorized: true });
  assert.equal(next.includes("mutated-by-caller"), false);
  assert.equal(
    next.some((input) => /merge|CLOUDFLARE|TOKEN/.test(input)),
    false,
  );
});

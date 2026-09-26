import assert from "node:assert/strict";
import { createHmac, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { emptyQuota, quotaTransition, quotaView } from "../dashboard/subscription-quota.ts";
const root = mkdtempSync(join(tmpdir(), "clawsweeper-quota-proof-"));
const db = new DatabaseSync(join(root, "quota.sqlite"));
db.exec("CREATE TABLE quota (id INTEGER PRIMARY KEY, value TEXT)");
let clock = Date.now();
const secret = "isolated-proof-only";
const server = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  const expected = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  const supplied = String(req.headers["x-clawsweeper-exact-review-signature"] || "");
  if (
    supplied.length !== expected.length ||
    !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
  ) {
    res.writeHead(401);
    res.end();
    return;
  }
  try {
    const stored = db.prepare("SELECT value FROM quota WHERE id=1").get();
    const state = stored ? JSON.parse(stored.value) : emptyQuota();
    const parsed = JSON.parse(body);
    parsed.sentAt = clock;
    const result = quotaTransition(state, parsed, clock);
    db.prepare("INSERT OR REPLACE INTO quota VALUES (1, ?)").run(JSON.stringify(result.state));
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(result.response));
  } catch {
    res.writeHead(400);
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const calls = join(root, "calls");
const codex = join(root, "codex");
writeFileSync(
  codex,
  `#!${process.execPath}
const fs = require('node:fs');
if(process.argv.includes('app-server')) {
 let buffer=''; process.stdin.on('data', c => { buffer+=c; let i; while((i=buffer.indexOf('\\n'))>=0){ const m=JSON.parse(buffer.slice(0,i));buffer=buffer.slice(i+1);
 if(m.id===1) console.log(JSON.stringify({id:1,result:{}}));
 if(m.id===2) console.log(JSON.stringify({id:2,result:{rateLimits:{limitId:'codex',primary:{usedPercent:20,windowDurationMins:300,resetsAt:Math.floor(Date.now()/1000)+20000}}}}));
 }});
} else { fs.appendFileSync(${JSON.stringify(calls)},'1'); console.log('synthetic model completed'); }
`,
  { mode: 0o700 },
);
const env = {
  ...process.env,
  CODEX_BIN: codex,
  CLAWSWEEPER_QUOTA_ENABLED: "1",
  CLAWSWEEPER_QUOTA_URL: `http://127.0.0.1:${server.address().port}`,
  CLAWSWEEPER_QUOTA_SECRET: secret,
};
const invoke = () =>
  new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import {runCodexProcess} from ${JSON.stringify(new URL("../dist/codex-process.js", import.meta.url).href)}; console.log(JSON.stringify(runCodexProcess({args:['exec','-'],cwd:${JSON.stringify(root)},env:process.env,input:'fixture',timeoutMs:30000})));`,
      ],
      { env },
    );
    let output = "";
    child.stdout.on("data", (c) => (output += c));
    child.stderr.on("data", () => {});
    child.on("error", reject);
    child.on("close", () => resolvePromise(JSON.parse(output)));
  });
try {
  const first = await invoke();
  assert.equal(first.status, 0);
  const stored = JSON.parse(db.prepare("SELECT value FROM quota WHERE id=1").get().value);
  const exhausted = quotaTransition(stored, { action: "exhausted", sentAt: clock }, clock);
  db.prepare("UPDATE quota SET value=? WHERE id=1").run(JSON.stringify(exhausted.state));
  const blocked = await Promise.all([invoke(), invoke()]);
  assert.ok(blocked.every((r) => r.status === 1 && r.stderr.includes("fleet cooldown")));
  assert.equal(readFileSync(calls, "utf8"), "1");
  clock = exhausted.state.blockedUntil + 1;
  const recovered = await invoke();
  assert.equal(recovered.status, 0);
  assert.equal(readFileSync(calls, "utf8"), "11");
  const report = {
    scenario: "two repository processes, shared persistent SQLite quota",
    firstStarts: 1,
    blockedConcurrentStarts: 0,
    afterResetStarts: 1,
    state: quotaView(
      JSON.parse(db.prepare("SELECT value FROM quota WHERE id=1").get().value),
      clock,
    ),
    limits:
      "Real HTTP/HMAC, SQLite, app-server protocol and native process guard. Synthetic allowance/model executables and controlled clock; no live quota exhaustion or production queue mutation.",
  };
  const output = process.argv[2] || join(root, "proof.json");
  writeFileSync(resolve(output), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report));
} finally {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  rmSync(root, { recursive: true, force: true });
}

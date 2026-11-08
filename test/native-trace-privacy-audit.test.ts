import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {auditNativeTracePrivacy,spansFromProviderExport} from "../scripts/audit-native-trace-privacy.mjs";

const VERSION="26dcfdda-a4c4-439e-b83f-46aa4d57ed9e";
const WORKER="clawsweeper-source-trace-local-only";
const attr=(key:string,stringValue:string)=>({key,value:{stringValue}});
const providerFixture=()=>({
 resourceSpans:[{
  resource:{attributes:[attr("cloudflare.script_name",WORKER),attr("cloudflare.script_version.id",VERSION)]},
  scopeSpans:[{scope:{name:"cloudflare"},spans:[
    {name:"fetch handler",attributes:[
      attr("url.full","https://local.example/api/health"),
      attr("url.path","/api/health"),
      attr("http.request.method","GET"),
    ]},
    {name:"clawsweeper.http.health",attributes:[
      attr("clawsweeper.module","dashboard/worker.ts"),
      attr("clawsweeper.route_family","http.health"),
    ]},
  ]}],
 }],
});

test("synthetic provider-shaped automatic and custom spans pass *content-only* checks",()=>{
 const sample=providerFixture();
 assert.equal(spansFromProviderExport(sample).length,2);
 const report=auditNativeTracePrivacy(sample,{
  expectedScriptName:WORKER,expectedVersionId:VERSION,
 });
 assert.equal(report.state,"CONTENT_PASS_NOT_PROVIDER_AUTHENTICATED");
 assert.equal(report.spanCount,2);
 assert.equal(report.automaticSpanCount,1);
 assert.equal(report.customSpanCount,1);
 assert.equal(report.versionBoundSpanCount,2);
 assert.equal(report.findings.length,0);
 assert.match(report.limitation,/not production privacy approval/);
});

test("query string redaction failure is detected in automatic url.full and url.query",()=>{
 const fixture=providerFixture();
 const spans=fixture.resourceSpans[0]!.scopeSpans[0]!.spans;
 spans[0]!.attributes[0]!.value.stringValue="https://local.example/api/health?token=synthetic-privacy-canary-secret";
 spans[0]!.attributes.push(attr("url.query","token=synthetic-privacy-canary-secret"));
 const report=auditNativeTracePrivacy(fixture,{expectedVersionId:VERSION});
 assert.equal(report.state,"HOLD");
 assert.ok(report.findingCounts["sensitive_auto_attribute_present"]>=1);
 assert.ok(report.findingCounts["query_or_fragment_present"]>=1);
});

test("storage, cache, unexpected path and free-form warning metadata fail closed",()=>{
 const fixture=providerFixture();
 const spans=fixture.resourceSpans[0]!.scopeSpans[0]!.spans;
 spans[0]!.attributes.push(
  attr("cache.request.url","https://local.example/private?id=123"),
  attr("db.query.text","SELECT * FROM sensitive_customer_data"),
  attr("cloudflare.kv.query.keys","secret-account-name"),
  attr("cloudflare.warning.message","unexpected data: private"),
  attr("url.path","/private/customer/secret-id"),
 );
 const result=auditNativeTracePrivacy(fixture,{expectedVersionId:VERSION});
 assert.equal(result.state,"HOLD");
 assert.ok(result.findingCounts["sensitive_auto_attribute_present"]>=3);
 assert.ok(result.findingCounts["sensitive_or_unexpected_url_path"]>=1);
});

test("no automatic or no custom span must not be deemed privacy-verified",()=>{
 const sample=providerFixture();
 sample.resourceSpans[0]!.scopeSpans[0]!.spans.splice(1);
 assert.equal(auditNativeTracePrivacy(sample).state,"HOLD");
 sample.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.name="clawsweeper.http.health";
 assert.equal(auditNativeTracePrivacy(sample).state,"HOLD");
});

test("CLI prints digests, counts and attribute names, not private trace values",()=>{
 const sample=providerFixture();
 sample.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes[0]!.value.stringValue=
  "https://local.example/api/health?token=synthetic-privacy-canary-secret";
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),"clawsweeper-trace-privacy-"));
 try{
  const file=path.join(tmp,"input.json");
  fs.writeFileSync(file,JSON.stringify(sample));
  const child=spawnSync(process.execPath,[
    new URL("../scripts/audit-native-trace-privacy.mjs",import.meta.url).pathname,file,
  ],{encoding:"utf8",timeout:10000});
  assert.equal(child.status,2);
  assert.ok(child.stdout.includes("HOLD"));
  assert.ok(child.stdout.includes("inputSha256"));
  assert.ok(!child.stdout.includes("synthetic-privacy-canary-secret"));
  assert.ok(!child.stdout.includes("token="));
 }finally{fs.rmSync(tmp,{recursive:true,force:true})}
});

test("unknown platform attributes fail closed even if their names look innocuous",()=>{
 const fixture=providerFixture();
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes.push(
  attr("cloudflare.experimental.private_caller","person-identity-value"),
 );
 const report=auditNativeTracePrivacy(fixture,{expectedVersionId:VERSION});
 assert.equal(report.state,"HOLD");
 assert.ok(report.findingCounts["unreviewed_platform_attribute"]>=1);
 assert.ok(!JSON.stringify(report).includes("person-identity-value"));
});

test("a sensitive span name cannot evade attribute filtering",()=>{
 const fixture=providerFixture();
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.name="GET /api/health?token=synthetic-privacy-canary-secret";
 const report=auditNativeTracePrivacy(fixture);
 assert.equal(report.state,"HOLD");
 assert.ok(report.findingCounts["sensitive_span_name"]>=1);
 assert.ok(!JSON.stringify(report).includes("synthetic-privacy-canary-secret"));
});

test("production Wrangler config leaves traces off and sets query redaction",()=>{
 const config=fs.readFileSync(new URL("../dashboard/wrangler.toml",import.meta.url),"utf8");
 assert.match(config,/\[observability\]\s*redact_query_string\s*=\s*true/);
 assert.match(config,/\[observability\.traces\]\s*enabled\s*=\s*false/);
 assert.match(config,/head_sampling_rate\s*=\s*0\.005/);
});

test("privacy report never echoes an attacker-supplied attribute key",()=>{
 const fixture=providerFixture();
 const secretKey="synthetic-privacy-canary-secret";
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes.push(attr(secretKey,"hidden"));
 const result=auditNativeTracePrivacy(fixture);
 assert.equal(result.state,"HOLD");
 assert.ok(result.findingCounts["unreviewed_platform_attribute"]>=1);
 assert.ok(!JSON.stringify(result).includes(secretKey));
});

test("private route names beyond the first 100 characters cannot hide tokens",()=>{
 const fixture=providerFixture();
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.name="x".repeat(130)+"/private?token=synthetic-privacy-canary-secret";
 const result=auditNativeTracePrivacy(fixture);
 assert.equal(result.state,"HOLD");
 assert.ok(result.findingCounts["sensitive_span_name"]>=1);
 assert.ok(!JSON.stringify(result).includes("synthetic-privacy-canary-secret"));
});

test("unknown automatic span names require explicit review before content acceptance",()=>{
 const fixture=providerFixture();
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.name="cache_put /private/account";
 const result=auditNativeTracePrivacy(fixture);
 assert.equal(result.state,"HOLD");
 assert.ok(result.findingCounts["unreviewed_span_name"]>=1);
});

test("unexpected dynamic http.route paths are not considered privacy-bounded",()=>{
 const fixture=providerFixture();
 fixture.resourceSpans[0]!.scopeSpans[0]!.spans[0]!.attributes.push(attr("http.route","/internal/exact-review/private-id"));
 const result=auditNativeTracePrivacy(fixture);
 assert.equal(result.state,"HOLD");
 assert.ok(result.findingCounts["sensitive_or_unexpected_url_path"]>=1);
});

test("provider spans with an unexpected version cannot pass the canary content audit",()=>{
 const sample=providerFixture();
 const report=auditNativeTracePrivacy(sample,{
  expectedVersionId:"deadbeef-a11f-4ddd-abcd-40303a000000",
  expectedScriptName:WORKER,
 });
 assert.equal(report.state,"HOLD");
 assert.ok(report.findingCounts["provider_worker_version_unobserved"]>=1);
});

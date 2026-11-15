import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {spawnSync,execFileSync} from "node:child_process";
import {appendFileSync,copyFileSync,existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import {test} from "node:test";
import {fileURLToPath} from "node:url";
import {runtimeDigests} from "../../dist/repair/ci-triage-runtime.js";
import {runtimeDigests as bootstrapDigests} from "../../scripts/analysis/ci-triage-preimport.mjs";

const project=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
function fixture(){
 const root=mkdtempSync(join(tmpdir(),"triage-preimport-"));
 const git=(...args)=>execFileSync("git",["-C",root,...args],
  {encoding:"utf8",stdio:["ignore","pipe","pipe"],
   env:{...process.env,GIT_CONFIG_GLOBAL:"/dev/null"}}).trim();
 git("init","-q");
 writeFileSync(join(root,"tracked.txt"),"signed-source-fixture\n");
 git("add","tracked.txt");
 git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
     "-c","commit.gpgsign=false","commit","-qm","fixture");
 const source=git("rev-parse","HEAD");
 writeFileSync(join(root,"package.json"),'{"type":"module"}\n');
 mkdirSync(join(root,"config"),{recursive:true});
 copyFileSync(join(project,"config/automation-limits.json"),
              join(root,"config/automation-limits.json"));
 const original=runtimeDigests(project);
 for(const file of Object.keys(original)){
  mkdirSync(dirname(join(root,file)),{recursive:true});
  copyFileSync(join(project,file),join(root,file));
 }
 const bootRel="scripts/analysis/ci-triage-preimport.mjs";
 mkdirSync(dirname(join(root,bootRel)),{recursive:true});
 copyFileSync(join(project,bootRel),join(root,bootRel));
 const boot=join(root,bootRel);
 const pin=createHash("sha256").update(readFileSync(boot)).digest("hex");
 const privateDir=join(root,"private");
 mkdirSync(privateDir,{mode:0o700});
 const manifest=join(privateDir,"runtime.json");
 writeFileSync(manifest,JSON.stringify({
  schema:"clawsweeper.ci-triage-runtime.v3",implementationSha:source,files:runtimeDigests(root),
  sourceBuild:{schema:"clawsweeper.ci-triage-build.v1",sourceSha:source,
    runtimeFilesSha256:createHash("sha256").update(JSON.stringify(runtimeDigests(root))).digest("hex"),
    emittedFilesSha256:"a".repeat(64),toolchain:{typescriptVersion:"7.0.2",
    compilerSha256:"b".repeat(64),nativeCompilerSha256:"d".repeat(64),lockfileSha256:"c".repeat(64)}}
 }),{mode:0o600});
 const env={...process.env,CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA:source,
   CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256:pin,
   CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST:manifest};
 const run=(mode="observer",args=["--help"],extra={})=>spawnSync(process.execPath,
   [boot,mode,...args],{env:{...env,...extra},encoding:"utf8",timeout:60000});
 return {root,source,boot,manifest,env,run,cleanup:()=>rmSync(root,{recursive:true,force:true})};
}
test("builtins-only bootstrap executes verified observer help",()=>{
 const f=fixture();try{
  const out=f.run();
  assert.equal(out.status,0,out.stderr);
  assert.match(out.stdout,/observe-ci-triage/);
 }finally{f.cleanup();}
});
test("tampered transitive ESM config refuses BEFORE import-time side effects",()=>{
 const f=fixture();try{
  const marker=join(f.root,"MUST_NOT_RUN");
  appendFileSync(join(f.root,"dist/repair/config.js"),
    "\nimport {writeFileSync} from 'node:fs';\nwriteFileSync("+JSON.stringify(marker)+",'violated');\n");
  const out=f.run();
  assert.notEqual(out.status,0);
  assert.match(out.stderr,/preimport_(runtime_changed|build_provenance)/);
  assert.equal(existsSync(marker),false);
  const notifier=f.run("notifier",[]);
  assert.notEqual(notifier.status,0);
  assert.equal(existsSync(marker),false);
 }finally{f.cleanup();}
});
test("missing manifest, invalid bootstrap pin, mismatched signed source all refuse before application load",()=>{
 const f=fixture();try{
  const cases=[
    {CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST:"/not/found"},
    {CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256:"0".repeat(64)},
    {CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA:"0".repeat(40)}
  ];
  for(const override of cases){
   const out=f.run("observer",["--help"],override);
   assert.notEqual(out.status,0);
   assert.match(out.stderr,/preimport_/);
  }
 }finally{f.cleanup();}
});

test("both closure scanners reject valid but unparsed static ESM import forms",()=>{
 const f=fixture();
 try{
  const target=join(f.root,"dist/repair/observe-ci-triage.js");
  const original=readFileSync(target,"utf8");
  writeFileSync(join(f.root,"dist/repair/unlisted.js"),"globalThis.unlistedExecuted=true;\n");
  const cases=[
   "import/*gap*/\"./unlisted.js\";",
   "import\"./unlisted.js\";",
   "export*from\"./unlisted.js\";",
   'import\n"./unlisted.js";',
   'export\n*from"./unlisted.js";',
   'const x=1;import "./unlisted.js";',
   'const x=1;export * from "./unlisted.js";',
  ];
  for(const statement of cases){
   writeFileSync(target,original+"\n"+statement+"\n");
   assert.throws(()=>runtimeDigests(f.root),/implementation_runtime_import_unsupported/,statement);
   assert.throws(()=>bootstrapDigests(f.root),/preimport_import/,statement);
  }
 }finally{f.cleanup();}
});

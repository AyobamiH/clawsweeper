import test from "node:test";
import assert from "node:assert/strict";
import worker from "../dashboard/worker.ts";

const sourceSha="03d32fb784758d2a3770aaa9721f1212ac061096";

test("real Worker health handler is observationally equivalent with tracing on/off", async()=>{
  const envBase={CLAWSWEEPER_DEPLOY_SHA:sourceSha};
  const plain=await worker.fetch(
    new Request("https://clawsweeper-status.example/api/health?private=not-for-telemetry"),
    {...envBase,CLAWSWEEPER_ARCH_TRACE_ENABLED:"0"},
  );
  const seen:Array<{name:string;attributes:Record<string,unknown>}>=[];

  const context={
    tracing:{
      enterSpan<T>(name:string,fn:(span:{setAttribute:(name:string,value:unknown)=>void})=>T){
        const attributes:Record<string,unknown>={};
        seen.push({name,attributes});
        return fn({setAttribute:(name,value)=>{attributes[name]=value}});
      },
    },
  };
  const traced=await worker.fetch(
    new Request("https://clawsweeper-status.example/api/health?private=not-for-telemetry"),
    {...envBase,CLAWSWEEPER_ARCH_TRACE_ENABLED:"1"},
    context,
  );
  assert.equal(traced.status,plain.status);
  assert.equal(traced.headers.get("content-type"),plain.headers.get("content-type"));
  assert.equal(await traced.text(),await plain.text());
  assert.equal(seen.length,1);
  assert.equal(seen[0]!.name,"clawsweeper.http.health");
  assert.deepEqual(seen[0]!.attributes,{
    "clawsweeper.source_revision_claim":sourceSha,
    "clawsweeper.module":"dashboard/worker.ts",
    "clawsweeper.route_family":"http.health",
    "clawsweeper.trace_schema":"clawsweeper-native-workers-tracing/v1",
  });
  assert.ok(!JSON.stringify(seen).includes("not-for-telemetry"));
});

test("real Worker does not create a span for unknown health-like routes",async()=>{
  let count=0;
  const context={
    tracing:{
      enterSpan<T>(_name:string,fn:(span:{setAttribute:(name:string,value:unknown)=>void})=>T){
        count++;return fn({setAttribute:()=>undefined});
      },
    },
  };
  const response=await worker.fetch(
    new Request("https://clawsweeper-status.example/api/health-not-a-route",{
      method:"GET",
    }),
    {CLAWSWEEPER_DEPLOY_SHA:sourceSha,CLAWSWEEPER_ARCH_TRACE_ENABLED:"1"},
    context,
  );
  assert.equal(response.status,404);
  assert.equal(count,0);
});

import { getSandbox } from '@cloudflare/sandbox';
export { Sandbox } from '@cloudflare/sandbox';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') {
      return Response.json({service:'clawsweeper-compute', repairEnabled:false});
    }
    if (!env.PROBE_TOKEN || request.headers.get('Authorization') !== `Bearer ${env.PROBE_TOKEN}`) {
      return new Response('Unauthorized', {status:401});
    }
    if (url.pathname !== '/probe' || request.method !== 'POST') {
      return new Response('Not found', {status:404});
    }
    const sandbox = getSandbox(env.Sandbox, 'capability-proof', {sleepAfter:'2m'});
    try {
      const result = await sandbox.exec('node /opt/clawsweeper/dist/repair/containment-preflight.js', {timeout:60000});
      return Response.json({exitCode:result.exitCode, stdout:result.stdout, stderr:result.stderr, repairEnabled:false});
    } finally {
      await sandbox.destroy();
    }
  }
};

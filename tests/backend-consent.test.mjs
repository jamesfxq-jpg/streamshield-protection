import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
import { webcrypto } from 'node:crypto';

const origin='https://streamshield-protection-public.vercel.app';
const base='https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend';
const source=fs.readFileSync(new URL('../supabase/functions/streamshield-backend/index.ts',import.meta.url),'utf8').replace(/^import "jsr:[^\n]+\n/,'');
const calls=[];
let recordResult={id:'fixture-request',status:'verified'};
const pending={id:'fixture-request',status:'pending',broadcaster_id:101,kick_user_id:202};
const context=vm.createContext({
  Request,Response,Headers,URL,URLSearchParams,TextEncoder,TextDecoder,Uint8Array,Date,JSON,Number,Math,Map,Set,atob,btoa,
  crypto:webcrypto,console,
  fetch:async()=>{throw new Error('Unexpected network call in isolated test');},
  Deno:{env:{get:()=>''},serve:handler=>{context.handler=handler;}},
  mockRpc:async(name,args)=>{
    calls.push({type:'rpc',name,args});
    if(name==='streamshield_network_status') return {enabled:true};
    if(name==='streamshield_verification_get_by_token') return {...pending};
    if(name==='streamshield_verification_record_result') return recordResult;
    return {};
  },
  mockRest:async(path,options={})=>{calls.push({type:'rest',path,options});return Response.json([]);},
});
vm.runInContext(stripTypeScriptTypes(source),context);
vm.runInContext(`
  rpc=mockRpc; rest=mockRest;
  getAppCreds=async()=>({clientId:'fixture-client',clientSecret:'fixture-secret'});
  verifyKick=async()=>true; cleanupExpired=async()=>{};
  authorizeInstall=async()=>false;
  exchangeCode=async()=>({access_token:'fixture-access'});
  kickGet=async()=>({data:[{user_id:202,name:'fixture-viewer'}]});
`,context);
const resultStatus=r=>new URL(r.headers.get('location')).searchParams.get('status');
const target='fixture_request_token_0123456789abcdef';
const post=(url,body='consent=yes',requestOrigin=origin)=>new Request(url,{method:'POST',headers:{origin:requestOrigin,'content-type':'application/x-www-form-urlencoded'},body});

let r=await context.handler(new Request(base+'/network/start?broadcaster_id=101'));
assert.equal(r.status,303); assert.equal(new URL(r.headers.get('location')).origin,origin);
assert.equal(new URL(r.headers.get('location')).pathname,'/verify');
assert.equal(calls.length,0,'GET consent page must not observe a network or start OAuth');
r=await context.handler(post(base+'/network/start?broadcaster_id=101','consent=yes','https://untrusted.example'));
assert.equal(resultStatus(r),'400'); assert.equal(calls.length,0);
r=await context.handler(post(base+'/network/start?broadcaster_id=101','consent=no'));
assert.equal(resultStatus(r),'400');
r=await context.handler(post(base+'/network/start?broadcaster_id=101'));
let authorization=new URL(r.headers.get('location'));
assert.equal(authorization.origin,'https://id.kick.com');
let state=await context.unseal(authorization.searchParams.get('state'),'fixture-secret');
assert.equal(state.viewer_consent,true); assert.equal(state.flow,'network_gate');

r=await context.handler(new Request(base+'/verification/start?request='+target));
assert.equal(new URL(r.headers.get('location')).pathname,'/verify');
assert.equal(r.headers.get('set-cookie'),null,'No device cookie before explicit consent');
r=await context.handler(new Request(base+'/verification/kick?request='+target));
assert.equal(new URL(r.headers.get('location')).pathname,'/verify','Old direct GET must require consent');
r=await context.handler(post(base+'/verification/kick?request='+target));
const receiptUrl=r.headers.get('location');
assert.equal(new URL(receiptUrl).origin,new URL(base).origin);
assert.ok(new URL(receiptUrl).searchParams.get('consent_ticket'));
assert.equal(r.headers.get('set-cookie'),null,'Cross-site POST must not replace an existing Lax cookie');
const device='fixture_existing_browser_token_0123456789abcdef';
r=await context.handler(new Request(receiptUrl,{headers:{cookie:'ss_device='+device}}));
authorization=new URL(r.headers.get('location'));
assert.equal(authorization.origin,'https://id.kick.com');
assert.ok(r.headers.get('set-cookie').startsWith('ss_device='+device+';'));
state=await context.unseal(authorization.searchParams.get('state'),'fixture-secret');
assert.equal(state.viewer_consent,true);

recordResult=null;
r=await context.handler(new Request(base+'/oauth/kick/callback?code=fixture&state='+authorization.searchParams.get('state'),{headers:{cookie:'ss_device='+device,'cf-connecting-ip':'192.0.2.42'}}));
assert.equal(resultStatus(r),'410','A cancelled request must never promise automatic unlock');
assert.ok(new URL(r.headers.get('location')).searchParams.get('message').includes('newer moderation decision'));

calls.length=0;
const payload={broadcaster:{user_id:101,username:'fixture-channel'},banned_user:{user_id:202,username:'fixture-viewer'},metadata:{created_at:new Date(Date.now()-1000).toISOString(),expires_at:null,reason:'fixture'}};
const webhook=body=>new Request(base+'/kick-webhook',{method:'POST',headers:{'kick-event-message-id':'fixture-message','kick-event-message-timestamp':new Date().toISOString(),'kick-event-signature':'fixture','kick-event-type':'moderation.banned'},body:JSON.stringify(body)});
r=await context.handler(webhook(payload));
assert.equal(r.status,204);
const event=JSON.parse(calls.find(c=>c.type==='rest'&&c.path.startsWith('streamshield_webhook_events')).options.body);
assert.deepEqual(JSON.parse(JSON.stringify(event.meta)),{banned_user_id:202,permanent:true,created_at:payload.metadata.created_at,expires_at:null});
assert.ok(calls.some(c=>c.name==='streamshield_verification_cancel_for_ban'&&c.args.p_event_at===payload.metadata.created_at));
calls.length=0;
delete payload.metadata.expires_at;
r=await context.handler(webhook(payload));
assert.equal(r.status,204);
assert.equal(calls.some(c=>c.name==='streamshield_verification_cancel_for_ban'),false,'Missing expiry metadata is not proof of a permanent ban');
r=await context.handler(new Request(base+'/events?broadcaster_id=101'));
assert.equal(r.status,401);
r=await context.handler(new Request(base+'/kick-webhook',{method:'POST',body:'{}'}));
assert.equal(r.status,400);
console.log('PASS: consent routing, origin guard, no premature device cookie, preserved Lax cookie, cancelled callback, ban metadata/cancellation, and authorization gates. No external requests.');

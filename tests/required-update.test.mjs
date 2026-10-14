import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {stripTypeScriptTypes} from 'node:module';
import {webcrypto} from 'node:crypto';
import {createClientSessionGuard, expireClientSession} from '../desktop/app/dist/src/clientSession.js';
import {RuntimeStore} from '../desktop/app/dist/src/store.js';
import {CLIENT_VERSION} from '../desktop/app/dist/src/clientVersion.js';
const backend=fs.readFileSync(new URL('../supabase/functions/streamshield-backend/index.ts',import.meta.url),'utf8').replace(/^import .+;\n/gm,'');
const helpers=fs.readFileSync(new URL('../supabase/functions/streamshield-backend/clientPolicy.ts',import.meta.url),'utf8').replace(/export /g,'');
const base='https://fixture.invalid/functions/v1/streamshield-backend';
const version='0.6.0-beta.14';
const testCases=[];const test=(name,fn)=>testCases.push([name,fn]);
function fixture(){
 const f={calls:[],policy:{enforced:true,minimum_version:version,auth_epoch:4,force_reauth_after:'2026-01-01T00:00:00Z',download_url:'https://streamshield-protection-public.vercel.app/releases/test.zip'},rows:[],registration:null};
 const ctx=vm.createContext({Request,Response,Headers,URL,URLSearchParams,TextEncoder,TextDecoder,Uint8Array,Date,JSON,Number,Math,Map,Set,atob,btoa,crypto:webcrypto,console,
  fetch:()=>{throw new Error('Unexpected live request');},Deno:{env:{get:()=>''},serve:fn=>ctx.handler=fn},
  mockPolicy:async()=>({...f.policy}),
  mockRest:async(path,options={})=>{f.calls.push({path,options});if(f.rest)return f.rest(path,options);return Response.json(f.rows);},
  mockRpc:async(name,body)=>{f.calls.push({name,body});return{};}
 });
 vm.runInContext(stripTypeScriptTypes(helpers+'\n'+backend),ctx);
 vm.runInContext('getClientPolicy=mockPolicy;rest=mockRest;rpc=mockRpc;getAppCreds=async()=>({clientId:"fixture-client",clientSecret:"fixture-secret"});kickGet=async()=>({data:[{user_id:101,name:"fixture",slug:"fixture"}]});',ctx);
 f.ctx=ctx;f.request=(path,v=version,body,extra={})=>new Request(base+path,{method:body===undefined?'GET':'POST',headers:{...(v===null?{}:{'x-streamshield-client-version':v}),...(body===undefined?{}:{'content-type':'application/json'}),...extra},...(body===undefined?{}:{body:JSON.stringify(body)})});
 return f;
}
test('package, runtime and shared client version agree',()=>{
 const pkg=JSON.parse(fs.readFileSync(new URL('../desktop/app/package.json',import.meta.url)));
 assert.equal(CLIENT_VERSION,version);assert.equal(pkg.version,version);
 assert.match(fs.readFileSync(new URL('../desktop/app/dist/src/server.js',import.meta.url),'utf8'),/const APP_VERSION = CLIENT_VERSION/);
});
test('versions compare numerically, including beta 9 versus beta 14',()=>{
 const {ctx}=fixture();assert.equal(ctx.supportedClientVersion('0.6.0-beta.9',version),false);assert.equal(ctx.supportedClientVersion(version,version),true);assert.equal(ctx.supportedClientVersion('0.6.0',version),true);
 for(const bad of ['',null,undefined,'0.6.0-beta.14garbage','v0.6.0-beta.14','0.6.0-beta.014','99999.1.1'])assert.equal(ctx.supportedClientVersion(bad,version),false);
});
test('old and missing versions are refused before protected endpoint work',async()=>{
 const f=fixture();
 for(const v of [null,'0.6.0-beta.12','0.6.0-beta.13'])for(const [path,body] of [['/events?broadcaster_id=101'],['/oauth/start',{}],['/oauth/redeem',{}],['/register',{}],['/moderator/command',{}]]){
  const response=await f.ctx.handler(f.request(path,v,body));assert.equal(response.status,426,path);const data=await response.json();assert.equal(data.sign_out,true);assert.equal(data.minimum_version,version);
 }
 assert.equal(f.calls.length,0);
});
test('edge alternate path prefixes cannot bypass the compatibility gate',async()=>{
 const f=fixture();for(const path of ['/streamshield-backend/events','/custom/prefix/events','/streamshield-backend/oauth/start']){
  const response=await f.ctx.handler(new Request('https://fixture.invalid'+path,{method:path.endsWith('start')?'POST':'GET'}));assert.equal(response.status,426);
 }
});
test('current version does not replace installation authentication',async()=>{
 const f=fixture();const response=await f.ctx.handler(f.request('/client/session?broadcaster_id=101'));assert.equal(response.status,401);assert.equal((await response.json()).error,'reauthentication_required');
});
test('revoked epoch cannot authorize an old installation with a forged version header',async()=>{
 const f=fixture(),key='test_key_abcdefghijklmnopqrstuvwxyz1234567890';f.rows=[{install_key_hash:await f.ctx.sha256Hex(key),auth_epoch:3}];
 assert.equal(await f.ctx.authorizeInstall(f.request('/events',version,undefined,{'x-streamshield-install-key':key}),101),false);
 f.rows[0].auth_epoch=4;assert.equal(await f.ctx.authorizeInstall(f.request('/events',version,undefined,{'x-streamshield-install-key':key}),101),true);
});
test('registration using an old cached KICK token cannot revive a revoked installation',async()=>{
 const f=fixture();const response=await f.ctx.handler(f.request('/register',version,{kick_access_token:'cached_test_token',install_key:'test_install_key_abcdefghijklmnopqrstuvwxyz'}));assert.equal(response.status,401);assert.ok(!f.calls.some(c=>c.options?.method==='POST'));
});
test('old in-flight OAuth states are rejected before code exchange',async()=>{
 const f=fixture();vm.runInContext('exchangeCode=async()=>{throw new Error("Code exchange must not run");}',f.ctx);
 for(const v of [1,4]){
  const state=await f.ctx.seal({v,flow:v===4?'moderator_invite':undefined,exp:Date.now()+10000,auth_epoch:3,client_version:version},'fixture-secret');
  const response=await f.ctx.handler(f.request('/oauth/kick/callback?code=test&state='+encodeURIComponent(state)));
  assert.equal(new URL(response.headers.get('location')).searchParams.get('status'),'426');
 }
});
test('redeem requires current epoch and an install-bound ticket',async()=>{
 const f=fixture(),key='test_install_key_abcdefghijklmnopqrstuvwxyz';
 const ticket=await f.ctx.seal({v:1,jti:'test',exp:Date.now()+10000,install_hash:await f.ctx.sha256Hex(key),auth_epoch:3,client_version:version},'fixture-secret');
 const response=await f.ctx.handler(f.request('/oauth/redeem',version,{ticket,install_key:key}));assert.equal(response.status,401);assert.equal(f.calls.length,0);
});
test('fresh consumed OAuth ticket stamps epoch without touching bans or settings',async()=>{
 const f=fixture(),key='test_install_key_abcdefghijklmnopqrstuvwxyz';
 const ticket=await f.ctx.seal({v:1,jti:'test',exp:Date.now()+10000,install_hash:await f.ctx.sha256Hex(key),auth_epoch:4,client_version:version,broadcaster_id:101,username:'fixture',slug:'fixture',token:{access_token:'test-token'}},'fixture-secret');
 const response=await f.ctx.handler(f.request('/oauth/redeem',version,{ticket,install_key:key}));assert.equal(response.status,200);
 assert.deepEqual(f.calls.map(c=>c.path),['streamshield_oauth_redeemed','streamshield_channels?on_conflict=broadcaster_id']);
 const row=JSON.parse(f.calls[1].options.body);assert.equal(row.auth_epoch,4);assert.equal(row.client_version,version);assert.equal('token' in row,false);
});
test('heartbeat updates only the authenticated installation and records reported version',async()=>{
 const f=fixture(),key='test_install_key_abcdefghijklmnopqrstuvwxyz',hash=await f.ctx.sha256Hex(key);f.rows=[{install_key_hash:hash,auth_epoch:4}];
 const response=await f.ctx.handler(f.request('/client/session?broadcaster_id=101',version,undefined,{'x-streamshield-install-key':key}));assert.equal(response.status,200);
 const write=f.calls.find(c=>c.options.method==='PATCH');assert.ok(write.path.includes('install_key_hash=eq.'+hash));assert.ok(write.path.includes('auth_epoch=eq.4'));assert.equal(JSON.parse(write.options.body).client_version,version);
});
test('moderator sessions remain epoch-bound even when created after the reset cutoff',async()=>{
 const f=fixture();f.rows=[{id:'test-session',broadcaster_id:101,kick_user_id:202,created_at:'2026-10-01T00:00:00Z',auth_epoch:3}];
 const result=await f.ctx.moderatorSession(f.request('/moderator/snapshot',version,undefined,{'x-streamshield-mod-session':'A'.repeat(40)}));assert.equal(result,null);
});
test('public policy, viewer consent and signed-webhook entry points stay separate',async()=>{
 const f=fixture();let response=await f.ctx.handler(f.request('/client/policy',null));assert.equal(response.status,200);assert.equal((await response.json()).auth_epoch,4);
 response=await f.ctx.handler(f.request('/network/start?broadcaster_id=101',null));assert.equal(response.status,303);assert.equal(new URL(response.headers.get('location')).pathname,'/verify');
 response=await f.ctx.handler(f.request('/kick-webhook',null,{}));assert.equal(response.status,400);assert.equal((await response.json()).error,'missing_kick_headers');
});
test('dormant policy does not enforce an older version',async()=>{
 const f=fixture();f.policy.enforced=false;const response=await f.ctx.handler(f.request('/oauth/start',null,{}));assert.equal(response.status,400);assert.equal((await response.json()).error,'invalid_local_callback');
});
test('session guard coalesces requests and expires its short lease',async()=>{
 let count=0,time=1000;const session={};const guard=createClientSessionGuard({check:async()=>{count++;return{ok:true};},expire:async()=>{},now:()=>time});
 await Promise.all([guard(session),guard(session),guard(session)]);assert.equal(count,1);time+=29999;await guard(session);assert.equal(count,1);time+=2;await guard(session);assert.equal(count,2);
});
test('session expiration removes credentials and preserves policies, reports and ban holds',async()=>{
 const session={token:{access_token:'test',refresh_token:'refresh'},shieldActive:true,trustedUserIds:[1],verificationLocks:{req:2},permanentBanHolds:{3:4},remoteBackendRegistered:true};
 const guard=createClientSessionGuard({check:async()=>{throw Object.assign(new Error('Required update'),{status:426});},expire:async(s,m)=>expireClientSession(s,m)});
 await assert.rejects(guard(session),/Required update/);assert.equal(session.reauthRequired,true);assert.deepEqual(session.token,{});assert.equal(session.shieldActive,true);assert.deepEqual(session.verificationLocks,{req:2});assert.deepEqual(session.permanentBanHolds,{3:4});await assert.rejects(guard(session),/Required update/);
});
test('network failure fails closed without deleting credentials and can recover',async()=>{
 let fail=true;const session={token:{access_token:'test'}};const guard=createClientSessionGuard({check:()=>{if(fail)throw new Error('unavailable');return{ok:true};},expire:async()=>{throw new Error('Must not erase valid credentials on network failure');}});
 await assert.rejects(guard(session),/unavailable/);assert.equal(session.reauthRequired,undefined);fail=false;await guard(session);
});
test('session serialization preserves sign-out and settings; fresh reauthorization clears hold',()=>{
 const store=new RuntimeStore('/unused-no-files');const session=store.createSession({broadcasterId:101,username:'fixture',slug:'fixture',token:{access_token:'test'},tokenExpiresAt:Date.now()+10000,isLive:false});session.authClientVersion=version;session.permanentBanHolds={7:8};expireClientSession(session,'Reconnect');
 const row=store.serializeSessions()[0];assert.equal(row.reauthRequired,true);assert.deepEqual(row.token,{});assert.equal(row.authClientVersion,version);
 const oldId=session.id;const fresh=store.createSession({broadcasterId:101,username:'fixture',slug:'fixture',token:{access_token:'fresh'},tokenExpiresAt:Date.now()+10000,isLive:false});assert.equal(fresh.reauthRequired,false);assert.deepEqual(fresh.permanentBanHolds,{7:8});assert.notEqual(fresh.id,oldId);
});
test('a stale failed check cannot sign out a newly reauthorized session',async()=>{
 let reject;const oldResult=new Promise((_,r)=>{reject=r;});const session={id:'old',remoteInstallKey:'old-key'};
 const guard=createClientSessionGuard({check:s=>s.id==='old'?oldResult:Promise.resolve({ok:true}),expire:async(s,m)=>expireClientSession(s,m)});
 const previous=guard(session);await Promise.resolve();session.id='new';session.remoteInstallKey='new-key';await guard(session);
 reject(Object.assign(new Error('Old session ended'),{status:401}));await assert.rejects(previous,/Old session/);assert.equal(session.reauthRequired,undefined);await guard(session);
});
test('reauthorization cannot inherit a previous session authorization lease',async()=>{
 let calls=0;const session={id:'first',remoteInstallKey:'first-key'};const guard=createClientSessionGuard({check:async()=>{calls++;return{ok:true};},expire:async()=>{}});
 await guard(session);session.id='second';session.remoteInstallKey='second-key';await guard(session);assert.equal(calls,2);
});
for(const [name,fn]of testCases){await fn();console.log('PASS '+name);}console.log(testCases.length+'/'+testCases.length+' required-update tests passed with synthetic accounts and no live network.');

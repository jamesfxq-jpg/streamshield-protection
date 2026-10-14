import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { summarizeBanShield, validateVerificationResult, createVerificationDeliveryCache } from '../desktop/app/dist/src/quietShield.js';
import { quietShieldBrowserScript } from '../desktop/app/dist/src/quietShieldUi.js';

const tests=[];
const test=(name,fn)=>tests.push({name,fn});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return{promise,resolve};};
const backend='https://fixture.invalid/functions/v1/streamshield-backend';
const now=Date.now();
const valid=()=>({request:{id:'request-fixture'},verification_url:backend+'/verification/start?request='+'A'.repeat(32),expires_at:new Date(now+30*60_000).toISOString()});

test('ban results distinguish disabled, unavailable, missing, syncing and confirmed network history',()=>{
 assert.equal(summarizeBanShield(null,7).state,'protection_off');
 const enabled={enabled:true};
 for(const value of [null,undefined,{},'oops',{history:{}}])assert.equal(summarizeBanShield(value,7,enabled).state,'history_unavailable');
 assert.equal(summarizeBanShield({history:[]},7,enabled).state,'no_retained_network');
 const row={accounts:[{kick_user_id:7}],network_hash:'a'.repeat(64),ip:'192.0.2.17',blocked:false};
 assert.equal(summarizeBanShield({history:[row]},7,enabled).state,'network_sync_pending');
 row.blocked=true;
 const result=summarizeBanShield({history:[row]},7,enabled);
 assert.equal(result.state,'network_shield_active');
 assert.doesNotMatch(JSON.stringify(result),/192\.0\.2\.17|aaaaaaa|network_hash/);
});
test('network matching uses stable IDs, never reused usernames',()=>{
 const history={history:[{kick_username:'same-name',accounts:[{kick_user_id:9,kick_username:'same-name'}],blocked:true}]};
 assert.equal(summarizeBanShield(history,7,{enabled:true}).state,'no_retained_network');
});
test('explicit unblocked status and mixed histories cannot falsely report all networks protected',()=>{
 for(const row of [{blocked:false,is_blocked:true,blocked_at:'2026-10-01'}, {blocked_at:'2026-10-01',unblocked_at:'2026-10-02'}]){
  assert.equal(summarizeBanShield({history:[{...row,accounts:[{kick_user_id:7}]}]},7,{enabled:true}).state,'network_sync_pending');
 }
 assert.equal(summarizeBanShield({history:[{kick_user_id:7,blocked:true},{kick_user_id:7,blocked:false}]},7,{enabled:true}).state,'network_sync_pending');
});
test('verification link validation accepts only the configured HTTPS backend and original bounded expiry',()=>{
 assert.equal(validateVerificationResult(valid(),backend,now).requestId,'request-fixture');
 for(const url of [
  'http://fixture.invalid/functions/v1/streamshield-backend/verification/start?request='+'A'.repeat(32),
  'https://fixture.invalid.evil.example/verification/start?request='+'A'.repeat(32),
  'https://user:pass@fixture.invalid/functions/v1/streamshield-backend/verification/start?request='+'A'.repeat(32),
  valid().verification_url+'&request='+'B'.repeat(32), valid().verification_url+'#hidden',
  'https://fixture.invalid/other?request='+'A'.repeat(32),
 ])assert.throws(()=>validateVerificationResult({...valid(),verification_url:url},backend,now),/no chat restriction was applied/);
 for(const expires_at of ['',new Date(now-1).toISOString(),new Date(now+32*60_000).toISOString()])assert.throws(()=>validateVerificationResult({...valid(),expires_at},backend,now));
 assert.throws(()=>validateVerificationResult({...valid(),request:{}},backend,now));
});
test('delivery cache is bounded, account-scoped, expires, and never extends its original lifetime',()=>{
 let clock=1000;const cache=createVerificationDeliveryCache({maxEntries:2,now:()=>clock});
 const value=valid();cache.remember('channel:7',value,2000);
 assert.equal(cache.get('channel:8','request-fixture'),undefined);
 assert.equal(cache.get('channel:7','different-request'),undefined);
 cache.markSent('channel:7','request-fixture','message');
 assert.equal(cache.get('channel:7','request-fixture').sentAt,1000);
 clock=2000;assert.equal(cache.get('channel:7','request-fixture'),undefined);
 for(let i=0;i<10;i++)cache.remember('user:'+i,value,clock+1000);
 assert.equal(cache.size,2);assert.equal(cache.get('user:0','request-fixture'),undefined);
 cache.forget('user:9');assert.equal(cache.size,1);
});

class Element{
 constructor(){this.children=[];this.style={};this.hidden=false;this.textContent='';this.attributes={};this.classList={add(){},remove(){}};}
 append(...items){this.children.push(...items);}
 replaceChildren(...items){this.children=items;}
 setAttribute(key,value){this.attributes[key]=value;}
 removeAttribute(key){delete this.attributes[key];}
 addEventListener(){}
 scrollIntoView(){}
}
function uiFixture(){
 const nodes=new Map(),calls=[],buttons=[];
 const el=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
 const f={nodes,calls,confirmations:0,hooks:{}};
 const context={console,Set,Number,String,Error,Promise,
  document:{querySelector:id=>el(id),querySelectorAll:()=>buttons},
  current:{networkProtection:{enabled:false,auto_ban_exact_network_match:false}},
  confirm:()=>{f.confirmations++;return true;},alert:()=>{throw new Error('Success should use private inline notice, not alert');},prompt:()=>{},
  navigator:{clipboard:{writeText:async()=>{}}},
  loadQueue:async()=>{if(f.hooks.refresh)await f.hooks.refresh();},
  api:async(path,body)=>{calls.push({path,body});return f.hooks.api?await f.hooks.api(path,body):{ok:true,text:async()=>JSON.stringify({ok:true,account_banned:true,ban_shield:{message:'Account banned; history still syncing.'}})};},
 };
 f.context=vm.createContext(context);vm.runInContext(quietShieldBrowserScript,f.context);
 f.bind=(action,id)=>{const b=new Element();buttons.push(b);f.context.quietBind(b,action,{userId:id});return b;};
 return f;
}
test('double clicks submit one moderation action; refreshed buttons remain disabled while pending',async()=>{
 const f=uiFixture(),gate=deferred();f.hooks.api=async()=>{await gate.promise;return{ok:true,text:async()=>JSON.stringify({ban_shield:{message:'Banned.'}})};};
 const first=f.bind('ban',7);const a=first.onclick();
 const refreshed=f.bind('ban',7);assert.equal(refreshed.disabled,true);
 await refreshed.onclick();assert.equal(f.calls.length,1);assert.equal(f.confirmations,1);
 gate.resolve();await a;assert.equal(refreshed.disabled,false);assert.equal(f.nodes.get('#quietShieldNotice').textContent,'Banned.');
});
test('a successful ban remains successful when the history panel refresh fails',async()=>{
 const f=uiFixture();f.hooks.refresh=async()=>{throw new Error('refresh down');};
 await f.bind('ban',7).onclick();assert.match(f.nodes.get('#quietShieldNotice').textContent,/Account banned/);assert.doesNotMatch(f.nodes.get('#quietShieldNotice').textContent,/failed/);
});
test('network or moderation errors re-enable controls without fabricating success',async()=>{
 const f=uiFixture();f.hooks.api=async()=>({ok:false,text:async()=>JSON.stringify({error:'Ban not confirmed'})});
 const button=f.bind('ban',7);await button.onclick();assert.equal(button.disabled,false);assert.equal(f.nodes.get('#quietShieldNotice').textContent,'Ban not confirmed');
});
test('review-first shortcut never opts into automatic bans, including when switching an old advanced setting',async()=>{
 const f=uiFixture();f.context.current.networkProtection={enabled:true,auto_ban_exact_network_match:true};
 await f.context.enableReviewFirstShield();assert.equal(f.calls.length,1);
 assert.deepEqual(JSON.parse(JSON.stringify(f.calls[0])),{path:'/api/network-protection',body:{enabled:true,autoBanExactNetworkMatch:false}});
});
test('verification delivery reuse gets quiet private feedback and no second public message request',async()=>{
 const f=uiFixture();f.hooks.api=async()=>({ok:true,text:async()=>JSON.stringify({reused:true,chat_message_sent:true,chat_message_reused:true})});
 await f.bind('verify',7).onclick();assert.match(f.nodes.get('#quietShieldNotice').textContent,/No new restriction or duplicate message/);
 assert.equal(f.calls[0].path,'/api/verification/request');
});
test('server text is assigned as text rather than injected HTML',async()=>{
 const f=uiFixture();f.hooks.api=async()=>({ok:true,text:async()=>JSON.stringify({ban_shield:{message:'<img src=x onerror=alert(1)>'}})});
 await f.bind('ban',7).onclick();assert.equal(f.nodes.get('#quietShieldNotice').textContent,'<img src=x onerror=alert(1)>');assert.equal(f.nodes.get('#quietShieldNotice').innerHTML,undefined);
});
test('consent page remains explicit, legible, and disabled until a valid link is checked',async()=>{
 const html=await readFile(new URL('../verify.html',import.meta.url),'utf8');
 for(const term of ['Verify to chat','By continuing, you agree','privacy-protected network identifier','first-party browser token','does not store or show your full IP address','aria-describedby="verification-disclosure"','id="verification-fields" disabled'])assert.ok(html.includes(term),term);
 const script=await readFile(new URL('../assets/verify.js',import.meta.url),'utf8');assert.match(script,/noDuplicate/);assert.match(script,/oneMode/);
});
test('remote moderator panel prevents duplicate in-flight actions and uses new Ban & Shield feedback',async()=>{
 const source=await readFile(new URL('../assets/mod-panel.js',import.meta.url),'utf8');
 const nodes=new Map(),el=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
 const gate=deferred();let posts=0;
 const context={console,URLSearchParams,Date,Number,String,Set,Promise,Error,
  location:{search:'',hash:'#session=synthetic-test-session'},history:{replaceState(){}},
  sessionStorage:{getItem:()=>'',setItem(){},removeItem(){}},
  document:{getElementById:el,createElement:()=>new Element(),body:new Element(),querySelectorAll:()=>[]},
  confirm:()=>true,alert:()=>{throw new Error('No blocking success alert expected');},prompt(){},navigator:{clipboard:{writeText:async()=>{}}},
  setInterval:()=>0,setTimeout,window:{open(){}},
  fetch:async(url,init={})=>{
   if(url.includes('/moderator/snapshot'))return{ok:true,json:async()=>({channel:{},recent_chat:[],verification:[],networks:[],commands:[]})};
   if(url.includes('/moderator/command/status')){await gate.promise;return{ok:true,json:async()=>({command:{status:'completed',result:{ban_shield:{message:'Account banned. No retained verified network was found.'}}}})};}
   if(url.endsWith('/moderator/command')&&init.method==='POST'){posts++;return{ok:true,json:async()=>({command:{id:'command-fixture'}})};}
   throw new Error('Unexpected request: '+url);
  },
 };
 const ctx=vm.createContext(context);vm.runInContext(source.replace(/\}\)\(\);\s*$/,'globalThis.testRunAction = runAction;})();'),ctx);
 const row={sender_id:7,sender_username:'fixture'};const a=ctx.testRunAction('permanent_ban',row);await Promise.resolve();await ctx.testRunAction('permanent_ban',row);assert.equal(posts,1);
 gate.resolve();await a;assert.match(el('quiet-mod-notice').textContent,/No retained verified network/);
 assert.ok(source.includes('["Ban & Shield","permanent_ban","danger"]'));
});

let passed=0;
for(const {name,fn} of tests){await fn();console.log('PASS '+name);passed++;}
console.log(`${passed}/${tests.length} Quiet Shield privacy, expiry, status, consent and UI regressions passed. No live account activity.`);

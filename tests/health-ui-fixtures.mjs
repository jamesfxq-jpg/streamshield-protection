import vm from 'node:vm';
import assert from 'node:assert/strict';
import { StreamShieldDetector } from '../desktop/app/dist/src/detector.js';
import { dashboard, compactDashboard } from '../desktop/app/dist/src/ui.js';
class Element {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.style={};this.dataset={};this._text='';this._html='';this.classList={add(){},remove(){}};}
 append(...xs){this.children.push(...xs);}replaceChildren(...xs){this.children=xs;this._text='';this._html='';}
 set textContent(x){this._text=String(x);this.children=[];this._html='';}get textContent(){return this._text+this.children.map(x=>x.textContent??String(x)).join('');}
 set innerHTML(x){this._html=x;this.children=[];this._text='';}get innerHTML(){return this._html;}addEventListener(){}remove(){}
}
const d=new StreamShieldDetector();
const s={id:'fixture',slug:'qa_fixture',csrfToken:'fake',detector:d,lastAssessment:d.assess(),isLive:true,mode:'assist',shieldActive:false,followShieldEnabled:true,chatRaidShieldEnabled:true,linkScamShieldEnabled:true,recentChat:[],recentActions:[],recentEvents:[],subscriptionHealthy:true,remoteBackendRegistered:true,lastWebhookAt:Date.now(),lastPollAt:Date.now(),overlayKey:'fake-overlay'};
const base={assessment:s.lastAssessment,slug:s.slug,isLive:true,mode:s.mode,subscriptionHealthy:true,remoteBackendConfigured:true,remoteBackendRegistered:true,publicWebhookAvailable:true,temporaryWebhookTunnel:false,lastWebhookAt:s.lastWebhookAt,lastPollAt:s.lastPollAt,baseline:d.getBaseline(),recentChat:[],recentActions:[],recentEvents:[],protectionHealth:{level:'green',label:'Protected',reasons:[]}};
async function check(compact){
 const html=compact?compactDashboard(s,true,false):dashboard(s,[],'http://localhost:18897','',true,'https://qa.invalid/kick-webhook');
 const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>['#'+m[1],new Element()]));
 let source;const calls=[];const outcomes=[['pending',''],['expired',''],['verified','no_local_verification_lock'],['verified','verification_setup_failed_review_required'],['review','review_required_chat_locked'],['verified','chat_released_clean'],['blocked','permanent_ban_preserved']];const requestRows=outcomes.map(([status,desktop_outcome],i)=>({id:'request-'+i,kick_user_id:910000002+i,kick_username:'qa_'+i,status,desktop_outcome}));
 const ctx=vm.createContext({document:{querySelector:q=>elements[q]||null,querySelectorAll:()=>[],createElement:t=>new Element(t),addEventListener(){},body:new Element('body')},fetch:async(path,init)=>{calls.push({path,body:init?.body?JSON.parse(init.body):null});return {ok:true,json:async()=>({ok:true,items:requestRows,history:[]}),text:async()=>''};},setInterval:()=>0,EventSource:class{constructor(){source=this;}},confirm:()=>true,alert(){},prompt(){},URL,Notification:{permission:'denied'},window:{open(){}},navigator:{clipboard:{writeText:async()=>{}}}});
 for(const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g))vm.runInContext(m[1],ctx);
 await new Promise(r=>setImmediate(r));
 const walk=e=>[e,...e.children.flatMap(walk)];const queue=elements[compact?'#compactQueue':'#verificationQueue'];const releases=walk(queue).filter(n=>n.tagName==='button'&&n.textContent===(compact?'Release chat / Unban':'Release Chat'));assert.equal(releases.length,5,'unresolved requests remain recoverable; successful releases/permanent holds excluded');await releases[0].onclick();assert.deepEqual(calls.find(x=>x.path==='/api/verification/release').body,{requestId:'request-0',userId:910000002});
 const status=elements[compact?'#compactStatus':'#status'];const reasons=elements[compact?'#compactHealthReasons':'#watchdogReasons'];
 assert.match(status.textContent,/CHECKING/);assert.match(status.className,/statusWarn/);
 const update=x=>source.onmessage({data:JSON.stringify({...base,...x})});
 update({protectionHealth:{level:'yellow',label:'Awaiting KICK events',reasons:['Awaiting the first signed KICK webhook event.']}});
 assert.match(status.textContent,/AWAITING KICK EVENTS/);assert.match(reasons.textContent,/first signed KICK webhook/);assert.match(status.className,/statusWarn/);
 update({remoteBackendError:'Relay request failed',protectionHealth:{level:'red',label:'Attention required',reasons:['Relay request failed']}});
 assert.match(status.textContent,/ATTENTION REQUIRED/);assert.match(reasons.textContent,/Relay request failed/);
 if(!compact){assert.equal(elements['#readinessCloud'].textContent,'Connection issue');assert.equal(elements['#readinessCloud'].className,'warn');}
 update({});assert.equal(status.textContent,'✓ PROTECTED');assert.equal(reasons.hidden,compact?true:undefined);
 update({isLive:false});assert.equal(status.textContent,'✓ READY · OFFLINE');
 update({publicWebhookAvailable:false});assert.match(status.textContent,/LOCAL TEST/);assert.match(reasons.textContent,/public KICK webhooks are not active/);
 update({assessment:{...base.assessment,score:90},protectionHealth:{level:'red',label:'Attention required',reasons:['Relay request failed']}});assert.match(status.textContent,/ATTACK/);assert.match(reasons.textContent,/Relay request failed/);
 if(!compact){const cases=[['https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend/site/download',true],['https://streamshield-protection-public.vercel.app/download',true],['http://streamshield-protection-public.vercel.app/download',false],['https://example.com/file.zip',false],['https://streamshield-protection-public.vercel.app.evil.example/file.zip',false],['https://attacker@streamshield-protection-public.vercel.app/download',false],['https://user:pass@blrdvuhnxtwnsphdxpkg.supabase.co/file.zip',false],['https://streamshield-protection-public.vercel.app:8443/download',false],['https://blrdvuhnxtwnsphdxpkg.supabase.co:444/file.zip',false],['not-a-url',false]];for(const [url,allowed] of cases){update({updateAvailable:true,latestRelease:{version:'qa-version',download_url:url}});assert.equal(elements['#updateBanner'].hidden,!allowed,url);if(allowed)assert.equal(elements['#updateLink'].href,url);}console.log('PASS release URLs: exact HTTPS Supabase and public-site hosts accepted; arbitrary/deceptive hosts, HTTP, credentials, custom ports, malformed URLs rejected.');}
 console.log('PASS '+(compact?'Compact':'Main')+': pending/expired/verified recovery with exact ID; checking before first snapshot; yellow/red health and reasons; healthy live/offline; local-test caution; attack status retains health warning.');
}
await check(false);await check(true);

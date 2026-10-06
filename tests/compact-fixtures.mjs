import vm from 'node:vm';
import assert from 'node:assert/strict';
import { StreamShieldDetector } from '../desktop/app/dist/src/detector.js';
import { compactDashboard as before } from './fixtures/beta9-ui.mjs';
import { compactDashboard as after } from '../desktop/app/dist/src/ui.js';
class Element {
  constructor(tag='div') { this.tagName=tag;this.children=[];this.style={};this._text='';this._html=''; }
  append(...xs){this.children.push(...xs);}
  replaceChildren(...xs){this.children=xs;this._text='';this._html='';}
  set textContent(x){this._text=String(x);this.children=[];this._html='';}
  get textContent(){return this._text+this.children.map(x=>x.textContent??String(x)).join('');}
  set innerHTML(x){this._html=x;this.children=[];this._text='';}
  get innerHTML(){return this._html;}
}
const d=new StreamShieldDetector();
const s={id:'fake-session',slug:'qa_fixture',csrfToken:'synthetic-csrf',lastAssessment:d.assess(),isLive:false,shieldActive:false,followShieldEnabled:true,chatRaidShieldEnabled:true,linkScamShieldEnabled:true,recentChat:[{userId:910000002,username:'qa_viewer',content:'synthetic test message'}],recentEvents:[],networkProtection:{enabled:true,auto_ban_exact_network_match:false,blocked_networks:1},subscriptionHealthy:true};
const network={ok:true,history:[{ip:'192.0.2.20',network_hash:'a'.repeat(64),blocked:true,accounts:[{kick_user_id:910000002,kick_username:'qa_viewer'}]},{ip:'192.0.2.21',network_hash:'b'.repeat(64),blocked:false,blocked_at:'2026-10-01T00:00:00Z',unblocked_at:'2026-10-02T00:00:00Z'}]};
const requests={ok:true,items:[{id:'00000000-0000-4000-8000-000000000001',kick_user_id:910000002,kick_username:'qa_viewer',status:'pending',requested_at:'2026-10-06T00:00:00.000Z'}]};
async function render(make){
 const html=make(s,true,false);const code=html.match(/<script>([\s\S]*)<\/script>/)[1];
 const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>['#'+m[1],new Element()]));
 const calls=[];
 const context={document:{querySelector:q=>elements[q]||null,createElement:t=>new Element(t)},fetch:async(path,init)=>{calls.push({path,body:init?.body?JSON.parse(init.body):null});return {ok:true,json:async()=>path==='/api/network-history'?network:requests,text:async()=>''};},setInterval:()=>0,EventSource:class{},confirm:()=>true,alert:()=>{},prompt:()=>{},navigator:{clipboard:{writeText:async()=>{}}}};
 vm.runInNewContext(code,context);await new Promise(r=>setImmediate(r));
 return {elements,calls};
}
function descendants(e){return [e,...e.children.flatMap(descendants)];}
const old=await render(before);
assert.equal(old.elements['#compactIpHistory'].innerHTML,'<p class="small">No blocked verified IPs.</p>');
assert.equal(descendants(old.elements['#compactQueue']).filter(n=>n.tagName==='button').length,0);
const next=await render(after);
const unblock=descendants(next.elements['#compactIpHistory']).find(n=>n.textContent==='UN-IP BAN');
assert.ok(unblock);assert.match(next.elements['#compactIpHistory'].textContent,/192\.0\.2\.20/);assert.doesNotMatch(next.elements['#compactIpHistory'].textContent,/192\.0\.2\.21/);
await unblock.onclick();
assert.deepEqual(next.calls.find(c=>c.path==='/api/network-unblock').body,{networkHash:'a'.repeat(64),reason:'compact_control_un_ip_ban'});
const release=descendants(next.elements['#compactQueue']).find(n=>n.textContent==='Release chat / Unban');
assert.ok(release);await release.onclick();
assert.deepEqual(next.calls.find(c=>c.path==='/api/verification/release').body,{userId:910000002,requestId:'00000000-0000-4000-8000-000000000001'});
console.log('PASS: Beta 9 reproduces both missing controls with authoritative backend response shapes.');
console.log('PASS: Beta 10 renders blocked IP + UN-IP BAN and submits the exact network hash; explicit blocked=false excludes historical blocks.');
console.log('PASS: Beta 10 renders pending verification release and submits the authoritative row.id.');
console.log('All network interactions stubbed; no browser, real KICK account, or cloud mutation used.');

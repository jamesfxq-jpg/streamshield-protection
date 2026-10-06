import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const secretJson = Deno.env.get("SUPABASE_SECRET_KEYS");
const SECRET_KEY = (() => {
  if (secretJson) {
    try {
      const parsed = JSON.parse(secretJson);
      if (parsed?.default) return String(parsed.default);
    } catch {}
  }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
})();

const enc = new TextEncoder();
const dec = new TextDecoder();
const MAX_BODY = 512 * 1024;
const BOOTSTRAP_HASH = "c0f15b44348bad8ddcb6d5edb43949aed8d7fccc991f721504bdebded914fc56";
const OAUTH_CALLBACK = "https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend/oauth/kick/callback";
const PUBLIC_WEB_ORIGIN = "https://streamshield-protection-public.vercel.app";
const KICK_SCOPES = ["user:read","channel:read","events:subscribe","moderation:ban","moderation:chat_message:manage"];
const NETWORK_VIEWER_SCOPES = ["user:read"];
let kickKey: CryptoKey | null = null;
let kickKeyFetchedAt = 0;

function json(status: number, value: unknown, extra: Record<string,string> = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...extra,
    },
  });
}

const MOD_CORS = {
  "access-control-allow-origin": PUBLIC_WEB_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, x-streamshield-mod-session",
};
function modJson(status:number,value:unknown,extra:Record<string,string>={}) {
  return json(status,value,{...MOD_CORS,...extra});
}
function html(status:number, title:string, body:string) {
  return verificationResult(status,title,body);
}

// Shared Supabase domains serve HTML as text/plain. Keep the OAuth callback and
// verification records here, and send human-readable pages to the public site.
function verificationResult(status:number,title:string,message:string,setCookie:string="") {
  const target=new URL("/verification-result",PUBLIC_WEB_ORIGIN);
  target.searchParams.set("status",String(status));
  target.searchParams.set("title",title);
  target.searchParams.set("message",message);
  return new Response(null,{status:303,headers:{
    location:target.toString(),"cache-control":"no-store","referrer-policy":"no-referrer",
    ...(setCookie?{"set-cookie":setCookie}:{})
  }});
}
function verificationConsentPage(params:Record<string,string>) {
  const target=new URL("/verify",PUBLIC_WEB_ORIGIN);
  for(const [key,value] of Object.entries(params)) target.searchParams.set(key,value);
  return new Response(null,{status:303,headers:{location:target.toString(),"cache-control":"no-store","referrer-policy":"no-referrer"}});
}
async function hasViewerConsent(req:Request) {
  if(req.method!=="POST" || req.headers.get("origin")!==PUBLIC_WEB_ORIGIN) return false;
  if(!(req.headers.get("content-type")??"").toLowerCase().startsWith("application/x-www-form-urlencoded")) return false;
  if(Number(req.headers.get("content-length")??0)>2048) return false;
  const raw=await req.text();
  return raw.length<=2048 && new URLSearchParams(raw).get("consent")==="yes";
}

function cookieValue(req:Request,name:string) {
  const raw=req.headers.get("cookie")??"";
  for(const part of raw.split(";")) {
    const [k,...rest]=part.trim().split("=");
    if(k===name) return decodeURIComponent(rest.join("="));
  }
  return "";
}
function deviceCookie(value:string) {
  return `ss_device=${encodeURIComponent(value)}; Path=/; Max-Age=${90*24*60*60}; Secure; HttpOnly; SameSite=Lax`;
}
function verificationHtml(status:number,title:string,message:string,buttonHref:string="",setCookie:string="") {
  return verificationResult(status,title,message,setCookie);
}

function bytesToBase64Url(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function base64UrlBytes(input: string) {
  const b64 = input.replace(/-/g,"+").replace(/_/g,"/") + "=".repeat((4 - input.length % 4) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}
function base64Bytes(input: string) {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function pemBytes(pem: string) {
  return base64Bytes(pem.replace(/-----BEGIN PUBLIC KEY-----/g, "").replace(/-----END PUBLIC KEY-----/g, "").replace(/\s+/g, ""));
}
async function sha256Bytes(value: string) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}
async function sha256Hex(value: string) {
  return [...await sha256Bytes(value)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function safeEqualHex(a:string,b:string) {
  if (a.length!==b.length) return false;
  let d=0; for(let i=0;i<a.length;i++) d |= a.charCodeAt(i)^b.charCodeAt(i);
  return d===0;
}
async function deriveBrokerKey(clientSecret:string) {
  const raw = await sha256Bytes("streamshield-oauth-broker-v1:" + clientSecret);
  return crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
}
async function seal(payload: unknown, clientSecret:string) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveBrokerKey(clientSecret);
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(JSON.stringify(payload))));
  const all=new Uint8Array(iv.length+cipher.length); all.set(iv); all.set(cipher,iv.length);
  return bytesToBase64Url(all);
}
async function unseal<T>(token:string, clientSecret:string):Promise<T> {
  const all=base64UrlBytes(token);
  if(all.length<29) throw new Error("invalid sealed token");
  const iv=all.slice(0,12), cipher=all.slice(12);
  const key=await deriveBrokerKey(clientSecret);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,cipher);
  return JSON.parse(dec.decode(plain)) as T;
}

async function rest(path: string, init: RequestInit = {}) {
  if (!SUPABASE_URL || !SECRET_KEY) throw new Error("Supabase backend secret unavailable");
  const headers = new Headers(init.headers);
  headers.set("apikey", SECRET_KEY);
  if (!headers.has("content-type") && init.body) headers.set("content-type", "application/json");
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { ...init, headers });
  if (!r.ok) {
    const text = await r.text();
    const err = new Error(`Database request failed ${r.status}: ${text.slice(0,500)}`) as Error & {status?:number};
    err.status=r.status;
    throw err;
  }
  return r;
}
async function rpc<T>(name:string, body:unknown):Promise<T> {
  const r=await rest(`rpc/${name}`,{method:"POST",body:JSON.stringify(body),headers:{accept:"application/json"}});
  return r.json();
}
async function getAppCreds() {
  const rows = await rpc<Array<{client_id:string|null;client_secret:string|null;configured_at:string|null}>>("streamshield_get_app_credentials",{});
  const row=rows?.[0];
  if(!row?.client_id || !row?.client_secret) throw new Error("StreamShield Kick app credentials are not configured");
  return {clientId:String(row.client_id),clientSecret:String(row.client_secret)};
}
async function getAppStatus() {
  const r=await rest("streamshield_app_config?singleton=eq.true&select=client_id,configured_at,bootstrap_used,public_version&limit=1",{headers:{accept:"application/json"}});
  return (await r.json())?.[0] ?? null;
}
async function readJson(req:Request) {
  const declared=Number(req.headers.get("content-length")??0);
  if(declared>MAX_BODY) throw Object.assign(new Error("body too large"),{status:413});
  const raw=new Uint8Array(await req.arrayBuffer());
  if(raw.byteLength>MAX_BODY) throw Object.assign(new Error("body too large"),{status:413});
  return raw.length ? JSON.parse(dec.decode(raw)) : {};
}
function validLocalCallback(value:string) {
  try {
    const u=new URL(value);
    return u.protocol==="http:" &&
      (u.hostname==="localhost" || u.hostname==="127.0.0.1") &&
      u.pathname==="/auth/kick/handoff" &&
      Number(u.port||80)>=1024 && Number(u.port||80)<=65535;
  } catch { return false; }
}
function edgeClientIp(req:Request) {
  const forwarded=(req.headers.get("x-forwarded-for")??"").split(",")[0]?.trim()??"";
  const candidates:Array<[string,string]> = [
    ["cf-connecting-ip",(req.headers.get("cf-connecting-ip")??"").trim()],
    ["x-real-ip",(req.headers.get("x-real-ip")??"").trim()],
    ["x-forwarded-for",forwarded],
  ];
  for (const [source,ip] of candidates) if(ip) return {ip,source};
  return {ip:"",source:"unavailable"};
}

async function getKickKey(force = false) {
  if (!force && kickKey && Date.now() - kickKeyFetchedAt < 6 * 60 * 60_000) return kickKey;
  const r = await fetch("https://api.kick.com/public/v1/public-key",{headers:{accept:"application/json"}});
  if (!r.ok) throw new Error(`Kick public key fetch failed: ${r.status}`);
  const b = await r.json();
  const pem = b?.data?.public_key;
  if (!pem) throw new Error("Kick public key missing");
  kickKey = await crypto.subtle.importKey("spki",pemBytes(String(pem)),{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
  kickKeyFetchedAt=Date.now(); return kickKey;
}
async function verifyKick(raw: Uint8Array, messageId: string, timestamp: string, signature: string) {
  const prefix=enc.encode(`${messageId}.${timestamp}.`);
  const signed=new Uint8Array(prefix.length+raw.length); signed.set(prefix); signed.set(raw,prefix.length);
  const verifyWith=(key:CryptoKey)=>crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,base64Bytes(signature),signed);
  const first=await getKickKey(); if(await verifyWith(first)) return true;
  return verifyWith(await getKickKey(true));
}
async function kickGet(token:string,path:string) {
  const r=await fetch(`https://api.kick.com/public/v1/${path}`,{headers:{authorization:`Bearer ${token}`,accept:"application/json"}});
  if(!r.ok) throw new Error(`Kick API ${r.status}: ${(await r.text()).slice(0,300)}`);
  return r.json();
}
async function exchangeCode(code:string, verifier:string, creds:{clientId:string;clientSecret:string}) {
  const body=new URLSearchParams({
    grant_type:"authorization_code",client_id:creds.clientId,client_secret:creds.clientSecret,
    redirect_uri:OAUTH_CALLBACK,code_verifier:verifier,code
  });
  const r=await fetch("https://id.kick.com/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body});
  const text=await r.text(); let parsed:any; try{parsed=JSON.parse(text)}catch{parsed=text}
  if(!r.ok) throw new Error(`Kick token exchange ${r.status}: ${typeof parsed==="string"?parsed:JSON.stringify(parsed)}`);
  return parsed;
}
async function refreshToken(refreshToken:string, creds:{clientId:string;clientSecret:string}) {
  const body=new URLSearchParams({
    grant_type:"refresh_token",client_id:creds.clientId,client_secret:creds.clientSecret,refresh_token:refreshToken
  });
  const r=await fetch("https://id.kick.com/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body});
  const text=await r.text(); let parsed:any; try{parsed=JSON.parse(text)}catch{parsed=text}
  if(!r.ok) throw new Error(`Kick token refresh ${r.status}: ${typeof parsed==="string"?parsed:JSON.stringify(parsed)}`);
  return parsed;
}
async function authorizeInstall(req: Request, broadcasterId: number) {
  const key=req.headers.get("x-streamshield-install-key")??"";
  if(key.length<32) return false;
  const r=await rest(`streamshield_channels?broadcaster_id=eq.${broadcasterId}&select=install_key_hash&limit=1`,{headers:{accept:"application/json"}});
  const expected=(await r.json())?.[0]?.install_key_hash;
  return expected ? safeEqualHex(await sha256Hex(key),String(expected)) : false;
}

async function cleanupExpired() {
  const now=new Date().toISOString();
  await Promise.allSettled([
    rest(`streamshield_webhook_events?content_expires_at=lt.${encodeURIComponent(now)}&chat_content=not.is.null`,{method:"PATCH",body:JSON.stringify({chat_content:null,sender_username:null})}),
    rest(`streamshield_webhook_events?row_expires_at=lt.${encodeURIComponent(now)}`,{method:"DELETE"}),
    rest(`streamshield_oauth_redeemed?expires_at=lt.${encodeURIComponent(now)}`,{method:"DELETE"})
  ]);
}

async function handleOwnerBootstrap(req:Request) {
  const current=await getAppStatus();
  if(current?.bootstrap_used) return json(409,{error:"already_configured"});
  const body:any=await readJson(req);
  const bootstrap=String(body?.bootstrap_token??"");
  if(!safeEqualHex(await sha256Hex(bootstrap),BOOTSTRAP_HASH)) return json(401,{error:"invalid_bootstrap_token"});
  const clientId=String(body?.client_id??"").trim(), clientSecret=String(body?.client_secret??"");
  if(clientId.length<8 || clientSecret.length<16) return json(400,{error:"invalid_credentials"});
  const result=await rpc<any>("streamshield_set_app_credentials",{p_client_id:clientId,p_client_secret:clientSecret});
  return json(200,{ok:true,client_id:clientId,secret_stored_in_vault:true,result});
}

async function handleOauthStart(req:Request) {
  const body:any=await readJson(req);
  const localCallback=String(body?.local_callback??"");
  const installKey=String(body?.install_key??"");
  if(!validLocalCallback(localCallback)) return json(400,{error:"invalid_local_callback"});
  if(installKey.length<32) return json(400,{error:"invalid_install_key"});
  const creds=await getAppCreds();
  const verifier=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge=bytesToBase64Url(await sha256Bytes(verifier));
  const state=await seal({
    v:1,exp:Date.now()+10*60_000,verifier,local_callback:localCallback,install_hash:await sha256Hex(installKey)
  },creds.clientSecret);
  const u=new URL("https://id.kick.com/oauth/authorize");
  u.searchParams.set("response_type","code");
  u.searchParams.set("client_id",creds.clientId);
  u.searchParams.set("redirect_uri",OAUTH_CALLBACK);
  u.searchParams.set("scope",KICK_SCOPES.join(" "));
  u.searchParams.set("state",state);
  u.searchParams.set("code_challenge",challenge);
  u.searchParams.set("code_challenge_method","S256");
  return json(200,{ok:true,authorize_url:u.toString(),redirect_uri:OAUTH_CALLBACK});
}
async function handleNetworkOauthStart(req:Request) {
  const u=new URL(req.url);
  const broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return html(400,"StreamShield verification","Invalid channel.");
  if(req.method!=="POST") return verificationConsentPage({broadcaster_id:String(broadcasterId)});
  if(!(await hasViewerConsent(req))) return html(400,"StreamShield verification","Please open the verification page and choose Continue with KICK after reviewing the connection-information notice.");
  const network=await rpc<any>("streamshield_network_status",{p_broadcaster_id:broadcasterId});
  if(!network?.enabled) return html(404,"StreamShield verification","Network protection is not enabled for this channel.");
  const creds=await getAppCreds();
  const verifier=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge=bytesToBase64Url(await sha256Bytes(verifier));
  const state=await seal({
    v:2,flow:"network_gate",exp:Date.now()+10*60_000,verifier,broadcaster_id:broadcasterId,viewer_consent:true
  },creds.clientSecret);
  const auth=new URL("https://id.kick.com/oauth/authorize");
  auth.searchParams.set("response_type","code");
  auth.searchParams.set("client_id",creds.clientId);
  auth.searchParams.set("redirect_uri",OAUTH_CALLBACK);
  auth.searchParams.set("scope",NETWORK_VIEWER_SCOPES.join(" "));
  auth.searchParams.set("state",state);
  auth.searchParams.set("code_challenge",challenge);
  auth.searchParams.set("code_challenge_method","S256");
  return Response.redirect(auth.toString(),302);
}

async function handleVerificationCreate(req:Request) {
  const body:any=await readJson(req);
  const broadcasterId=Number(body?.broadcaster_id), userId=Number(body?.kick_user_id);
  const username=String(body?.kick_username??"").slice(0,100);
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!Number.isFinite(userId)||userId<=0) return json(400,{error:"invalid_verification_target"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const network=await rpc<any>("streamshield_network_status",{p_broadcaster_id:broadcasterId});
  if(!network?.enabled) return json(409,{error:"full_protection_required"});
  const token=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash=await sha256Hex(token);
  const expiresAt=new Date(Date.now()+30*60_000).toISOString();
  const created=await rpc<any>("streamshield_verification_create",{
    p_broadcaster_id:broadcasterId,p_kick_user_id:userId,p_kick_username:username,
    p_token_hash:tokenHash,p_expires_at:expiresAt,p_note:String(body?.note??"").slice(0,500)
  });
  const url=new URL(req.url);
  const verificationUrl=`${url.origin}/functions/v1/streamshield-backend/verification/start?request=${encodeURIComponent(token)}`;
  return json(200,{ok:true,request:created,verification_url:verificationUrl,expires_at:expiresAt});
}

async function handleVerificationStart(req:Request) {
  const u=new URL(req.url), rawToken=String(u.searchParams.get("request")??"");
  if(rawToken.length<32) return verificationHtml(400,"Channel Verification","This verification request is invalid.");
  const tokenHash=await sha256Hex(rawToken);
  const request=await rpc<any>("streamshield_verification_get_by_token",{p_token_hash:tokenHash});
  if(!request || request.status!=="pending") return verificationHtml(410,"Channel Verification","This verification request is no longer active. Return to the channel moderator if you still need access.");
  return verificationConsentPage({request:rawToken});
}

async function handleVerificationKick(req:Request) {
  const u=new URL(req.url), rawToken=String(u.searchParams.get("request")??"");
  if(rawToken.length<32) return verificationHtml(400,"Channel Verification","This verification request is invalid.");
  const requestHash=await sha256Hex(rawToken);
  const consentTicket=u.searchParams.get("consent_ticket")??"";
  if(req.method!=="POST"&&!consentTicket) return verificationConsentPage({request:rawToken});
  if(req.method==="POST"&&!(await hasViewerConsent(req))) return verificationHtml(400,"Channel Verification","Please open the verification page and choose Continue with KICK after reviewing the connection-information notice.");
  const request=await rpc<any>("streamshield_verification_get_by_token",{p_token_hash:requestHash});
  if(!request || request.status!=="pending") return verificationHtml(410,"Channel Verification","This verification request is no longer active.");
  const creds=await getAppCreds();
  if(req.method==="POST") {
    // Return through a top-level safe GET so an existing SameSite=Lax device
    // cookie is available. A cross-site consent POST must not reset that token.
    const receipt=await seal({flow:"viewer_consent",request_hash:requestHash,exp:Date.now()+5*60_000},creds.clientSecret);
    const next=new URL("/functions/v1/streamshield-backend/verification/kick",u.origin);
    next.searchParams.set("request",rawToken);
    next.searchParams.set("consent_ticket",receipt);
    return new Response(null,{status:303,headers:{location:next.toString(),"cache-control":"no-store","referrer-policy":"no-referrer"}});
  }
  let receipt:any;
  try { receipt=await unseal<any>(consentTicket,creds.clientSecret); } catch { return verificationHtml(400,"Channel Verification","The consent step has expired. Reopen the verification link and try again."); }
  if(receipt?.flow!=="viewer_consent"||receipt?.request_hash!==requestHash||!Number.isFinite(receipt?.exp)||receipt.exp<Date.now()) return verificationHtml(400,"Channel Verification","The consent step has expired. Reopen the verification link and try again.");
  let device=cookieValue(req,"ss_device");
  if(!/^[A-Za-z0-9_-]{32,128}$/.test(device)) device=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const verifier=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge=bytesToBase64Url(await sha256Bytes(verifier));
  const state=await seal({
    v:3,flow:"targeted_verification",exp:Date.now()+10*60_000,verifier,
    request_hash:requestHash,broadcaster_id:Number(request.broadcaster_id),expected_user_id:Number(request.kick_user_id),viewer_consent:true
  },creds.clientSecret);
  const auth=new URL("https://id.kick.com/oauth/authorize");
  auth.searchParams.set("response_type","code");
  auth.searchParams.set("client_id",creds.clientId);
  auth.searchParams.set("redirect_uri",OAUTH_CALLBACK);
  auth.searchParams.set("scope",NETWORK_VIEWER_SCOPES.join(" "));
  auth.searchParams.set("state",state);
  auth.searchParams.set("code_challenge",challenge);
  auth.searchParams.set("code_challenge_method","S256");
  return new Response(null,{status:303,headers:{location:auth.toString(),"set-cookie":deviceCookie(device),"cache-control":"no-store","referrer-policy":"no-referrer"}});
}

async function handleVerificationQueue(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const items=await rpc<any>("streamshield_verification_get_queue",{p_broadcaster_id:broadcasterId,p_limit:25});
  return json(200,{ok:true,items});
}

async function handleVerificationRecent(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const items=await rpc<any>("streamshield_verification_recent",{p_broadcaster_id:broadcasterId,p_limit:50});
  return json(200,{ok:true,items});
}

async function handleVerificationComplete(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id), id=String(body?.id??"");
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!id) return json(400,{error:"broadcaster_id_and_id_required"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const completed=await rpc<boolean>("streamshield_verification_complete",{
    p_broadcaster_id:broadcasterId,p_id:id,p_outcome:String(body?.outcome??"completed").slice(0,100)
  });
  return json(200,{ok:true,completed:Boolean(completed)});
}


const MOD_PERMISSIONS = {
  delete_message:true,
  verify:true,
  timeout:true,
  ban:true,
  unban:true,
  case_file:true,
  network_view:true
};

function safeModAction(value:string) {
  return ["delete_message","verification_request","timeout_10","permanent_ban","unban","case_file"].includes(value);
}
function modPermissionForAction(action:string) {
  return ({
    delete_message:"delete_message",
    verification_request:"verify",
    timeout_10:"timeout",
    permanent_ban:"ban",
    unban:"unban",
    case_file:"case_file"
  } as Record<string,string>)[action] || "";
}
async function getModeratorInvite(rawToken:string) {
  if(!/^[A-Za-z0-9_-]{32,128}$/.test(rawToken)) return null;
  const tokenHash=await sha256Hex(rawToken);
  const now=encodeURIComponent(new Date().toISOString());
  const rr=await rest(`streamshield_moderator_invites?invite_token_hash=eq.${tokenHash}&revoked_at=is.null&expires_at=gt.${now}&select=id,broadcaster_id,kick_user_id,kick_username,permissions,created_at,expires_at,redeemed_at&limit=1`,{headers:{accept:"application/json"}});
  return (await rr.json())?.[0]??null;
}
async function moderatorSession(req:Request) {
  const raw=(req.headers.get("x-streamshield-mod-session")??"").trim();
  if(!/^[A-Za-z0-9_-]{32,128}$/.test(raw)) return null;
  const hash=await sha256Hex(raw);
  const now=encodeURIComponent(new Date().toISOString());
  const sr=await rest(`streamshield_moderator_sessions?session_token_hash=eq.${hash}&revoked_at=is.null&expires_at=gt.${now}&select=id,broadcaster_id,kick_user_id,kick_username,expires_at&limit=1`,{headers:{accept:"application/json"}});
  const session=(await sr.json())?.[0];
  if(!session) return null;
  const mr=await rest(`streamshield_moderators?broadcaster_id=eq.${Number(session.broadcaster_id)}&kick_user_id=eq.${Number(session.kick_user_id)}&active=eq.true&select=broadcaster_id,kick_user_id,kick_username,permissions,active&limit=1`,{headers:{accept:"application/json"}});
  const moderator=(await mr.json())?.[0];
  if(!moderator) return null;
  return {...session,permissions:moderator.permissions||{}};
}
async function handleModeratorInstallInvite(req:Request) {
  const body:any=await readJson(req);
  const broadcasterId=Number(body?.broadcaster_id), userId=Number(body?.kick_user_id);
  const username=String(body?.kick_username??"").slice(0,100);
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!Number.isFinite(userId)||userId<=0) return json(400,{error:"valid_broadcaster_and_user_required"});
  if(userId===broadcasterId) return json(400,{error:"broadcaster_cannot_be_moderator"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const raw=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const hash=await sha256Hex(raw);
  const expiresAt=new Date(Date.now()+48*60*60_000).toISOString();
  await rest(`streamshield_moderator_invites?broadcaster_id=eq.${broadcasterId}&kick_user_id=eq.${userId}&redeemed_at=is.null&revoked_at=is.null`,{method:"PATCH",body:JSON.stringify({revoked_at:new Date().toISOString()})});
  const rr=await rest("streamshield_moderator_invites",{method:"POST",headers:{prefer:"return=representation"},body:JSON.stringify({
    broadcaster_id:broadcasterId,kick_user_id:userId,kick_username:username,invite_token_hash:hash,
    permissions:MOD_PERMISSIONS,expires_at:expiresAt
  })});
  const created=(await rr.json())?.[0];
  return json(200,{ok:true,invite:{id:created?.id,kick_user_id:userId,kick_username:username,expires_at:expiresAt},invite_url:`${PUBLIC_WEB_ORIGIN}/mod?invite=${encodeURIComponent(raw)}`});
}
async function handleModeratorInstallAccess(req:Request) {
  const url=new URL(req.url), broadcasterId=Number(url.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const [modsR,invitesR]=await Promise.all([
    rest(`streamshield_moderators?broadcaster_id=eq.${broadcasterId}&active=eq.true&select=kick_user_id,kick_username,permissions,approved_at,last_login_at&order=approved_at.desc`,{headers:{accept:"application/json"}}),
    rest(`streamshield_moderator_invites?broadcaster_id=eq.${broadcasterId}&revoked_at=is.null&redeemed_at=is.null&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=id,kick_user_id,kick_username,created_at,expires_at&order=created_at.desc`,{headers:{accept:"application/json"}})
  ]);
  return json(200,{ok:true,moderators:await modsR.json(),pending_invites:await invitesR.json()});
}
async function handleModeratorInstallRevoke(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id), userId=Number(body?.kick_user_id);
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!Number.isFinite(userId)||userId<=0) return json(400,{error:"valid_broadcaster_and_user_required"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const now=new Date().toISOString();
  await Promise.all([
    rest(`streamshield_moderators?broadcaster_id=eq.${broadcasterId}&kick_user_id=eq.${userId}`,{method:"PATCH",body:JSON.stringify({active:false,revoked_at:now})}),
    rest(`streamshield_moderator_sessions?broadcaster_id=eq.${broadcasterId}&kick_user_id=eq.${userId}&revoked_at=is.null`,{method:"PATCH",body:JSON.stringify({revoked_at:now})}),
    rest(`streamshield_moderator_invites?broadcaster_id=eq.${broadcasterId}&kick_user_id=eq.${userId}&revoked_at=is.null&redeemed_at=is.null`,{method:"PATCH",body:JSON.stringify({revoked_at:now})})
  ]);
  return json(200,{ok:true,revoked:true});
}
async function handleModeratorInstallCommands(req:Request) {
  const url=new URL(req.url), broadcasterId=Number(url.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const items=await rpc<any>("streamshield_moderator_claim_commands",{p_broadcaster_id:broadcasterId,p_limit:20});
  return json(200,{ok:true,items:Array.isArray(items)?items:[]});
}
async function handleModeratorInstallCommandComplete(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id), id=String(body?.id??"");
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!/^[0-9a-f-]{36}$/i.test(id)) return json(400,{error:"invalid_command"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const completed=await rpc<boolean>("streamshield_moderator_complete_command",{
    p_broadcaster_id:broadcasterId,p_id:id,p_ok:Boolean(body?.ok),
    p_outcome:String(body?.outcome??"").slice(0,200),p_result:body?.result??{}
  });
  return json(200,{ok:true,completed:Boolean(completed)});
}
async function handleModeratorInviteInfo(req:Request) {
  const raw=String(new URL(req.url).searchParams.get("invite")??"");
  const invite=await getModeratorInvite(raw);
  if(!invite) return modJson(410,{error:"invite_expired_or_invalid"});
  const cr=await rest(`streamshield_channels?broadcaster_id=eq.${Number(invite.broadcaster_id)}&select=broadcaster_id,username,slug&limit=1`,{headers:{accept:"application/json"}});
  const channel=(await cr.json())?.[0]??null;
  return modJson(200,{ok:true,invite:{kick_user_id:invite.kick_user_id,kick_username:invite.kick_username,expires_at:invite.expires_at},channel});
}
async function handleModeratorStart(req:Request) {
  const raw=String(new URL(req.url).searchParams.get("invite")??"");
  const invite=await getModeratorInvite(raw);
  if(!invite) return verificationResult(410,"Moderator Invite","This StreamShield moderator invite is invalid or expired.");
  const creds=await getAppCreds();
  const verifier=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge=bytesToBase64Url(await sha256Bytes(verifier));
  const state=await seal({
    v:4,flow:"moderator_invite",exp:Date.now()+10*60_000,verifier,
    invite_hash:await sha256Hex(raw),broadcaster_id:Number(invite.broadcaster_id),expected_user_id:Number(invite.kick_user_id)
  },creds.clientSecret);
  const auth=new URL("https://id.kick.com/oauth/authorize");
  auth.searchParams.set("response_type","code");
  auth.searchParams.set("client_id",creds.clientId);
  auth.searchParams.set("redirect_uri",OAUTH_CALLBACK);
  auth.searchParams.set("scope",NETWORK_VIEWER_SCOPES.join(" "));
  auth.searchParams.set("state",state);
  auth.searchParams.set("code_challenge",challenge);
  auth.searchParams.set("code_challenge_method","S256");
  return new Response(null,{status:302,headers:{location:auth.toString(),"cache-control":"no-store","referrer-policy":"no-referrer"}});
}
async function handleModeratorSnapshot(req:Request) {
  const mod=await moderatorSession(req);
  if(!mod) return modJson(401,{error:"moderator_session_invalid"});
  const broadcasterId=Number(mod.broadcaster_id), userId=Number(mod.kick_user_id);
  const after=encodeURIComponent(new Date(Date.now()-15*60_000).toISOString());
  const [channelR,chatR,verification,history,commandsR]=await Promise.all([
    rest(`streamshield_channels?broadcaster_id=eq.${broadcasterId}&select=broadcaster_id,username,slug,last_webhook_at,last_event_type&limit=1`,{headers:{accept:"application/json"}}),
    rest(`streamshield_webhook_events?broadcaster_id=eq.${broadcasterId}&event_type=eq.chat.message.sent&event_timestamp=gt.${after}&select=kick_chat_message_id,sender_id,sender_username,chat_content,event_timestamp&order=event_timestamp.desc&limit=50`,{headers:{accept:"application/json"}}),
    rpc<any>("streamshield_verification_recent",{p_broadcaster_id:broadcasterId,p_limit:30}),
    rpc<any>("streamshield_network_history",{p_broadcaster_id:broadcasterId,p_limit:30}),
    rest(`streamshield_moderator_commands?broadcaster_id=eq.${broadcasterId}&moderator_user_id=eq.${userId}&select=id,action,status,outcome,result,created_at,completed_at&order=created_at.desc&limit=20`,{headers:{accept:"application/json"}})
  ]);
  const safeNetworks=(Array.isArray(history)?history:[]).map((row:any)=>({
    network_label:String(row?.network_label??"Verified network"),
    blocked:Boolean(row?.blocked),source_username:row?.source_username??null,
    last_match_at:row?.last_match_at??null,match_count:Number(row?.match_count||0)
  }));
  return modJson(200,{ok:true,moderator:{kick_user_id:userId,kick_username:mod.kick_username,permissions:mod.permissions},
    channel:(await channelR.json())?.[0]??null,recent_chat:await chatR.json(),
    verification:Array.isArray(verification)?verification:[],networks:safeNetworks,commands:await commandsR.json()});
}
async function handleModeratorCommand(req:Request) {
  const mod=await moderatorSession(req);
  if(!mod) return modJson(401,{error:"moderator_session_invalid"});
  const body:any=await readJson(req), action=String(body?.action??"");
  if(!safeModAction(action)) return modJson(400,{error:"unsupported_action"});
  const permission=modPermissionForAction(action);
  if(!permission || mod.permissions?.[permission]!==true) return modJson(403,{error:"permission_denied"});
  const payload:any={};
  const userId=Number(body?.userId);
  if(action!=="delete_message") {
    if(!Number.isFinite(userId)||userId<=0) return modJson(400,{error:"valid_user_required"});
    payload.userId=Math.trunc(userId);
    payload.username=String(body?.username??"").slice(0,100);
  }
  if(action==="delete_message") {
    const messageId=String(body?.messageId??"").slice(0,200);
    if(!messageId) return modJson(400,{error:"message_id_required"});
    payload.messageId=messageId;
    if(Number.isFinite(userId)&&userId>0) payload.userId=Math.trunc(userId);
    payload.username=String(body?.username??"").slice(0,100);
  }
  const rr=await rest("streamshield_moderator_commands",{method:"POST",headers:{prefer:"return=representation"},body:JSON.stringify({
    broadcaster_id:Number(mod.broadcaster_id),moderator_user_id:Number(mod.kick_user_id),
    moderator_username:String(mod.kick_username??"").slice(0,100),action,payload,status:"queued"
  })});
  const row=(await rr.json())?.[0];
  return modJson(200,{ok:true,command:{id:row?.id,status:row?.status??"queued",action}});
}
async function handleModeratorCommandStatus(req:Request) {
  const mod=await moderatorSession(req);
  if(!mod) return modJson(401,{error:"moderator_session_invalid"});
  const id=String(new URL(req.url).searchParams.get("id")??"");
  if(!/^[0-9a-f-]{36}$/i.test(id)) return modJson(400,{error:"invalid_command_id"});
  const rr=await rest(`streamshield_moderator_commands?id=eq.${id}&broadcaster_id=eq.${Number(mod.broadcaster_id)}&moderator_user_id=eq.${Number(mod.kick_user_id)}&select=id,action,status,outcome,result,created_at,claimed_at,completed_at&limit=1`,{headers:{accept:"application/json"}});
  const command=(await rr.json())?.[0];
  if(!command) return modJson(404,{error:"command_not_found"});
  return modJson(200,{ok:true,command});
}
async function handleModeratorLogout(req:Request) {
  const raw=(req.headers.get("x-streamshield-mod-session")??"").trim();
  if(/^[A-Za-z0-9_-]{32,128}$/.test(raw)) {
    const hash=await sha256Hex(raw);
    await rest(`streamshield_moderator_sessions?session_token_hash=eq.${hash}&revoked_at=is.null`,{method:"PATCH",body:JSON.stringify({revoked_at:new Date().toISOString()})});
  }
  return modJson(200,{ok:true});
}
async function handleOauthCallback(req:Request) {
  const u=new URL(req.url), code=u.searchParams.get("code")??"", state=u.searchParams.get("state")??"";
  if(!code||!state) return html(400,"StreamShield connection failed","Kick did not return a complete authorization response.");
  try {
    const creds=await getAppCreds();
    const st=await unseal<any>(state,creds.clientSecret);
    if(Number(st?.exp)<Date.now()) throw new Error("expired state");
    const token=await exchangeCode(code,String(st?.verifier??""),creds);

    if(st?.v===4 && st?.flow==="moderator_invite") {
      const broadcasterId=Number(st?.broadcaster_id), expectedUserId=Number(st?.expected_user_id), inviteHash=String(st?.invite_hash??"");
      const ir=await rest(`streamshield_moderator_invites?invite_token_hash=eq.${inviteHash}&broadcaster_id=eq.${broadcasterId}&kick_user_id=eq.${expectedUserId}&revoked_at=is.null&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=id,broadcaster_id,kick_user_id,kick_username,permissions,redeemed_at&limit=1`,{headers:{accept:"application/json"}});
      const invite=(await ir.json())?.[0];
      if(!invite) return verificationResult(410,"Moderator Invite","This StreamShield moderator invite is no longer active.");
      const users=await kickGet(token.access_token,"users");
      const user=users?.data?.[0];
      if(!user?.user_id) throw new Error("Kick moderator identity lookup failed");
      if(Number(user.user_id)!==expectedUserId) return verificationResult(403,"Wrong KICK Account","This moderator invite belongs to a different KICK account.");
      const now=new Date().toISOString();
      await rest("streamshield_moderators?on_conflict=broadcaster_id,kick_user_id",{method:"POST",headers:{prefer:"resolution=merge-duplicates,return=minimal"},body:JSON.stringify({
        broadcaster_id:broadcasterId,kick_user_id:expectedUserId,kick_username:String(user.name??"").slice(0,100),
        permissions:invite.permissions||MOD_PERMISSIONS,active:true,approved_at:now,last_login_at:now,revoked_at:null
      })});
      await rest(`streamshield_moderator_invites?id=eq.${invite.id}`,{method:"PATCH",body:JSON.stringify({redeemed_at:now})});
      const sessionRaw=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(36)));
      await rest("streamshield_moderator_sessions",{method:"POST",headers:{prefer:"return=minimal"},body:JSON.stringify({
        broadcaster_id:broadcasterId,kick_user_id:expectedUserId,kick_username:String(user.name??"").slice(0,100),
        session_token_hash:await sha256Hex(sessionRaw),expires_at:new Date(Date.now()+12*60*60_000).toISOString()
      })});
      const target=new URL("/mod-panel",PUBLIC_WEB_ORIGIN);
      target.searchParams.set("session",sessionRaw);
      return new Response(null,{status:302,headers:{location:target.toString(),"cache-control":"no-store","referrer-policy":"no-referrer"}});
    }

    if(st?.v===3 && st?.flow==="targeted_verification") {
      if(st.viewer_consent!==true) return verificationHtml(400,"Channel Verification","Please reopen the verification link and review the connection-information notice before continuing.");
      const broadcasterId=Number(st?.broadcaster_id), expectedUserId=Number(st?.expected_user_id);
      const request=await rpc<any>("streamshield_verification_get_by_token",{p_token_hash:String(st?.request_hash??"")});
      if(!request || request.status!=="pending" || Number(request.broadcaster_id)!==broadcasterId) return verificationHtml(410,"Channel Verification","This verification request is no longer active.");
      const users=await kickGet(token.access_token,"users");
      const user=users?.data?.[0];
      if(!user?.user_id) throw new Error("Kick viewer identity lookup failed");
      if(Number(user.user_id)!==expectedUserId) return verificationHtml(403,"Use the requested KICK account","This verification request belongs to a different KICK account. Sign into the requested account and try again.");
      const edge=edgeClientIp(req);
      if(!edge.ip) return verificationHtml(503,"Channel Verification","Connection verification could not be completed from this browser.");
      let device=cookieValue(req,"ss_device");
      if(!/^[A-Za-z0-9_-]{32,128}$/.test(device)) device=bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
      const deviceHash=await sha256Hex("streamshield-device-v1:"+device+":"+creds.clientSecret);
      const [observed,deviceResult]=await Promise.all([
        rpc<any>("streamshield_network_observe",{
          p_broadcaster_id:broadcasterId,p_kick_user_id:Number(user.user_id),
          p_kick_username:String(user.name??""),p_ip:edge.ip,p_source:edge.source
        }),
        rpc<any>("streamshield_device_observe",{
          p_broadcaster_id:broadcasterId,p_kick_user_id:Number(user.user_id),
          p_kick_username:String(user.name??""),p_device_hash:deviceHash,p_retention_days:90
        })
      ]);
      const reasons:any[]=[];
      let score=0, status="verified";
      if(observed?.blocked_network) {
        score=100; status="blocked";
        reasons.push({signal:"exact_blocked_network",weight:100,label:"Exact previously blocked network match"});
      } else if(deviceResult?.blocked_device) {
        score=85; status="review";
        reasons.push({signal:"blocked_device_token",weight:85,label:"Previously blocked first-party device token"});
      } else if(Number(deviceResult?.other_accounts||0)>0) {
        score=25;
        reasons.push({signal:"device_seen_on_other_accounts",weight:25,label:"Device token previously verified with another KICK account"});
      }
      const recorded=await rpc<any>("streamshield_verification_record_result",{
        p_request_id:String(request.id),p_device_hash:deviceHash,p_status:status,
        p_risk_score:score,p_risk_reasons:reasons
      });
      if(!recorded) return verificationHtml(410,"Channel Verification","This request has expired or a newer moderation decision replaced it. Ask the channel moderator to review chat access.");
      if(status==="blocked") return verificationHtml(403,"Channel Verification","This channel's security policy denied chat access. Contact the moderation team if you believe this is an error.","",deviceCookie(device));
      if(status==="review") return verificationHtml(200,"Verification Complete","Verification finished. A moderator review is required before chat access is restored.","",deviceCookie(device));
      return verificationHtml(200,"Verification Complete","Your KICK account has been verified. Chat access should restore automatically in a few seconds.","",deviceCookie(device));
    }

    if(st?.v===2 && st?.flow==="network_gate") {
      if(st.viewer_consent!==true) return html(400,"StreamShield verification","Please reopen the verification link and review the connection-information notice before continuing.");
      const broadcasterId=Number(st?.broadcaster_id);
      if(!Number.isFinite(broadcasterId)||broadcasterId<=0) throw new Error("invalid network gate channel");
      const users=await kickGet(token.access_token,"users");
      const user=users?.data?.[0];
      if(!user?.user_id) throw new Error("Kick viewer identity lookup failed");
      const edge=edgeClientIp(req);
      if(!edge.ip) return html(503,"StreamShield verification unavailable","Network verification could not be completed from this connection.");
      const observed=await rpc<any>("streamshield_network_observe",{
        p_broadcaster_id:broadcasterId,
        p_kick_user_id:Number(user.user_id),
        p_kick_username:String(user.name??""),
        p_ip:edge.ip,
        p_source:edge.source
      });
      if(observed?.blocked_network) {
        return html(403,"StreamShield access denied","This channel's security policy denied this verification. Return to the streamer for assistance if you believe this is an error.");
      }
      return html(200,"StreamShield verification complete","Your KICK account and connection were verified for this protected channel. StreamShield does not store or display your full IP address; it keeps only a keyed one-way network identifier for exact-match moderation. You may close this window and return to the stream.");
    }

    if(st?.v!==1 || !validLocalCallback(String(st?.local_callback??""))) throw new Error("invalid state");
    const [users,channels]=await Promise.all([kickGet(token.access_token,"users"),kickGet(token.access_token,"channels")]);
    const user=users?.data?.[0], channel=channels?.data?.[0];
    if(!user||!channel) throw new Error("Kick identity lookup failed");
    const jti=crypto.randomUUID();
    const ticket=await seal({
      v:1,jti,exp:Date.now()+5*60_000,install_hash:String(st.install_hash),
      token,broadcaster_id:Number(user.user_id),username:String(user.name??""),slug:String(channel.slug??"")
    },creds.clientSecret);
    const target=new URL(String(st.local_callback));
    target.searchParams.set("ticket",ticket);
    return Response.redirect(target.toString(),302);
  } catch(e) {
    return html(400,"StreamShield connection failed","The Kick authorization could not be completed. Return to StreamShield and try again.");
  }
}
async function handleOauthRedeem(req:Request) {
  const body:any=await readJson(req), ticket=String(body?.ticket??""), installKey=String(body?.install_key??"");
  if(!ticket || installKey.length<32) return json(400,{error:"ticket_and_install_key_required"});
  const creds=await getAppCreds();
  let t:any;
  try { t=await unseal<any>(ticket,creds.clientSecret); } catch { return json(400,{error:"invalid_ticket"}); }
  if(t?.v!==1 || Number(t?.exp)<Date.now()) return json(400,{error:"expired_ticket"});
  if(!safeEqualHex(String(t.install_hash??""),await sha256Hex(installKey))) return json(401,{error:"installation_mismatch"});
  try {
    await rest("streamshield_oauth_redeemed",{method:"POST",headers:{prefer:"return=minimal"},body:JSON.stringify({
      jti:String(t.jti),broadcaster_id:Number(t.broadcaster_id)||null,expires_at:new Date(Number(t.exp)).toISOString()
    })});
  } catch(e) {
    if((e as any)?.status===409) return json(409,{error:"ticket_already_redeemed"});
    throw e;
  }
  return json(200,{ok:true,token:t.token,broadcaster_id:t.broadcaster_id,username:t.username,slug:t.slug});
}
async function handleOauthRefresh(req:Request) {
  const body:any=await readJson(req);
  const broadcasterId=Number(body?.broadcaster_id), refresh=String(body?.refresh_token??"");
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!refresh) return json(400,{error:"broadcaster_id_and_refresh_token_required"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const creds=await getAppCreds();
  return json(200,{ok:true,token:await refreshToken(refresh,creds)});
}

async function handleRegister(req: Request) {
  const body:any=await readJson(req);
  const token=String(body?.kick_access_token??""), installKey=String(body?.install_key??"");
  if(!token||installKey.length<32) return json(400,{error:"token_and_install_key_required"});
  try {
    const [users,channels]=await Promise.all([kickGet(token,"users"),kickGet(token,"channels")]);
    const user=users?.data?.[0], channel=channels?.data?.[0];
    if(!user||!channel) return json(502,{error:"kick_identity_lookup_failed"});
    const broadcasterId=Number(user.user_id);
    if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(502,{error:"invalid_kick_identity"});
    const row={broadcaster_id:broadcasterId,username:String(user.name??""),slug:String(channel.slug??""),install_key_hash:await sha256Hex(installKey),registered_at:new Date().toISOString(),updated_at:new Date().toISOString()};
    await rest("streamshield_channels?on_conflict=broadcaster_id",{method:"POST",headers:{prefer:"resolution=merge-duplicates,return=minimal"},body:JSON.stringify(row)});
    return json(200,{ok:true,broadcaster_id:broadcasterId,username:row.username,slug:row.slug,kick_token_stored:false});
  } catch(e) {
    return json(502,{error:"registration_failed",detail:e instanceof Error?e.message:String(e)});
  }
}

async function handleWebhook(req: Request) {
  const declared=Number(req.headers.get("content-length")??0); if(declared>MAX_BODY) return json(413,{error:"body_too_large"});
  const raw=new Uint8Array(await req.arrayBuffer()); if(raw.byteLength>MAX_BODY) return json(413,{error:"body_too_large"});
  const messageId=req.headers.get("kick-event-message-id")??"", timestamp=req.headers.get("kick-event-message-timestamp")??"", signature=req.headers.get("kick-event-signature")??"", eventType=req.headers.get("kick-event-type")??"";
  if(!messageId||!timestamp||!signature||!eventType) return json(400,{error:"missing_kick_headers"});
  const sentAt=Date.parse(timestamp), age=Date.now()-sentAt;
  if(!Number.isFinite(sentAt)||age>48*60*60_000||age< -5*60_000) return json(400,{error:"timestamp_outside_window"});
  try { if(!(await verifyKick(raw,messageId,timestamp,signature))) return json(401,{error:"invalid_signature"}); }
  catch(e){ return json(503,{error:"signature_verification_unavailable",detail:e instanceof Error?e.message:String(e)}); }
  let payload:any; try{payload=JSON.parse(dec.decode(raw));}catch{return json(400,{error:"invalid_json"});}
  const broadcasterId=Number(payload?.broadcaster?.user_id); if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"missing_broadcaster"});
  const eventAtRaw=payload?.created_at??payload?.metadata?.created_at??payload?.timestamp??timestamp;
  const eventAt=Number.isFinite(Date.parse(String(eventAtRaw)))?new Date(Date.parse(String(eventAtRaw))).toISOString():new Date(sentAt).toISOString();
  const senderId=Number(payload?.sender?.user_id)||null, senderUsername=payload?.sender?.username?String(payload.sender.username).slice(0,100):null;
  const chatMessageId=payload?.message_id?String(payload.message_id).slice(0,200):null;
  const chatContent=eventType==="chat.message.sent"?String(payload?.content??"").slice(0,5000):null;
  const followerId=Number(payload?.follower?.user_id)||null, isLive=eventType==="livestream.status.updated"?Boolean(payload?.is_live):null, receivedAt=new Date().toISOString();
  const banMeta=eventType==="moderation.banned"?{
    banned_user_id:Number(payload?.banned_user?.user_id)||0,
    permanent:payload?.metadata?.expires_at===null,
    created_at:eventAt,
    expires_at:payload?.metadata?.expires_at??null
  }:null;
  try {
    // Cancel older verification outcomes before making the ban event visible
    // to polling desktops. A storage retry is safe because cancellation is
    // idempotent and only touches requests created before this signed event.
    if(banMeta?.permanent && banMeta.banned_user_id>0) await rpc<any>("streamshield_verification_cancel_for_ban",{
      p_broadcaster_id:broadcasterId,p_kick_user_id:banMeta.banned_user_id,p_event_at:eventAt
    });
    await cleanupExpired();
    await rest("streamshield_webhook_events?on_conflict=kick_message_id",{method:"POST",headers:{prefer:"resolution=ignore-duplicates,return=minimal"},body:JSON.stringify({
      kick_message_id:messageId,broadcaster_id:broadcasterId,event_type:eventType.slice(0,120),event_timestamp:eventAt,received_at:receivedAt,
      sender_id:senderId,sender_username:senderUsername,kick_chat_message_id:chatMessageId,chat_content:chatContent,chat_content_hash:chatContent?await sha256Hex(chatContent):null,
      follower_id:followerId,is_live:isLive,meta:banMeta??{},content_expires_at:chatContent?new Date(Date.now()+15*60_000).toISOString():null,row_expires_at:new Date(Date.now()+24*60*60_000).toISOString()
    })});
    await rest("streamshield_channels?on_conflict=broadcaster_id",{method:"POST",headers:{prefer:"resolution=merge-duplicates,return=minimal"},body:JSON.stringify({
      broadcaster_id:broadcasterId,username:String(payload?.broadcaster?.username??payload?.broadcaster?.name??"").slice(0,100),
      slug:String(payload?.broadcaster?.channel_slug??payload?.broadcaster?.slug??"").slice(0,200),updated_at:receivedAt,last_webhook_at:receivedAt,last_event_type:eventType.slice(0,120),webhook_verified:true
    })});
    if(eventType==="moderation.banned") {
      const bannedId=Number(payload?.banned_user?.user_id)||0;
      if(bannedId>0) {
        await rpc<any>("streamshield_network_mark_banned",{
          p_broadcaster_id:broadcasterId,
          p_kick_user_id:bannedId,
          p_kick_username:String(payload?.banned_user?.username??"").slice(0,100),
          p_reason:String(payload?.metadata?.reason??"").slice(0,500),
          p_permanent:Boolean(banMeta?.permanent)
        });
        await rpc<any>("streamshield_device_mark_banned",{
          p_broadcaster_id:broadcasterId,
          p_kick_user_id:bannedId,
          p_kick_username:String(payload?.banned_user?.username??"").slice(0,100),
          p_reason:String(payload?.metadata?.reason??"").slice(0,500),
          p_permanent:Boolean(banMeta?.permanent)
        });
      }
    }
    return new Response(null,{status:204});
  } catch(e) {
    return json(503,{error:"webhook_storage_failed",detail:e instanceof Error?e.message:String(e)},{"retry-after":"5"});
  }
}

async function handleEvents(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  await cleanupExpired();
  const afterRaw=u.searchParams.get("after")||new Date(Date.now()-20*60_000).toISOString();
  const after=Number.isFinite(Date.parse(afterRaw))?new Date(Date.parse(afterRaw)).toISOString():new Date(Date.now()-20*60_000).toISOString();
  const r=await rest(`streamshield_webhook_events?broadcaster_id=eq.${broadcasterId}&received_at=gt.${encodeURIComponent(after)}&select=id,kick_message_id,event_type,event_timestamp,received_at,sender_id,sender_username,kick_chat_message_id,chat_content,follower_id,is_live,meta&order=received_at.asc&limit=200`,{headers:{accept:"application/json"}});
  return json(200,{ok:true,events:await r.json()});
}
async function handleStatus(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const r=await rest(`streamshield_channels?broadcaster_id=eq.${broadcasterId}&select=broadcaster_id,username,slug,last_webhook_at,last_event_type,webhook_verified,updated_at&limit=1`,{headers:{accept:"application/json"}});
  return json(200,{ok:true,channel:(await r.json())?.[0]??null});
}
async function handleNetworkStatus(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  return json(200,{ok:true,network:await rpc<any>("streamshield_network_status",{p_broadcaster_id:broadcasterId})});
}
async function handleNetworkSettings(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id);
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const result=await rpc<any>("streamshield_network_set_settings",{
    p_broadcaster_id:broadcasterId,
    p_enabled:Boolean(body?.enabled),
    p_auto_ban_exact_network_match:Boolean(body?.auto_ban_exact_network_match),
    p_observation_retention_days:Number(body?.observation_retention_days)||30
  });
  return json(200,result);
}
async function handleNetworkHistory(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const history=await rpc<any>("streamshield_network_history",{p_broadcaster_id:broadcasterId,p_limit:100});
  const safeHistory=(Array.isArray(history)?history:[]).map((row:any)=>{ const {ip,ip_address,display_ip,...rest}=row??{}; return rest; });
  return json(200,{ok:true,history:safeHistory});
}
async function handleNetworkUnblock(req:Request) {
  const body:any=await readJson(req);
  const broadcasterId=Number(body?.broadcaster_id);
  const networkHash=String(body?.network_hash??"");
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||networkHash.length!==64) return json(400,{error:"broadcaster_id_and_network_hash_required"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const result=await rpc<any>("streamshield_network_unblock",{
    p_broadcaster_id:broadcasterId,
    p_network_hash:networkHash,
    p_reason:String(body?.reason??"manual_un_ip_ban")
  });
  return json(200,result);
}
async function handleNetworkQueue(req:Request) {
  const u=new URL(req.url), broadcasterId=Number(u.searchParams.get("broadcaster_id"));
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const items=await rpc<any>("streamshield_network_get_queue",{p_broadcaster_id:broadcasterId,p_limit:25});
  return json(200,{ok:true,items});
}
async function handleNetworkQueueComplete(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id), id=String(body?.id??"");
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0||!id) return json(400,{error:"broadcaster_id_and_id_required"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  const completed=await rpc<boolean>("streamshield_network_complete_queue",{
    p_broadcaster_id:broadcasterId,p_id:id,p_outcome:String(body?.outcome??"completed")
  });
  return json(200,{ok:true,completed:Boolean(completed)});
}
async function handleDeleteData(req:Request) {
  const body:any=await readJson(req), broadcasterId=Number(body?.broadcaster_id);
  if(!Number.isFinite(broadcasterId)||broadcasterId<=0) return json(400,{error:"invalid_broadcaster_id"});
  if(!(await authorizeInstall(req,broadcasterId))) return json(401,{error:"unauthorized_installation"});
  await rpc<boolean>("streamshield_network_delete_broadcaster",{p_broadcaster_id:broadcasterId});
  await rpc<boolean>("streamshield_verification_delete_broadcaster",{p_broadcaster_id:broadcasterId});
  await rest(`streamshield_webhook_events?broadcaster_id=eq.${broadcasterId}`,{method:"DELETE"});
  await rest(`streamshield_channels?broadcaster_id=eq.${broadcasterId}`,{method:"DELETE"});
  return json(200,{ok:true,deleted:true});
}

Deno.serve(async (req:Request)=>{
  const path=new URL(req.url).pathname;
  try {
    if(req.method==="GET" && (path.endsWith("/health")||path.endsWith("/streamshield-backend"))) {
      try {
        // getAppStatus is itself a database read, so it is sufficient to verify DB
        // connectivity. Avoid a second sequential REST query on this latency-sensitive route.
        const status=await getAppStatus();
        return json(200,{ok:true,service:"streamshield-backend",database:true,kick_primary:true,app_configured:Boolean(status?.bootstrap_used),public_version:status?.public_version??null,stores_kick_oauth_tokens:false,chat_buffer_minutes:15,event_retention_hours:24,network_protection:true,targeted_verification:true,first_party_device_tokens:true,invasive_device_fingerprinting:false,stores_raw_viewer_ips:false,stores_encrypted_verified_ips:false,stores_hashed_network_identifiers:true});
      } catch(e) {
        return json(503,{ok:false,service:"streamshield-backend",database:false,error:e instanceof Error?e.message:String(e)});
      }
    }
    if(req.method==="GET" && path.endsWith("/release/latest")) {
      const r=await rest("streamshield_releases?channel=eq.beta&select=version,channel,download_url,sha256,published_at,notes&order=published_at.desc&limit=1",{headers:{accept:"application/json"}});
      return json(200,{ok:true,release:(await r.json())?.[0]??null});
    }
    if(req.method==="OPTIONS" && path.includes("/moderator/")) return new Response(null,{status:204,headers:MOD_CORS});
    if(req.method==="POST" && path.endsWith("/moderator/install/invite")) return handleModeratorInstallInvite(req);
    if(req.method==="GET" && path.endsWith("/moderator/install/access")) return handleModeratorInstallAccess(req);
    if(req.method==="POST" && path.endsWith("/moderator/install/revoke")) return handleModeratorInstallRevoke(req);
    if(req.method==="GET" && path.endsWith("/moderator/install/commands")) return handleModeratorInstallCommands(req);
    if(req.method==="POST" && path.endsWith("/moderator/install/commands/complete")) return handleModeratorInstallCommandComplete(req);
    if(req.method==="GET" && path.endsWith("/moderator/invite-info")) return handleModeratorInviteInfo(req);
    if(req.method==="GET" && path.endsWith("/moderator/start")) return handleModeratorStart(req);
    if(req.method==="GET" && path.endsWith("/moderator/snapshot")) return handleModeratorSnapshot(req);
    if(req.method==="POST" && path.endsWith("/moderator/command")) return handleModeratorCommand(req);
    if(req.method==="GET" && path.endsWith("/moderator/command/status")) return handleModeratorCommandStatus(req);
    if(req.method==="POST" && path.endsWith("/moderator/logout")) return handleModeratorLogout(req);
    if(req.method==="POST" && path.endsWith("/owner-bootstrap")) return handleOwnerBootstrap(req);
    if(req.method==="POST" && path.endsWith("/oauth/start")) return handleOauthStart(req);
    if(req.method==="GET" && path.endsWith("/oauth/kick/callback")) return handleOauthCallback(req);
    if(req.method==="POST" && path.endsWith("/oauth/redeem")) return handleOauthRedeem(req);
    if(req.method==="POST" && path.endsWith("/oauth/refresh")) return handleOauthRefresh(req);
    if(req.method==="POST" && path.endsWith("/register")) return handleRegister(req);
    if(req.method==="POST" && path.endsWith("/kick-webhook")) return handleWebhook(req);
    if(req.method==="GET" && path.endsWith("/events")) return handleEvents(req);
    if(req.method==="GET" && path.endsWith("/status")) return handleStatus(req);
    if(req.method==="POST" && path.endsWith("/verification/request")) return handleVerificationCreate(req);
    if(req.method==="GET" && path.endsWith("/verification/start")) return handleVerificationStart(req);
    if((req.method==="GET"||req.method==="POST") && path.endsWith("/verification/kick")) return handleVerificationKick(req);
    if(req.method==="GET" && path.endsWith("/verification/queue")) return handleVerificationQueue(req);
    if(req.method==="GET" && path.endsWith("/verification/recent")) return handleVerificationRecent(req);
    if(req.method==="POST" && path.endsWith("/verification/complete")) return handleVerificationComplete(req);
    if((req.method==="GET"||req.method==="POST") && path.endsWith("/network/start")) return handleNetworkOauthStart(req);
    if(req.method==="GET" && path.endsWith("/network/status")) return handleNetworkStatus(req);
    if(req.method==="GET" && path.endsWith("/network/history")) return handleNetworkHistory(req);
    if(req.method==="POST" && path.endsWith("/network/unblock")) return handleNetworkUnblock(req);
    if(req.method==="POST" && path.endsWith("/network/settings")) return handleNetworkSettings(req);
    if(req.method==="GET" && path.endsWith("/network/queue")) return handleNetworkQueue(req);
    if(req.method==="POST" && path.endsWith("/network/queue/complete")) return handleNetworkQueueComplete(req);
    if(req.method==="POST" && path.endsWith("/delete-data")) return handleDeleteData(req);
    return json(404,{error:"not_found"});
  } catch(e) {
    const status=(e as any)?.status===413?413:500;
    return json(status,{error:status===413?"body_too_large":"internal_error",detail:e instanceof Error?e.message:String(e)});
  }
});

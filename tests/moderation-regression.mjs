import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { RuntimeStore } from '../desktop/app/dist/src/store.js';
import { summarizeBanShield, validateVerificationResult, createVerificationDeliveryCache } from '../desktop/app/dist/src/quietShield.js';

const source = await readFile(new URL('../desktop/app/dist/src/server.js', import.meta.url), 'utf8');
function extract(name) {
  const start = new RegExp('(?:async )?function ' + name + '\\(').exec(source)?.index;
  assert.notEqual(start, undefined, name + ' exists');
  const rest = source.slice(start);
  const next = /\n(?:async )?function \w+\(/.exec(rest);
  return rest.slice(0, next?.index ?? rest.length);
}
const names = ['verificationCacheKey', 'withNetworkPolicy', 'describeBanShield', 'verificationChatText', 'postVerificationChatMessage', 'processNetworkEnforcementQueue', 'withUserModeration', 'invalidateVerificationLocks', 'applyPermanentUserBan', 'applyUserTimeout', 'releaseUserRestriction', 'observePermanentUserBan', 'requestUserVerification', 'processVerificationQueue', 'protectionHealth', 'runPreflight'];
const code = names.map(extract).join('\n');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function fixture() {
  const session = { broadcasterId: 123, remoteBackendRegistered: true, remoteInstallKey: 'fixture-only', remoteBackendError: '', remoteLastPollAt: Date.now(), lastWebhookAt: Date.now(), subscriptionHealthy: true, verificationLocks: { req: 456 }, permanentBanHolds: {}, networkProtection: { enabled: true } };
  const f = { session, calls: [], outcomes: [], saved: [], queueReads: 0, isBanned: true, hooks: {} };
  const context = {
    Date, Number, String, Object, Map, Promise, Error, console,
    summarizeBanShield, validateVerificationResult, verificationDeliveryCache: createVerificationDeliveryCache(), networkPolicyTails: new Map(),
    remoteBackendConfigured: true, publicWebhookAvailable: true, remoteBackendUrl: 'https://fixture.invalid', userModerationTails: new Map(),
    fetch: () => { throw new Error('Live network access is forbidden in regression tests'); },
    store: { saveSession: async s => { f.saved.push(JSON.parse(JSON.stringify({ locks: s.verificationLocks, holds: s.permanentBanHolds }))); } },
    getRemoteVerificationQueue: async () => { f.queueReads++; return f.hooks.queue ? await f.hooks.queue(f.queueReads) : { items: [{ id: 'req', kick_user_id: 456, status: 'verified' }] }; },
    completeRemoteVerification: async (_url, _channel, _key, id, outcome) => { f.outcomes.push({ id, outcome }); if (f.hooks.complete) await f.hooks.complete(id, outcome); return { ok: true, completed: true }; },
    createRemoteVerificationRequest: async () => { f.calls.push('create'); return f.hooks.create ? await f.hooks.create() : { request: { id: 'new-request' }, verification_url: 'https://fixture.invalid/verification/start?request='+'A'.repeat(32), expires_at:new Date(Date.now()+30*60_000).toISOString() }; },
    getRemoteVerificationRecent: async () => f.hooks.recent ? await f.hooks.recent() : { items: [] },
    getRemoteNetworkHistory: async () => f.hooks.history ? await f.hooks.history() : { history: [] },
    getRemoteNetworkStatus: async () => f.hooks.policy ? await f.hooks.policy() : { network: { enabled: true, auto_ban_exact_network_match: false } },
    getRemoteNetworkQueue: async () => f.hooks.networkQueue ? await f.hooks.networkQueue() : { items: [{ id:'network-match',kick_user_id:456,kick_username:'viewer' }] },
    completeRemoteNetworkQueue: async (_url,_channel,_key,id,outcome) => { f.outcomes.push({id,outcome}); },
    syncNetworkProtection: async () => {},
    sendKickChatMessage: async (_token,_channel,content) => { if(f.hooks.chat) await f.hooks.chat(content); f.calls.push('chat'); return {data:{message_id:'chat-fixture'}}; },
    ensureFreshToken: async () => f.hooks.token ? await f.hooks.token() : 'fixture-token',
    banKickUser: async () => { if (f.hooks.ban) await f.hooks.ban(); f.calls.push('ban'); f.isBanned = true; },
    unbanKickUser: async () => { if (f.hooks.unban) await f.hooks.unban(); f.calls.push('unban'); f.isBanned = false; },
    timeoutKickUser: async () => { if (f.hooks.timeout) await f.hooks.timeout(); f.calls.push('timeout'); f.isBanned = true; },
    recordAction: async (_session, action) => { f.lastAction = action; }, pushEvent: () => {}, broadcast: () => {}, reconcileKickSubscriptions: async () => {},
  };
  f.context = vm.createContext(context);
  vm.runInContext(code, f.context);
  return f;
}
const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test('clean verification is automatically released after a fresh backend recheck', async () => {
  const f = fixture(); await f.context.processVerificationQueue(f.session);
  assert.deepEqual(f.calls, ['unban']); assert.equal(f.queueReads, 2);
  assert.equal(f.session.verificationLocks.req, undefined); assert.equal(f.isBanned, false);
  assert.equal(f.outcomes.at(-1).outcome, 'chat_released_clean');
});
test('a permanent ban queued while release awaits its token finishes after the release', async () => {
  const f = fixture(), entered = deferred(), gate = deferred(); let first = true;
  f.hooks.token = async () => { if (first) { first = false; entered.resolve(); await gate.promise; } return 'fixture-token'; };
  const releasing = f.context.processVerificationQueue(f.session); await entered.promise;
  const banning = f.context.applyPermanentUserBan(f.session, 456, 'moderator intent');
  assert.deepEqual(f.calls, []); gate.resolve(); await Promise.all([releasing, banning]);
  assert.deepEqual(f.calls, ['unban', 'ban']); assert.equal(f.isBanned, true);
  assert.ok(f.session.permanentBanHolds[456]); assert.equal(f.session.verificationLocks.req, undefined);
});
test('a permanent ban already running prevents a queued automatic release', async () => {
  const f = fixture(), entered = deferred(), gate = deferred();
  f.hooks.ban = async () => { assert.equal(f.saved.at(-1).locks.req, undefined); entered.resolve(); await gate.promise; };
  const banning = f.context.applyPermanentUserBan(f.session, 456, 'moderator intent'); await entered.promise;
  const releasing = f.context.processVerificationQueue(f.session); gate.resolve(); await Promise.all([banning, releasing]);
  assert.deepEqual(f.calls, ['ban']); assert.equal(f.isBanned, true);
});
test('an observed external permanent ban while token refresh is pending prevents DELETE', async () => {
  const f = fixture(), entered = deferred(), gate = deferred();
  f.hooks.token = async () => { entered.resolve(); await gate.promise; return 'fixture-token'; };
  const releasing = f.context.processVerificationQueue(f.session); await entered.promise;
  await f.context.observePermanentUserBan(f.session, 456, new Date().toISOString());
  gate.resolve(); await releasing; assert.deepEqual(f.calls, []); assert.equal(f.isBanned, true);
});
test('backend cancellation between queue reads prevents DELETE', async () => {
  const f = fixture(); f.hooks.queue = async count => ({ items: count === 1 ? [{ id: 'req', kick_user_id: 456, status: 'verified' }] : [] });
  await f.context.processVerificationQueue(f.session); assert.equal(f.queueReads, 2); assert.deepEqual(f.calls, []);
});
test('missing ownership, relay errors, stale polling and no signed event each fail closed', async () => {
  const cases = [{ verificationLocks: {} }, { remoteBackendError: 'relay unreachable' }, { remoteLastPollAt: Date.now() - 16000 }, { lastWebhookAt: undefined }, { permanentBanHolds: { 456: Date.now() } }];
  for (const change of cases) { const f = fixture(); Object.assign(f.session, change); await f.context.processVerificationQueue(f.session); assert.deepEqual(f.calls, [], JSON.stringify(change)); }
});
test('a new manual timeout queued during verification release remains applied', async () => {
  const f = fixture(), entered = deferred(), gate = deferred(); let first = true;
  f.hooks.token = async () => { if (first) { first = false; entered.resolve(); await gate.promise; } return 'fixture-token'; };
  const releasing = f.context.processVerificationQueue(f.session); await entered.promise;
  const timeout = f.context.applyUserTimeout(f.session, 456, 10, 'new moderation'); gate.resolve(); await Promise.all([releasing, timeout]);
  assert.deepEqual(f.calls, ['unban', 'timeout']); assert.equal(f.isBanned, true);
});
test('failed cloud request creation imposes no timeout and issues no rollback unban', async () => {
  const f = fixture(); f.session.verificationLocks = {}; f.hooks.create = async () => { throw new Error('fixture cloud failure'); };
  await assert.rejects(f.context.requestUserVerification(f.session, 456, 'viewer'), /fixture cloud failure/);
  assert.deepEqual(f.calls, ['create']);
});
test('invalid cloud request response imposes no timeout', async () => {
  const f = fixture(); f.session.verificationLocks = {}; f.hooks.create = async () => ({ request: {} });
  await assert.rejects(f.context.requestUserVerification(f.session, 456, 'viewer'), /no chat restriction was applied/);
  assert.deepEqual(f.calls, ['create']);
});
test('successful verification setup creates the request before timeout and persists ownership', async () => {
  const f = fixture(); f.session.verificationLocks = {};
  await f.context.requestUserVerification(f.session, 456, 'viewer');
  assert.deepEqual(f.calls, ['create', 'timeout']); assert.equal(f.session.verificationLocks['new-request'], 456);
  await assert.rejects(f.context.requestUserVerification(f.session, 456, 'viewer'), /already has a verification restriction/);
});
test('a known permanent ban prevents verification or timeout from replacing it', async () => {
  const f = fixture(); f.session.permanentBanHolds[456] = Date.now();
  await assert.rejects(f.context.requestUserVerification(f.session, 456, 'viewer'), /permanent ban/);
  await assert.rejects(f.context.applyUserTimeout(f.session, 456, 10, 'fixture'), /permanent ban/);
  assert.deepEqual(f.calls, []);
});
test('explicit moderator unban clears old holds and release ownership', async () => {
  const f = fixture(); f.session.permanentBanHolds[456] = Date.now();
  await f.context.releaseUserRestriction(f.session, 456, 'released_by_moderator');
  assert.deepEqual(f.calls, ['unban']); assert.equal(f.session.permanentBanHolds[456], undefined); assert.equal(f.session.verificationLocks.req, undefined);
});
test('failed completion acknowledgement cannot trigger a second automatic unban', async () => {
  const f = fixture(); let fail = true; f.hooks.complete = async () => { if (fail) { fail = false; throw new Error('fixture lost acknowledgement'); } };
  await f.context.processVerificationQueue(f.session); await f.context.processVerificationQueue(f.session);
  assert.deepEqual(f.calls, ['unban']);
});
test('reauthorization preserves broadcaster settings, owned restrictions and permanent holds', async () => {
  const store = new RuntimeStore('/unused-no-init-no-files');
  const original = store.createSession({ broadcasterId: 123, username: 'fixture', slug: 'fixture', token: { access_token: 'old' }, tokenExpiresAt: Date.now() + 3600000, isLive: true });
  Object.assign(original, { mode: 'shield', shieldActive: true, autoTimeoutEnabled: true, trustedUserIds: [789], verificationLocks: { req: 456 }, permanentBanHolds: { 987: Date.now() } });
  const oldId = original.id, oldCsrf = original.csrfToken, oldOverlay = original.overlayKey;
  const next = store.createSession({ broadcasterId: 123, username: 'fixture', slug: 'fixture', token: { access_token: 'new' }, tokenExpiresAt: Date.now() + 3600000, isLive: false });
  assert.equal(next, original); assert.notEqual(next.id, oldId); assert.notEqual(next.csrfToken, oldCsrf); assert.equal(next.overlayKey, oldOverlay);
  assert.equal(next.token.access_token, 'new'); assert.equal(next.mode, 'shield'); assert.equal(next.shieldActive, true); assert.equal(next.autoTimeoutEnabled, true); assert.equal(next.isLive, true);
  assert.deepEqual(next.trustedUserIds, [789]); assert.deepEqual(next.verificationLocks, { req: 456 }); assert.ok(next.permanentBanHolds[987]);
  assert.equal(store.sessions.has(oldId), false); assert.equal(store.getByBroadcaster(123), next);
  const persisted = store.serializeSessions()[0]; assert.deepEqual(persisted.verificationLocks, { req: 456 }); assert.ok(persisted.permanentBanHolds[987]);
});
test('health waits for first signed event, and preflight fails on a registered-but-failing relay', async () => {
  const f = fixture(); delete f.session.lastWebhookAt;
  const health = f.context.protectionHealth(f.session); assert.equal(health.level, 'yellow'); assert.equal(health.label, 'Awaiting KICK events');
  f.session.remoteBackendError = 'relay unreachable'; const preflight = await f.context.runPreflight(f.session);
  assert.equal(preflight.ready, false); assert.equal(preflight.checks.find(c => c.key === 'cloud_relay').status, 'fail');
});


test('two verification requests reuse the same fresh pending request without another timeout', async () => {
  const f=fixture(); f.session.verificationLocks={};
  f.hooks.recent=async()=>({items:[{id:'new-request',kick_user_id:456,status:'pending'}]});
  const a=await f.context.requestUserVerification(f.session,456,'viewer');
  const b=await f.context.requestUserVerification(f.session,456,'viewer');
  assert.equal(a.reused,false);assert.equal(b.reused,true);assert.equal(b.verification_url,a.verification_url);
  assert.deepEqual(f.calls,['create','timeout']);
});
test('rapid resend attempts make one chat post and do not reapply the timeout', async () => {
  const f=fixture();f.session.verificationLocks={};
  const a=await f.context.requestUserVerification(f.session,456,'viewer');
  const results=await Promise.all([f.context.postVerificationChatMessage(f.session,'viewer',456,a.verification_url),f.context.postVerificationChatMessage(f.session,'viewer',456,a.verification_url)]);
  assert.equal(results[0].reused,false);assert.equal(results[1].reused,true);
  assert.deepEqual(f.calls,['create','timeout','chat']);
  assert.match(results[0].content,/Please verify to chat/);assert.doesNotMatch(results[0].content,/IP|suspicious|evasi|blocked|device/i);
});
test('a failed chat post may be retried without recreating verification', async () => {
  const f=fixture();f.session.verificationLocks={};
  const a=await f.context.requestUserVerification(f.session,456,'viewer');
  f.hooks.chat=async()=>{throw new Error('chat unavailable');};
  await assert.rejects(f.context.postVerificationChatMessage(f.session,'viewer',456,a.verification_url),/chat unavailable/);
  delete f.hooks.chat;await f.context.postVerificationChatMessage(f.session,'viewer',456,a.verification_url);
  assert.deepEqual(f.calls,['create','timeout','chat']);
});
test('reviewed, blocked, completed, wrong-account and missing requests cannot be reused', async () => {
  for(const row of [{id:'new-request',kick_user_id:456,status:'review'},{id:'new-request',kick_user_id:456,status:'blocked'},{id:'new-request',kick_user_id:456,status:'verified'},{id:'new-request',kick_user_id:999,status:'pending'},{id:'other',kick_user_id:456,status:'pending'}]){
    const f=fixture();f.session.verificationLocks={};await f.context.requestUserVerification(f.session,456,'viewer');f.hooks.recent=async()=>({items:[row]});
    await assert.rejects(f.context.requestUserVerification(f.session,456,'viewer'),/already has a verification restriction/);assert.deepEqual(f.calls,['create','timeout']);
  }
});
test('an external ban during pending-request recheck prevents reuse and message delivery', async () => {
  const f=fixture();f.session.verificationLocks={};const a=await f.context.requestUserVerification(f.session,456,'viewer');
  f.hooks.recent=async()=>{await f.context.observePermanentUserBan(f.session,456,new Date().toISOString());return{items:[{id:'new-request',kick_user_id:456,status:'pending'}]};};
  await assert.rejects(f.context.requestUserVerification(f.session,456,'viewer'));
  await assert.rejects(f.context.postVerificationChatMessage(f.session,'viewer',456,a.verification_url));
  assert.deepEqual(f.calls,['create','timeout']);
});
test('review-first rejects previously queued network bans without altering account restrictions', async () => {
  const f=fixture();await f.context.processNetworkEnforcementQueue(f.session);
  assert.deepEqual(f.calls,[]);assert.equal(f.outcomes.at(-1).outcome,'review_required_no_automatic_ban');assert.equal(f.session.verificationLocks.req,456);
});
test('network opt-in is rechecked after token refresh before a queued automatic ban', async () => {
  const f=fixture();let enabled=true;f.hooks.policy=async()=>({network:{enabled:true,auto_ban_exact_network_match:enabled}});f.hooks.token=async()=>{enabled=false;return'fixture-token';};
  await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,[]);
});
test('unavailable or malformed network policy never applies an automatic ban', async () => {
  for(const response of [null,{}, {network:{enabled:true}}]){const f=fixture();f.hooks.policy=async()=>response;await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,[]);}
  const f=fixture();f.hooks.policy=async()=>{throw new Error('policy offline');};await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,[]);
});
test('trusted users are skipped even with a queued network match', async () => {
  const f=fixture();f.session.trustedUserIds=[456];await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,[]);assert.equal(f.outcomes.at(-1).outcome,'skipped_trusted');
});
test('Ban & Shield history failure is reported without undoing the successful account ban', async () => {
  const f=fixture();f.hooks.history=async()=>{throw new Error('offline');};await f.context.applyPermanentUserBan(f.session,456,'test');const status=await f.context.describeBanShield(f.session,456);
  assert.equal(status.state,'history_unavailable');assert.deepEqual(f.calls,['ban']);assert.ok(f.session.permanentBanHolds[456]);
});

test('an explicit ban with failed token refresh still cancels automatic verification release ownership', async () => {
 const f=fixture();f.hooks.token=async()=>{throw new Error('token unavailable');};
 await assert.rejects(f.context.applyPermanentUserBan(f.session,456,'moderator intent'),/token unavailable/);assert.equal(f.session.verificationLocks.req,undefined);
 delete f.hooks.token;await f.context.processVerificationQueue(f.session);assert.deepEqual(f.calls,[]);
});
test('explicitly opted-in network enforcement still applies after the fresh policy check', async () => {
 const f=fixture();f.hooks.policy=async()=>({network:{enabled:true,auto_ban_exact_network_match:true}});f.hooks.history=async()=>({history:[{accounts:[{kick_user_id:456}],blocked:true}]});
 await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,['ban']);assert.equal(f.outcomes.at(-1).outcome,'banned');
});
test('a queued network match cannot ban after its retained network is unblocked', async () => {
 const f=fixture();f.hooks.policy=async()=>({network:{enabled:true,auto_ban_exact_network_match:true}});
 f.hooks.history=async()=>({history:[{accounts:[{kick_user_id:456}],blocked:false,blocked_at:'2026-10-01',unblocked_at:'2026-10-02'}]});
 await f.context.processNetworkEnforcementQueue(f.session);assert.deepEqual(f.calls,[]);assert.equal(f.outcomes.at(-1).outcome,'review_required_no_automatic_ban');
});
test('a settings change already in flight is serialized ahead of queued network enforcement', async () => {
 const f=fixture(), gate=deferred(), entered=deferred();let auto=true;
 f.hooks.policy=async()=>({network:{enabled:true,auto_ban_exact_network_match:auto}});
 const settings=f.context.withNetworkPolicy(f.session,async()=>{entered.resolve();await gate.promise;auto=false;});await entered.promise;
 const enforcing=f.context.processNetworkEnforcementQueue(f.session);gate.resolve();await Promise.all([settings,enforcing]);assert.deepEqual(f.calls,[]);
});
let passed = 0;
for (const { name, fn } of tests) {
  let timer;
  try {
    await Promise.race([fn(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test timed out')), 1500); })]);
    console.log('PASS ' + name); passed++;
  } finally { clearTimeout(timer); }
}
console.log(`${passed}/${tests.length} isolated moderation/reauthorization/health regressions passed; no live network requests.`);

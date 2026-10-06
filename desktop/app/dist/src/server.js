import http from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { StreamShieldDetector } from "./detector.js";
import { RuntimeStore } from "./store.js";
import { compactDashboard, dashboard, landing, overlay, privacy, report, terms } from "./ui.js";
import { buildIncidentPdf } from "./pdfReport.js";
import { banKickUser, deleteKickChatMessage, exchangeKickCode, getKickChannel, getKickLivestreamForUser, getKickUser, KICK_EVENT_NAMES, listKickSubscriptions, makeKickAuthorizeUrl, makePkce, refreshKickToken, revokeKickToken, subscribeKickEvents, timeoutKickUser, unbanKickUser, } from "./kickClient.js";
import { verifyKickWebhook } from "./kickSignature.js";
import { completeRemoteNetworkQueue, completeRemoteVerification, createRemoteVerificationRequest, deleteRemoteChannelData, getRemoteEvents, getRemoteNetworkHistory, getRemoteNetworkQueue, getRemoteNetworkStatus, getRemoteVerificationQueue, getRemoteVerificationRecent, redeemRemoteKickOauth, refreshRemoteKickToken, registerRemoteBackend, setRemoteNetworkSettings, startRemoteKickOauth, unblockRemoteNetwork, } from "./remoteBackend.js";
function loadDotEnv() {
    return readFile(resolve(process.cwd(), ".env"), "utf8").then(text => {
        for (const line of text.split(/\r?\n/)) {
            const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
            if (m && process.env[m[1]] === undefined)
                process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, "");
        }
    }).catch(() => { });
}
await loadDotEnv();
const port = Number(process.env.PORT || 8787);
const baseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${port}`;
const baseOrigin = new URL(baseUrl).origin;
const remoteBackendUrl = (process.env.STREAMSHIELD_REMOTE_BACKEND_URL || "https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend").trim().replace(/\/+$/, "");
const remoteBackendConfigured = remoteBackendUrl.startsWith("https://");
const cloudWebhookUrl = remoteBackendConfigured ? `${remoteBackendUrl}/kick-webhook` : "";
const webhookPublicUrl = (process.env.KICK_WEBHOOK_PUBLIC_URL || cloudWebhookUrl || (baseUrl.startsWith("https://") ? `${baseUrl}/webhooks/kick` : "")).trim();
const publicWebhookAvailable = webhookPublicUrl.startsWith("https://");
const temporaryWebhookTunnel = /(^|\.)trycloudflare\.com$/i.test((() => { try {
    return new URL(webhookPublicUrl).hostname;
}
catch {
    return "";
} })());
const dataDir = resolve(process.env.DATA_DIR || "./data");
const pollMs = Math.max(10_000, Number(process.env.VIEWER_POLL_MS || 15_000));
const supportEmail = process.env.STREAMSHIELD_SUPPORT_EMAIL || "";
const kickBotUsername = (process.env.STREAMSHIELD_KICK_BOT_USERNAME || "").trim().replace(/^@/, "");
const maxWebhookAgeMs = Math.max(60 * 60_000, Number(process.env.WEBHOOK_MAX_AGE_MS || 48 * 60 * 60_000));
const kickConfig = {
    clientId: process.env.KICK_CLIENT_ID || "",
    clientSecret: process.env.KICK_CLIENT_SECRET || "",
    redirectUri: process.env.KICK_REDIRECT_URI || `${baseUrl}/auth/kick/callback`,
};
const legacyKickConfigured = Boolean(kickConfig.clientId && kickConfig.clientSecret && kickConfig.redirectUri);
const publicOauthBroker = remoteBackendConfigured && process.env.STREAMSHIELD_PUBLIC_OAUTH !== "0";
const kickConfigured = legacyKickConfigured || publicOauthBroker;
const store = new RuntimeStore(dataDir);
await store.init();
const oauthState = new Map();
const sseBySession = new Map();
const sseByOverlay = new Map();
const mutationHits = new Map();
const processingWebhookIds = new Set();
const automatedTimeouts = new Map();
const remoteRegisterAttempts = new Map();
const userModerationTails = new Map();
function withUserModeration(session, userId, action) {
    const key = `${session.broadcasterId}:${userId}`;
    const previous = userModerationTails.get(key) || Promise.resolve();
    const next = previous.catch(() => {}).then(action);
    userModerationTails.set(key, next);
    return next.finally(() => {
        if (userModerationTails.get(key) === next) userModerationTails.delete(key);
    });
}
async function invalidateVerificationLocks(session, userId, outcome) {
    session.verificationLocks ||= {};
    const requestIds = [];
    for (const [requestId, lockedUserId] of Object.entries(session.verificationLocks)) {
        if (Number(lockedUserId) === userId) {
            delete session.verificationLocks[requestId];
            requestIds.push(requestId);
        }
    }
    // Persist loss of release ownership before any other moderation request.
    await store.saveSession(session);
    for (const requestId of requestIds) {
        if (remoteBackendConfigured && session.remoteInstallKey) {
            try { await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, outcome); }
            catch (e) { console.error("verification cancellation", e.message); }
        }
    }
}
async function applyPermanentUserBan(session, userId, reason) {
    return withUserModeration(session, userId, async () => {
        await invalidateVerificationLocks(session, userId, "permanent_ban_preserved");
        await banKickUser(await ensureFreshToken(session), session.broadcasterId, userId, reason);
        session.permanentBanHolds ||= {};
        session.permanentBanHolds[userId] = Date.now();
        await store.saveSession(session);
    });
}
async function applyUserTimeout(session, userId, minutes, reason) {
    return withUserModeration(session, userId, async () => {
        await invalidateVerificationLocks(session, userId, "new_moderation_restriction_preserved");
        const token = await ensureFreshToken(session);
        if (session.permanentBanHolds?.[userId])
            throw new Error("A permanent ban is recorded for this account. Unban it explicitly before applying a timeout.");
        await timeoutKickUser(token, session.broadcasterId, userId, minutes, reason);
    });
}
async function releaseUserRestriction(session, userId, outcome) {
    return withUserModeration(session, userId, async () => {
        const observedHold = session.permanentBanHolds?.[userId];
        await unbanKickUser(await ensureFreshToken(session), session.broadcasterId, userId);
        // A newer observed ban must remain a hold even during an explicit release.
        if (session.permanentBanHolds?.[userId] === observedHold)
            delete session.permanentBanHolds?.[userId];
        await invalidateVerificationLocks(session, userId, outcome);
    });
}
async function observePermanentUserBan(session, userId, createdAt) {
    if (!Number.isInteger(userId) || userId <= 0) return;
    session.permanentBanHolds ||= {};
    session.permanentBanHolds[userId] = Math.max(Number(session.permanentBanHolds[userId] || 0), Date.parse(createdAt || "") || Date.now());
    // Set the hold synchronously: a release already awaiting a token/queue read
    // must see it before it can issue DELETE /moderation/bans.
    await invalidateVerificationLocks(session, userId, "observed_permanent_ban_preserved");
}
async function requestUserVerification(session, userId, username) {
    return withUserModeration(session, userId, async () => {
        if (session.permanentBanHolds?.[userId])
            throw new Error("A permanent ban is recorded for this account. Unban it explicitly before requiring verification.");
        session.verificationLocks ||= {};
        if (Object.values(session.verificationLocks).some(value => Number(value) === userId))
            throw new Error("This account already has a verification restriction. Release that request before creating another.");
        const token = await ensureFreshToken(session);
        // Create and validate the challenge before imposing a seven-day timeout.
        // Cloud creation failures therefore cannot strand the viewer without a link.
        const result = await createRemoteVerificationRequest(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, userId, username, "Moderator required channel verification");
        const requestId = String(result?.request?.id || "");
        if (!requestId) throw new Error("Verification request ID was not returned; no chat restriction was applied.");
        try {
            if (session.permanentBanHolds?.[userId]) throw new Error("A permanent ban superseded the verification request.");
            await timeoutKickUser(token, session.broadcasterId, userId, 10080, "Channel verification required");
            if (session.permanentBanHolds?.[userId]) throw new Error("A permanent ban was observed during verification setup; moderator review is required.");
            session.verificationLocks[requestId] = userId;
            await store.saveSession(session);
            return result;
        }
        catch (e) {
            delete session.verificationLocks[requestId];
            try { await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "verification_setup_failed_review_required"); } catch {}
            // KICK's unban endpoint cannot remove just our timeout if another
            // moderator changed it. Leave any applied restriction for manual review.
            throw e;
        }
    });
}
function newStreamStats(startedAt = Date.now()) {
    return { startedAt, followsSeen: 0, chatsSeen: 0, maxThreatScore: 0, maxFollows60s: 0, maxChats60s: 0, maxViewerDelta30s: 0, maxViewers: 0, followSpikes: 0, chatRaidMessagesDeleted: 0, chatRaidTimeouts: 0, verificationRequests: 0, permanentBans: 0, networkAutoBans: 0, scamMessagesDeleted: 0, panicActivations: 0, followSpikeActive: false };
}
function ensureStreamStats(session) {
    session.streamStats ||= newStreamStats(session.createdAt || Date.now());
    return session.streamStats;
}
function latestStreamReport(session) {
    return store.listIncidents(session.broadcasterId).find(x => x.reportType === "stream_summary");
}
function buildSupportSummary(session, report) {
    const st = report.streamStats || {};
    const lines = [
        `StreamShield protection report for @${session.slug} on KICK`,
        `Stream window: ${report.startedAt} to ${report.endedAt}`,
        `Peak threat score: ${report.peakThreatScore}/100`,
        `Peak viewers: ${st.maxViewers || 0}; largest 30-second viewer change: ${st.maxViewerDelta30s >= 0 ? "+" : ""}${st.maxViewerDelta30s || 0}`,
        `Follows observed: ${st.followsSeen || 0}; peak follow rate: ${st.maxFollows60s || 0}/minute; suspicious follow spikes: ${st.followSpikes || 0}`,
        `Chat messages observed: ${st.chatsSeen || 0}; peak chat rate: ${st.maxChats60s || 0}/minute`,
        `Chat Raid Shield deletions: ${st.chatRaidMessagesDeleted || 0}; automatic spam timeouts: ${st.chatRaidTimeouts || 0}`,
        `Targeted verification requests: ${st.verificationRequests || 0}; permanent KICK bans: ${st.permanentBans || 0}; exact-network evasion auto-bans: ${st.networkAutoBans || 0}`,
        `Recorded StreamShield incidents: ${report.incidentCount || 0}`,
        report.evidenceSeal ? `Evidence integrity seal (SHA-256): ${report.evidenceSeal}` : "",
        report.eventChainId ? `Event-chain ID: ${report.eventChainId}` : "",
        `StreamShield did not generate or request the suspicious engagement described here. This summary documents defensive detection and moderation and is supporting evidence only. Please review KICK platform logs for the final determination.`
    ];
    return lines.filter(Boolean).join("\n");
}
function stableJson(value) {
    if (Array.isArray(value))
        return `[${value.map(stableJson).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}
function evidencePayload(report) {
    return {
        version: 1,
        channelSlug: report.channelSlug || report.slug || "",
        startedAt: report.startedAt || "",
        endedAt: report.endedAt || report.lastObservedAt || "",
        peakThreatScore: Number(report.peakThreatScore ?? report.peakScore ?? report.score ?? 0),
        needsReview: Boolean(report.needsReview ?? (report.level === "review_recommended")),
        reasons: report.reasons || [],
        metrics: report.metrics || {},
        streamStats: report.streamStats || {},
        incidentCount: Number(report.incidentCount || 0),
        actions: report.actions || [],
    };
}
function makeEvidenceSeal(report) {
    const payload = evidencePayload(report);
    const evidenceSeal = createHash("sha256").update(stableJson(payload), "utf8").digest("hex");
    let chain = createHash("sha256").update("streamshield-event-chain-v1", "utf8").digest("hex");
    const events = [
        ...(payload.reasons || []).map((x, i) => ({ kind: "reason", index: i, value: x })),
        ...(payload.actions || []).map((x, i) => ({ kind: "action", index: i, value: x })),
    ];
    for (const event of events)
        chain = createHash("sha256").update(`${chain}\\n${stableJson(event)}`, "utf8").digest("hex");
    return { evidenceSeal, eventChainId: chain, evidenceAlgorithm: "SHA-256", evidenceVersion: 1 };
}
function reportSealMatches(report) {
    if (!report?.evidenceSeal || !/^[a-f0-9]{64}$/i.test(String(report.evidenceSeal)))
        return null;
    const fresh = makeEvidenceSeal(report);
    return timingSafeEqual(Buffer.from(fresh.evidenceSeal, "hex"), Buffer.from(String(report.evidenceSeal), "hex"));
}
const APP_VERSION = "0.6.0-beta.10";
let latestRelease = null;
let lastReleaseCheckAt = 0;
function versionTuple(v) {
    const [core, pre = ""] = v.replace(/^v/i, "").split("-", 2);
    const nums = core.split(".").map(x => Number(x) || 0);
    while (nums.length < 3)
        nums.push(0);
    const preNums = (pre.match(/\d+/g) || []).map(Number);
    return { nums: nums.slice(0, 3), pre: pre.toLowerCase(), preNums };
}
function isNewerVersion(candidate, current) {
    const a = versionTuple(candidate), b = versionTuple(current);
    for (let i = 0; i < 3; i++) {
        if (a.nums[i] !== b.nums[i])
            return a.nums[i] > b.nums[i];
    }
    if (a.pre === b.pre)
        return false;
    if (!a.pre && b.pre)
        return true;
    if (a.pre && !b.pre)
        return false;
    const n = Math.max(a.preNums.length, b.preNums.length);
    for (let i = 0; i < n; i++) {
        const av = a.preNums[i] ?? 0, bv = b.preNums[i] ?? 0;
        if (av !== bv)
            return av > bv;
    }
    return a.pre > b.pre;
}
async function refreshReleaseInfo() {
    if (!remoteBackendConfigured)
        return;
    try {
        const r = await fetch(`${remoteBackendUrl}/release/latest`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(8000) });
        if (!r.ok)
            return;
        const body = await r.json();
        if (body?.release?.version && /^https:\/\//i.test(body.release.download_url || ""))
            latestRelease = body.release;
        lastReleaseCheckAt = Date.now();
    }
    catch { }
}
await refreshReleaseInfo();
const releaseTimer = setInterval(() => { void refreshReleaseInfo(); }, 60 * 60_000);
releaseTimer.unref?.();
function securityHeaders(type = "text/html; charset=utf-8") {
    return {
        "content-type": type,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "content-security-policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    };
}
function parseCookies(req) {
    const raw = req.headers.cookie || "";
    return Object.fromEntries(raw.split(";").map(x => x.trim()).filter(Boolean).map(x => { const i = x.indexOf("="); return i < 0 ? [x, ""] : [x.slice(0, i), decodeURIComponent(x.slice(i + 1))]; }));
}
function cookie(name, value, maxAge) {
    const attrs = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax"];
    if (baseUrl.startsWith("https:"))
        attrs.push("Secure");
    if (maxAge !== undefined)
        attrs.push(`Max-Age=${maxAge}`);
    return attrs.join("; ");
}
function getSession(req) { const id = parseCookies(req).ss_session; return id ? store.sessions.get(id) : undefined; }
function safeEqual(a, b) {
    const aa = Buffer.from(a), bb = Buffer.from(b);
    return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function validCsrf(req, session) {
    const token = String(req.headers["x-streamshield-csrf"] || "");
    if (!token || !safeEqual(token, session.csrfToken))
        return false;
    const origin = String(req.headers.origin || "");
    if (origin && origin !== baseOrigin)
        return false;
    return true;
}
function allowMutation(sessionId, now = Date.now()) {
    const cutoff = now - 60_000;
    const recent = (mutationHits.get(sessionId) || []).filter(x => x >= cutoff);
    if (recent.length >= 120) {
        mutationHits.set(sessionId, recent);
        return false;
    }
    recent.push(now);
    mutationHits.set(sessionId, recent);
    return true;
}
function send(res, status, body, type = "text/html; charset=utf-8", extra = {}) { res.writeHead(status, { ...securityHeaders(type), ...extra }); res.end(body); }
function sendBuffer(res, status, body, type, extra = {}) { res.writeHead(status, { ...securityHeaders(type), "content-length": String(body.length), ...extra }); res.end(body); }
function redirect(res, url, extra = {}) { res.writeHead(302, { location: url, "cache-control": "no-store", ...extra }); res.end(); }
async function bodyBuffer(req, maxBytes = 256 * 1024) {
    const declared = Number(req.headers["content-length"] || 0);
    if (declared > maxBytes)
        throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
    const chunks = [];
    let total = 0;
    for await (const c of req) {
        const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
        total += b.length;
        if (total > maxBytes)
            throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
        chunks.push(b);
    }
    return Buffer.concat(chunks);
}
async function jsonBody(req) { const b = await bodyBuffer(req); return b.length ? JSON.parse(b.toString("utf8")) : {}; }
function protectionHealth(session) {
    const now = Date.now();
    const reasons = [];
    if (!session.subscriptionHealthy) reasons.push("KICK event subscriptions are not fully healthy");
    if (remoteBackendConfigured && !session.remoteBackendRegistered) reasons.push("StreamShield cloud relay is disconnected");
    if (!session.lastWebhookAt) reasons.push("Awaiting the first signed KICK webhook event");
    if (session.isLive && session.lastWebhookAt && now - session.lastWebhookAt > 180000) reasons.push("No signed KICK webhook event has arrived for more than 3 minutes while live");
    if (session.remoteBackendError) reasons.push(session.remoteBackendError);
    const level = reasons.length >= 2 ? "red" : reasons.length === 1 ? "yellow" : "green";
    return { level, label: level === "green" ? "Protected" : reasons.length === 1 && !session.lastWebhookAt ? "Awaiting KICK events" : level === "yellow" ? "Degraded" : "Attention required", reasons };
}
async function generateStreamReport(session, options = {}) {
    const automatic = Boolean(options.automatic);
    const force = Boolean(options.force);
    const stats = { ...ensureStreamStats(session) };
    const startedAtMs = Number(stats.startedAt || session.createdAt || Date.now());
    const endedAtMs = Number(stats.endedAt || Date.now());
    const startedAt = new Date(startedAtMs).toISOString();
    const endedAt = new Date(endedAtMs).toISOString();
    const existing = store.listIncidents(session.broadcasterId).find(x => x.reportType === "stream_summary" && Math.abs((Date.parse(x.startedAt || "") || 0) - startedAtMs) < 1000);
    if (existing && !force)
        return existing;
    const incidents = store.listIncidents(session.broadcasterId).filter(x => x.reportType !== "stream_summary" && Date.parse(x.startedAt || "") >= startedAtMs && Date.parse(x.startedAt || "") <= endedAtMs + 60_000);
    const actions = incidents.flatMap(x => x.actions || []).sort((a, b) => Date.parse(a.at || "") - Date.parse(b.at || "")).slice(-200);
    const reasons = [];
    if ((stats.followSpikes || 0) > 0)
        reasons.push({ code: "follow_shield", label: "Suspicious follow spikes recorded", points: 0, detail: `${stats.followSpikes} follow spike(s), peak ${stats.maxFollows60s || 0} follows/minute` });
    if ((stats.chatRaidMessagesDeleted || 0) > 0 || (stats.chatRaidTimeouts || 0) > 0)
        reasons.push({ code: "chat_raid_shield", label: "Chat Raid Shield intervened", points: 0, detail: `${stats.chatRaidMessagesDeleted || 0} repetitive message deletion(s), ${stats.chatRaidTimeouts || 0} automatic spam timeout(s)` });
    if ((stats.scamMessagesDeleted || 0) > 0)
        reasons.push({ code: "link_scam_shield", label: "Link / Scam Shield intervened", points: 0, detail: `${stats.scamMessagesDeleted || 0} suspicious link/spam message deletion(s)` });
    if ((stats.networkAutoBans || 0) > 0)
        reasons.push({ code: "network_evasion", label: "Exact blocked-network matches enforced", points: 0, detail: `${stats.networkAutoBans || 0} automatic network-evasion ban(s)` });
    const reportDraft = {
        channelSlug: session.slug,
        startedAt,
        endedAt,
        peakThreatScore: Number(stats.maxThreatScore || session.lastAssessment.score || 0),
        needsReview: incidents.length > 0 || reasons.length > 0,
        reasons,
        metrics: {
            viewers: stats.maxViewers || 0,
            viewerDelta30s: stats.maxViewerDelta30s || 0,
            follows60s: stats.maxFollows60s || 0,
            chats60s: stats.maxChats60s || 0,
            uniqueChatters60s: session.lastAssessment.metrics.uniqueChatters60s || 0,
            duplicateRatio60s: session.lastAssessment.metrics.duplicateRatio60s || 0,
        },
        streamStats: stats,
        incidentCount: incidents.length,
        actions,
        autoGenerated: automatic,
        generatedAt: new Date().toISOString(),
    };
    Object.assign(reportDraft, makeEvidenceSeal(reportDraft));
    reportDraft.summaryText = buildSupportSummary(session, reportDraft);
    const item = await store.addStreamReport(session, reportDraft);
    session.lastAutoReportAt = automatic ? Date.now() : session.lastAutoReportAt;
    await store.saveSession(session);
    pushEvent(session, {
        kind: "action",
        title: automatic ? "End-of-stream report created automatically" : "End-of-stream report generated",
        detail: reportDraft.needsReview ? "Evidence summary, integrity seal, and KICK Support text are ready for review." : "No major suspicious activity was detected in the recorded stream window.",
        ok: true,
        score: reportDraft.peakThreatScore,
    });
    broadcast(session);
    return item;
}
async function runPreflight(session) {
    const checks = [];
    let tokenOk = false;
    try {
        await ensureFreshToken(session);
        tokenOk = true;
        checks.push({ key: "kick_oauth", label: "KICK authorization", status: "pass", detail: "OAuth token is available and refreshable." });
    }
    catch (e) {
        checks.push({ key: "kick_oauth", label: "KICK authorization", status: "fail", detail: e.message || "KICK authorization is unavailable." });
    }
    if (tokenOk) {
        try {
            await reconcileKickSubscriptions(session);
        }
        catch { }
    }
    if (publicWebhookAvailable)
        checks.push({ key: "kick_events", label: "KICK event monitoring", status: session.subscriptionHealthy ? "pass" : "fail", detail: session.subscriptionHealthy ? "Required event subscriptions are healthy." : (session.subscriptionError || `Missing: ${(session.subscriptionMissing || []).join(", ")}`) });
    else
        checks.push({ key: "kick_events", label: "KICK event monitoring", status: "warn", detail: "Local Test mode is active; production webhook delivery is not enabled." });
    if (remoteBackendConfigured)
        checks.push({ key: "cloud_relay", label: "StreamShield cloud relay", status: session.remoteBackendRegistered && !session.remoteBackendError ? "pass" : "fail", detail: session.remoteBackendRegistered && !session.remoteBackendError ? "Production relay is registered and has no current connection error." : (session.remoteBackendError || "Cloud relay is not registered.") });
    else
        checks.push({ key: "cloud_relay", label: "StreamShield cloud relay", status: "warn", detail: "Cloud relay is not configured in this build." });
    checks.push({ key: "kick_delivery", label: "Signed KICK event delivery", status: session.lastWebhookAt ? "pass" : "warn", detail: session.lastWebhookAt ? "At least one signed KICK event has been received." : "Waiting for the first signed KICK event; live delivery is not yet verified." });
    checks.push({ key: "follow_shield", label: "Follow Shield", status: session.followShieldEnabled !== false ? "pass" : "warn", detail: session.followShieldEnabled !== false ? "Suspicious follow bursts will be recorded." : "Follow Shield is currently off." });
    checks.push({ key: "chat_raid", label: "Chat Raid Shield", status: session.chatRaidShieldEnabled !== false ? "pass" : "warn", detail: session.chatRaidShieldEnabled !== false ? "High-confidence repetitive spam protection is enabled." : "Chat Raid Shield is currently off." });
    checks.push({ key: "link_scam", label: "Link / Scam Shield", status: session.linkScamShieldEnabled !== false ? "pass" : "warn", detail: session.linkScamShieldEnabled !== false ? "Repeated suspicious link patterns are protected." : "Link / Scam Shield is currently off." });
    checks.push({ key: "evidence", label: "Evidence logging", status: "pass", detail: "Encrypted local incident storage and SHA-256 report sealing are available." });
    const networkEnabled = Boolean(session.networkProtection?.enabled);
    checks.push({ key: "network", label: "Network Protection", status: networkEnabled ? "pass" : "info", detail: networkEnabled ? "Verified-network matching is enabled." : "Optional Network Protection is off; core stream protection still works." });
    const criticalKeys = new Set(["kick_oauth", ...(publicWebhookAvailable ? ["kick_events"] : []), ...(remoteBackendConfigured ? ["cloud_relay"] : [])]);
    const ready = !checks.some(c => criticalKeys.has(c.key) && c.status === "fail");
    const warnings = checks.filter(c => c.status === "warn" || c.status === "fail").map(c => c.detail);
    const result = { at: new Date().toISOString(), ready, label: ready ? (warnings.length ? "READY WITH WARNINGS" : "READY TO STREAM") : "NOT READY", checks, warnings };
    session.lastPreflight = result;
    await store.saveSession(session);
    return result;
}
function safeNetworkLabel(row) {
    const label = String(row?.network_label || "").trim();
    if (/^NET-[A-F0-9]{8}$/.test(label)) return label;
    const hash = String(row?.network_hash || "").toLowerCase();
    return /^[a-f0-9]{64}$/.test(hash) ? "NET-" + hash.slice(-8).toUpperCase() : "Verified network";
}
function redactNetworkHistory(result) {
    const history = Array.isArray(result?.history) ? result.history : [];
    return {
        ...(result && typeof result === "object" ? result : {}),
        history: history.map(row => {
            const { ip, ip_address, display_ip, ...rest } = row || {};
            return { ...rest, network_label: safeNetworkLabel(row) };
        }),
    };
}
function rowMatchesUser(row, userId, username) {
    const numeric = [row?.kick_user_id, row?.user_id, row?.source_user_id, row?.source_kick_user_id].map(Number).filter(Number.isFinite);
    if (numeric.includes(userId))
        return true;
    if ((row?.accounts || []).some(a => Number(a?.kick_user_id || a?.user_id) === userId))
        return true;
    const names = [row?.kick_username, row?.username, row?.source_username].filter(Boolean).map(x => String(x).toLowerCase());
    return username ? names.includes(String(username).toLowerCase()) : false;
}
async function buildOffenderCase(session, userId) {
    const messages = session.recentChat.filter(x => Number(x.userId) === userId).slice(0, 30);
    const username = messages[0]?.username || "";
    const actions = session.recentActions.filter(x => Number(x.meta?.userId) === userId || String(x.detail || "").includes(String(userId)) || (username && String(x.detail || "").includes(`@${username}`))).slice(0, 30);
    const incidents = store.listIncidents(session.broadcasterId).filter(i => (i.actions || []).some(a => Number(a.meta?.userId) === userId || String(a.detail || "").includes(String(userId)) || (username && String(a.detail || "").includes(`@${username}`)))).slice(0, 20).map(i => ({ id: i.id, startedAt: i.startedAt, level: i.level, peakScore: i.peakScore ?? i.score, note: i.note || "" }));
    let verificationMatches = [];
    let networkMatches = [];
    if (remoteBackendConfigured && session.remoteBackendRegistered && session.remoteInstallKey) {
        try {
            const vr = await getRemoteVerificationRecent(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
            const rows = Array.isArray(vr) ? vr : (vr?.requests || vr?.items || vr?.data || []);
            verificationMatches = rows.filter(r => rowMatchesUser(r, userId, username)).slice(0, 20).map(r => ({ status: r.status || "", at: r.completed_at || r.verified_at || r.created_at || r.requested_at || "", deviceMatch: Boolean(r.device_match || r.blocked_device_match || r.device_risk_match), networkMatch: Boolean(r.network_match || r.blocked_network_match), requestId: r.request_id || r.id || "" }));
        }
        catch { }
        try {
            const nh = await getRemoteNetworkHistory(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
            const history = nh?.history ?? nh;
            const rows = Array.isArray(history) ? history : [history?.observations, history?.blocks, history?.items, history?.networks].filter(Array.isArray).flat();
            networkMatches = rows.filter(r => rowMatchesUser(r, userId, username)).slice(0, 20).map(r => ({ networkLabel: safeNetworkLabel(r), blocked: typeof r.blocked === "boolean" ? r.blocked : typeof r.is_blocked === "boolean" ? r.is_blocked : Boolean(r.blocked_at && (!r.unblocked_at || Date.parse(r.blocked_at) > Date.parse(r.unblocked_at))), firstSeenAt: r.first_seen_at || r.blocked_at || "", lastSeenAt: r.last_seen_at || r.last_match_at || r.unblocked_at || "", matchCount: Number(r.match_count || 0) }));
        }
        catch { }
    }
    const riskSignals = [];
    if (networkMatches.some(x => x.blocked)) riskSignals.push("Previously blocked verified network associated with this account");
    if (verificationMatches.some(x => x.deviceMatch)) riskSignals.push("First-party device-token match requires moderator review");
    if (actions.some(x => x.action === "permanent_ban_user" || x.action === "auto_ban_network_evasion")) riskSignals.push("Prior permanent moderation action recorded");
    const caseId = createHash("sha256").update(`${session.broadcasterId}:${userId}`, "utf8").digest("hex").slice(0, 16).toUpperCase();
    return { caseId, userId, username, trusted: (session.trustedUserIds || []).includes(userId), riskSignals, messages, actions, incidents, verificationMatches, networkMatches };
}
async function undoLastReversible(session) {
    const reversible = new Set(["permanent_ban_user", "timeout_user", "verification_request", "panic_mode_activated", "trusted_user_changed"]);
    const target = session.recentActions.find(a => a.ok && !a.recoveredAt && reversible.has(a.action) && (a.action !== "panic_mode_activated" || session.panicActive));
    if (!target)
        return { ok: false, error: "No recent reversible StreamShield action is available." };
    if (target.action === "panic_mode_activated") {
        const p = session.panicPrevious || {};
        session.panicActive = false;
        session.mode = p.mode || "assist";
        session.shieldActive = !!p.shieldActive;
        session.autoTimeoutEnabled = !!p.autoTimeoutEnabled;
        session.followShieldEnabled = p.followShieldEnabled !== false;
        session.chatRaidShieldEnabled = p.chatRaidShieldEnabled !== false;
        session.linkScamShieldEnabled = p.linkScamShieldEnabled !== false;
        session.panicPrevious = null;
    }
    else if (target.action === "trusted_user_changed") {
        const userId = Number(target.meta?.userId || 0);
        if (!userId) return { ok: false, error: "The selected trusted-viewer action predates recovery metadata." };
        const set = new Set(session.trustedUserIds || []);
        if (target.meta?.previousTrusted) set.add(userId); else set.delete(userId);
        session.trustedUserIds = [...set];
    }
    else {
        const userId = Number(target.meta?.userId || String(target.detail || "").match(/\d+/)?.[0] || 0);
        if (!userId) return { ok: false, error: "The selected moderation action does not contain a recoverable user reference." };
        await releaseUserRestriction(session, userId, "recovery_center_release");
        if (target.action === "verification_request") {
            const requestId = String(target.meta?.requestId || "");
            if (requestId) {
                if (remoteBackendConfigured && session.remoteInstallKey)
                    try { await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "recovery_center_release"); } catch { }
            }
        }
    }
    target.recoveredAt = Date.now();
    target.recoveryNote = "Reversed from Recovery Center";
    await store.saveSession(session);
    await recordAction(session, { at: Date.now(), action: "recovery_undo", ok: true, detail: `Reversed ${target.action}`, meta: { recoveredAction: target.action, userId: target.meta?.userId || null } });
    return { ok: true, reversed: target.action };
}
function snapshot(session) { const lastReport = latestStreamReport(session); return JSON.stringify({ assessment: session.lastAssessment, isLive: session.isLive, lastWebhookAt: session.lastWebhookAt, lastPollAt: session.lastPollAt, mode: session.mode, shieldActive: session.shieldActive, followShieldEnabled: session.followShieldEnabled !== false, chatRaidShieldEnabled: session.chatRaidShieldEnabled !== false, linkScamShieldEnabled: session.linkScamShieldEnabled !== false, panicActive: !!session.panicActive, protectionHealth: protectionHealth(session), lastPreflight: session.lastPreflight || null, streamStats: ensureStreamStats(session), lastStreamReport: lastReport ? { id: lastReport.id, startedAt: lastReport.startedAt, endedAt: lastReport.lastObservedAt, summaryText: lastReport.summaryText || "", evidenceSeal: lastReport.evidenceSeal || "", eventChainId: lastReport.eventChainId || "", sealValid: reportSealMatches(lastReport) } : null, lastSubscriptionCheckAt: session.lastSubscriptionCheckAt, subscriptionHealthy: session.subscriptionHealthy, subscriptionMissing: session.subscriptionMissing || [], subscriptionError: session.subscriptionError || "", moderatorSetupConfirmed: !!session.moderatorSetupConfirmed, autoTimeoutEnabled: !!session.autoTimeoutEnabled, trustedUserIds: session.trustedUserIds ?? [], kickBotUsername, baseline: session.detector.getBaseline(), recentChat: session.recentChat.slice(0, 20), recentActions: session.recentActions.slice(0, 20), recentEvents: session.recentEvents.slice(0, 40), networkProtection: session.networkProtection ?? { enabled: false, auto_ban_exact_network_match: false, active_observations: 0, blocked_networks: 0, pending_enforcements: 0 }, networkGateUrl: remoteBackendConfigured ? `${remoteBackendUrl}/network/start?broadcaster_id=${encodeURIComponent(session.broadcasterId)}` : "", ipEnforcementAvailable: remoteBackendConfigured, publicWebhookAvailable, temporaryWebhookTunnel, webhookPublicUrl, remoteBackendConfigured, remoteBackendRegistered: !!session.remoteBackendRegistered, remoteBackendError: session.remoteBackendError || "", remoteBackendUrl: remoteBackendConfigured ? remoteBackendUrl : "", appVersion: APP_VERSION, latestRelease, lastReleaseCheckAt, updateAvailable: !!(latestRelease?.version && isNewerVersion(latestRelease.version, APP_VERSION)) }); }
function broadcast(session) { const data = `data: ${snapshot(session)}\n\n`; for (const r of sseBySession.get(session.id) || [])
    r.write(data); for (const r of sseByOverlay.get(session.overlayKey) || [])
    r.write(data); }
function addSse(setMap, key, req, res, initial) {
    res.writeHead(200, { ...securityHeaders("text/event-stream"), connection: "keep-alive", "content-security-policy": "default-src 'none'" });
    res.write(`data: ${initial}\n\n`);
    const set = setMap.get(key) || new Set();
    set.add(res);
    setMap.set(key, set);
    const heartbeat = setInterval(() => { try {
        res.write(": heartbeat\n\n");
    }
    catch { } }, 20_000);
    req.on("close", () => { clearInterval(heartbeat); set.delete(res); });
}
function pushEvent(session, event) {
    session.recentEvents.unshift({ at: event.at ?? Date.now(), kind: event.kind, title: event.title, detail: event.detail, score: event.score, ok: event.ok });
    session.recentEvents = session.recentEvents.slice(0, 80);
}
async function recordAction(session, action) {
    action = { at: action.at ?? Date.now(), action: action.action, ok: Boolean(action.ok), detail: action.detail ?? "", ...(action.meta ? { meta: action.meta } : {}) };
    const stats = ensureStreamStats(session);
    if (action.ok) {
        if (action.action === "auto_delete_repetitive_chat") stats.chatRaidMessagesDeleted = (stats.chatRaidMessagesDeleted || 0) + 1;
        else if (action.action === "auto_timeout_repetitive_spammer") stats.chatRaidTimeouts = (stats.chatRaidTimeouts || 0) + 1;
        else if (action.action === "verification_request") stats.verificationRequests = (stats.verificationRequests || 0) + 1;
        else if (action.action === "permanent_ban_user") stats.permanentBans = (stats.permanentBans || 0) + 1;
        else if (action.action === "auto_ban_network_evasion") stats.networkAutoBans = (stats.networkAutoBans || 0) + 1;
        else if (action.action === "auto_delete_suspicious_link_spam") stats.scamMessagesDeleted = (stats.scamMessagesDeleted || 0) + 1;
        else if (action.action === "panic_mode_activated") stats.panicActivations = (stats.panicActivations || 0) + 1;
    }
    session.recentActions.unshift(action);
    session.recentActions = session.recentActions.slice(0, 30);
    pushEvent(session, { at: action.at, kind: "action", title: action.action.replace(/_/g, " "), detail: action.detail, ok: action.ok, score: session.lastAssessment.score });
    await store.addIncidentAction(session.activeIncidentId, action);
    broadcast(session);
}
async function reassess(session, note) {
    const before = session.previousScore;
    const a = session.detector.assess();
    session.lastAssessment = a;
    if (before < 81 && a.score >= 81)
        pushEvent(session, { kind: "threat", title: "Active attack threshold reached", detail: a.reasons.slice(0, 3).map(r => r.label).join(" · "), score: a.score });
    else if (before < 61 && a.score >= 61)
        pushEvent(session, { kind: "threat", title: "Likely bot activity detected", detail: a.reasons.slice(0, 3).map(r => r.label).join(" · "), score: a.score });
    else if (before < 41 && a.score >= 41)
        pushEvent(session, { kind: "threat", title: "Suspicious activity detected", detail: a.reasons.slice(0, 3).map(r => r.label).join(" · "), score: a.score });
    else if (before < 21 && a.score >= 21)
        pushEvent(session, { kind: "info", title: "Activity elevated", detail: a.reasons.slice(0, 2).map(r => r.label).join(" · "), score: a.score });
    if (before >= 21 && a.score < 21)
        pushEvent(session, { kind: "info", title: "Activity returned to normal", detail: "Threat signals fell back below the elevated threshold.", score: a.score, ok: true });
    if (session.previousScore < 61 && a.score >= 61) {
        const incident = await store.addIncident(session, a, note);
        session.activeIncidentId = incident.id;
    }
    else if (session.activeIncidentId && a.score >= 41) {
        await store.updateIncident(session.activeIncidentId, a);
    }
    else if (session.activeIncidentId && a.score < 41) {
        await store.updateIncident(session.activeIncidentId, a);
        session.activeIncidentId = undefined;
    }
    const stats = ensureStreamStats(session);
    stats.maxThreatScore = Math.max(stats.maxThreatScore || 0, a.score || 0);
    stats.maxFollows60s = Math.max(stats.maxFollows60s || 0, a.metrics.follows60s || 0);
    stats.maxChats60s = Math.max(stats.maxChats60s || 0, a.metrics.chats60s || 0);
    stats.maxViewerDelta30s = Math.max(stats.maxViewerDelta30s || 0, a.metrics.viewerDelta30s || 0);
    stats.maxViewers = Math.max(stats.maxViewers || 0, a.metrics.viewers || 0);
    const followBurst = a.reasons.some(r => String(r.code || "").startsWith("follow_burst"));
    if (session.followShieldEnabled !== false && followBurst && !stats.followSpikeActive) {
        stats.followSpikes = (stats.followSpikes || 0) + 1;
        stats.followSpikeActive = true;
        pushEvent(session, { kind: "threat", title: "Follow Shield quarantined a suspicious follow spike", detail: `${a.metrics.follows60s} follows in the last minute were preserved as evidence. StreamShield does not auto-ban followers from follow velocity alone.`, score: a.score, ok: false });
    }
    if (!followBurst) stats.followSpikeActive = false;
    session.previousScore = a.score;
    if (session.isLive && session.detector.learnFromCalmActivity(a))
        await store.saveBaseline(session);
    broadcast(session);
    return a;
}
async function ensureFreshToken(session) {
    if (Date.now() < session.tokenExpiresAt - 60_000)
        return session.token.access_token;
    if (!session.token.refresh_token)
        throw new Error("Kick access token expired and no refresh token is available");
    let next;
    if (publicOauthBroker && session.remoteInstallKey) {
        next = await refreshRemoteKickToken(remoteBackendUrl, session.broadcasterId, session.token.refresh_token, session.remoteInstallKey);
    }
    else {
        if (!legacyKickConfigured)
            throw new Error("Kick token refresh is unavailable until the StreamShield cloud OAuth broker is configured");
        next = await refreshKickToken(kickConfig, session.token.refresh_token);
    }
    session.token = next;
    session.tokenExpiresAt = Date.now() + Number(next.expires_in || 3600) * 1000;
    await store.saveSession(session);
    return next.access_token;
}
async function ensureRemoteRegistration(session) {
    if (!remoteBackendConfigured || !session.remoteInstallKey)
        return;
    if (session.remoteBackendRegistered && !session.remoteBackendError)
        return;
    const lastAttempt = remoteRegisterAttempts.get(session.id) || 0;
    if (Date.now() - lastAttempt < 60_000)
        return;
    remoteRegisterAttempts.set(session.id, Date.now());
    try {
        const token = await ensureFreshToken(session);
        await registerRemoteBackend(remoteBackendUrl, token, session.remoteInstallKey);
        const wasRegistered = session.remoteBackendRegistered;
        session.remoteBackendRegistered = true;
        session.remoteBackendError = "";
        if (!wasRegistered)
            pushEvent(session, { kind: "health", title: "StreamShield cloud connected", detail: "This installation is registered with the permanent production webhook backend. Kick OAuth tokens remain on this computer and are not stored in the cloud.", ok: true, score: session.lastAssessment.score });
        await store.saveSession(session);
        broadcast(session);
    }
    catch (e) {
        session.remoteBackendRegistered = false;
        session.remoteBackendError = e.message;
        await store.saveSession(session);
        console.error("remote backend registration", session.remoteBackendError);
    }
}
async function syncNetworkProtection(session) {
    if (!remoteBackendConfigured || !session.remoteBackendRegistered || !session.remoteInstallKey)
        return;
    try {
        const status = await getRemoteNetworkStatus(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
        session.networkProtection = status.network || session.networkProtection;
        session.networkProtectionError = "";
    }
    catch (e) {
        session.networkProtectionError = e.message;
    }
}
async function processNetworkEnforcementQueue(session) {
    if (!remoteBackendConfigured || !session.remoteBackendRegistered || !session.remoteInstallKey || session.networkQueueProcessing)
        return;
    session.networkQueueProcessing = true;
    try {
        const batch = await getRemoteNetworkQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
        for (const item of batch.items || []) {
            const userId = Number(item.kick_user_id) || 0;
            if (!userId)
                continue;
            if (userId === session.broadcasterId || (session.trustedUserIds ?? []).includes(userId)) {
                await completeRemoteNetworkQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, item.id, "skipped_trusted");
                await recordAction(session, { at: Date.now(), action: "network_match_skipped", ok: true, detail: `Kick user ${userId} is broadcaster/trusted` });
                continue;
            }
            try {
                await applyPermanentUserBan(session, userId, "StreamShield blocked-network match");
                await completeRemoteNetworkQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, item.id, "banned");
                await recordAction(session, { at: Date.now(), action: "auto_ban_network_evasion", ok: true, detail: `Permanently banned @${item.kick_username || userId} after exact blocked-network verification match` });
            }
            catch (e) {
                if (e?.status === 429 || e?.status >= 500) {
                    console.error("network enforcement transient", e.message);
                    continue;
                }
                await completeRemoteNetworkQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, item.id, `failed:${String(e.message).slice(0,70)}`);
                await recordAction(session, { at: Date.now(), action: "auto_ban_network_evasion", ok: false, detail: e.message });
            }
        }
        await syncNetworkProtection(session);
        await store.saveSession(session);
        broadcast(session);
    }
    catch (e) {
        console.error("network enforcement poll", e.message);
    }
    finally {
        session.networkQueueProcessing = false;
    }
}
async function processVerificationQueue(session) {
    if (!remoteBackendConfigured || !session.remoteBackendRegistered || !session.remoteInstallKey || session.verificationQueueProcessing)
        return;
    session.verificationQueueProcessing = true;
    session.verificationLocks ||= {};
    try {
        const batch = await getRemoteVerificationQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
        for (const item of batch.items || []) {
            const userId = Number(item.kick_user_id) || 0;
            const requestId = String(item.id || "");
            if (!userId || !requestId)
                continue;
            if (item.status === "verified") {
                try {
                    await withUserModeration(session, userId, async () => {
                        if (session.permanentBanHolds?.[userId]) {
                            await invalidateVerificationLocks(session, userId, "permanent_ban_preserved");
                            await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "permanent_ban_preserved");
                            return;
                        }
                        if (Number(session.verificationLocks[requestId] || 0) !== userId) {
                            await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "no_local_verification_lock");
                            return;
                        }
                        if (!session.remoteBackendRegistered || session.remoteBackendError || !session.lastWebhookAt || !session.remoteLastPollAt || Date.now() - session.remoteLastPollAt > 15_000) return;
                        const token = await ensureFreshToken(session);
                        // Re-read after token refresh and while holding the user's
                        // moderation lock. The backend removes candidates when a
                        // permanent-ban webhook supersedes verification.
                        const current = await getRemoteVerificationQueue(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey);
                        const fresh = (current.items || []).find(row => String(row.id) === requestId && Number(row.kick_user_id) === userId && row.status === "verified");
                        if (!fresh || session.permanentBanHolds?.[userId] || Number(session.verificationLocks[requestId] || 0) !== userId || !session.remoteBackendRegistered || session.remoteBackendError || Date.now() - session.remoteLastPollAt > 15_000) return;
                        await unbanKickUser(token, session.broadcasterId, userId);
                        delete session.verificationLocks[requestId];
                        await store.saveSession(session);
                        if (session.permanentBanHolds?.[userId]) {
                            await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "external_ban_during_release_review_required");
                            await recordAction(session, { at: Date.now(), action: "verification_chat_release", ok: false, detail: `A permanent ban was observed while releasing @${item.kick_username || userId}; check the current KICK ban state before further action.` });
                            return;
                        }
                        await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "chat_released_clean");
                        await recordAction(session, { at: Date.now(), action: "verification_chat_released", ok: true, detail: `@${item.kick_username || userId} verified cleanly; chat access restored` });
                    });
                }
                catch (e) {
                    // Failed lookups, token refreshes, or release requests leave the
                    // restriction in place and the candidate retryable.
                    await recordAction(session, { at: Date.now(), action: "verification_chat_release", ok: false, detail: e.message });
                }
            }
            else if (item.status === "review") {
                await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "review_required_chat_locked");
                pushEvent(session, { kind: "threat", title: "Verification needs moderator review", detail: `@${item.kick_username || userId} matched a previously blocked first-party device token. Chat remains locked; this is a risk signal, not automatic proof of identity.`, ok: false, score: Number(item.risk_score || 0) });
            }
            else if (item.status === "blocked") {
                await completeRemoteVerification(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, requestId, "blocked_network_chat_locked");
                pushEvent(session, { kind: "threat", title: "Blocked-network verification match", detail: `@${item.kick_username || userId} verified from an exact previously blocked network. Chat remains locked and existing network enforcement settings apply.`, ok: false, score: 100 });
            }
        }
        await store.saveSession(session);
        broadcast(session);
    }
    catch (e) {
        console.error("verification enforcement poll", e.message);
    }
    finally {
        session.verificationQueueProcessing = false;
    }
}
function suspiciousLinkSpam(content, session, senderId) {
    const text = String(content || "").toLowerCase();
    const urls = text.match(/https?:\/\/[^\s]+/g) || [];
    if (!urls.length) return false;
    const scamWords = /(free\s*(nitro|gift|crypto)|claim\s*(now|reward|prize)|wallet|airdrop|giveaway\s*winner|verify\s*account|urgent\s*login|steam\s*gift)/i.test(text);
    const multiLink = urls.length >= 2;
    const repeated = senderId ? session.detector.recentUserExactChatCount(senderId, content, 30) >= 3 : false;
    return (scamWords && (multiLink || repeated)) || (multiLink && repeated);
}
async function applyAutoProtection(session, chatMessageId, chatContent, senderId, assessment) {
    const trustedSender = senderId === session.broadcasterId || (session.trustedUserIds ?? []).includes(senderId);
    if (session.linkScamShieldEnabled !== false && chatMessageId && !trustedSender && suspiciousLinkSpam(chatContent, session, senderId)) {
        try {
            await deleteKickChatMessage(await ensureFreshToken(session), chatMessageId);
            await recordAction(session, { at: Date.now(), action: "auto_delete_suspicious_link_spam", ok: true, detail: `Deleted suspicious repeated/link-heavy message ${chatMessageId}` });
            return;
        } catch (e) {
            await recordAction(session, { at: Date.now(), action: "auto_delete_suspicious_link_spam", ok: false, detail: e.message });
        }
    }
    if (!(session.chatRaidShieldEnabled !== false && chatMessageId && assessment.score >= 85 && assessment.metrics.duplicateRatio60s >= 0.75 && session.detector.recentExactChatCount(chatContent) >= 4))
        return;
    try {
        await deleteKickChatMessage(await ensureFreshToken(session), chatMessageId);
        await recordAction(session, { at: Date.now(), action: "auto_delete_repetitive_chat", ok: true, detail: `Deleted ${chatMessageId}` });
    }
    catch (e) {
        await recordAction(session, { at: Date.now(), action: "auto_delete_repetitive_chat", ok: false, detail: e.message });
    }
    const repeatedBySender = senderId ? session.detector.recentUserExactChatCount(senderId, chatContent, 20) : 0;
    const timeoutKey = `${session.id}:${senderId}`;
    const lastTimeout = automatedTimeouts.get(timeoutKey) || 0;
    const trusted = senderId === session.broadcasterId || (session.trustedUserIds ?? []).includes(senderId);
    if (session.autoTimeoutEnabled && senderId && !trusted && assessment.score >= 95 && repeatedBySender >= 6 && Date.now() - lastTimeout > 10 * 60_000) {
        try {
            await applyUserTimeout(session, senderId, 10, "StreamShield high-confidence repetitive spam");
            automatedTimeouts.set(timeoutKey, Date.now());
            await recordAction(session, { at: Date.now(), action: "auto_timeout_repetitive_spammer", ok: true, detail: `Kick user ${senderId} timed out for 10m after ${repeatedBySender} repeated messages` });
        }
        catch (e) {
            await recordAction(session, { at: Date.now(), action: "auto_timeout_repetitive_spammer", ok: false, detail: e.message });
        }
    }
}
async function processRemoteEvent(session, event) {
    if (!event.kick_message_id || store.hasWebhookSeen(event.kick_message_id))
        return;
    const eventType = event.event_type || "";
    const firstWebhook = !session.lastWebhookAt;
    const receivedAt = Date.parse(event.received_at) || Date.now();
    session.lastWebhookAt = Math.max(session.lastWebhookAt || 0, receivedAt);
    if (firstWebhook)
        pushEvent(session, { kind: "health", title: "Production Kick webhook delivery verified", detail: `Received a signed ${eventType || "Kick"} event through the StreamShield cloud backend.`, ok: true, score: session.lastAssessment.score });
    if (eventType === "moderation.banned" && event.meta?.permanent === true)
        await observePermanentUserBan(session, Number(event.meta.banned_user_id), String(event.meta.created_at || event.event_timestamp || event.received_at || ""));
    let chatMessageId = "";
    let chatContent = "";
    let senderId = 0;
    if (eventType === "chat.message.sent" && event.chat_content !== null && event.chat_content !== undefined) {
        chatMessageId = String(event.kick_chat_message_id || "");
        chatContent = String(event.chat_content || "");
        senderId = Number(event.sender_id) || 0;
        const eventAt = Date.parse(event.event_timestamp || "") || receivedAt;
        session.detector.observeChat(chatContent, senderId || undefined, chatMessageId || undefined, eventAt);
        ensureStreamStats(session).chatsSeen = (ensureStreamStats(session).chatsSeen || 0) + 1;
        if (chatMessageId) {
            session.recentChat.unshift({ messageId: chatMessageId, userId: senderId || undefined, username: String(event.sender_username || ""), content: chatContent, at: eventAt });
            session.recentChat = session.recentChat.slice(0, 50);
        }
    }
    else if (eventType === "channel.followed") {
        session.detector.observeFollow(Number(event.follower_id) || undefined, Date.parse(event.event_timestamp || "") || receivedAt);
        ensureStreamStats(session).followsSeen = (ensureStreamStats(session).followsSeen || 0) + 1;
    }
    else if (eventType === "livestream.status.updated") {
        const wasLive = session.isLive;
        session.isLive = Boolean(event.is_live);
        if (wasLive !== session.isLive)
            pushEvent(session, { kind: "stream", title: session.isLive ? "Kick stream went live" : "Kick stream ended", detail: session.isLive ? "Silent monitoring is active." : "Live protection monitoring is idle until the next stream.", ok: true });
        if (session.isLive) {
            session.detector = new StreamShieldDetector(session.detector.getBaseline());
            session.previousScore = 0;
            session.activeIncidentId = undefined;
            session.streamStats = newStreamStats(receivedAt);
        }
        else {
            ensureStreamStats(session).endedAt = receivedAt;
        }
        if (!session.isLive && session.activeIncidentId) {
            await store.updateIncident(session.activeIncidentId, session.lastAssessment);
            session.activeIncidentId = undefined;
        }
        if (wasLive && !session.isLive)
            await generateStreamReport(session, { automatic: true });
    }
    const assessment = await reassess(session, `Kick cloud webhook anomaly: ${eventType}`);
    if (eventType === "chat.message.sent" && chatMessageId && chatContent)
        await applyAutoProtection(session, chatMessageId, chatContent, senderId, assessment);
    store.markWebhookSeen(event.kick_message_id, receivedAt);
}
async function reconcileKickSubscriptions(session) {
    const wasHealthy = session.subscriptionHealthy;
    if (!publicWebhookAvailable) {
        session.lastSubscriptionCheckAt = Date.now();
        session.subscriptionHealthy = false;
        session.subscriptionMissing = [...KICK_EVENT_NAMES];
        session.subscriptionError = "Local Test mode: public Kick webhooks are not active. Viewer polling and OAuth remain available.";
        if (wasHealthy !== false)
            pushEvent(session, { kind: "health", title: "Local Test mode", detail: session.subscriptionError, ok: true, score: session.lastAssessment.score });
        await store.saveSession(session);
        broadcast(session);
        return;
    }
    try {
        const token = await ensureFreshToken(session);
        const current = await listKickSubscriptions(token, session.broadcasterId);
        const active = new Set(current.data.filter(x => x.method === "webhook" && x.version === 1).map(x => x.event));
        let missing = KICK_EVENT_NAMES.filter(name => !active.has(name));
        if (missing.length) {
            await subscribeKickEvents(token, missing);
            const refreshed = await listKickSubscriptions(token, session.broadcasterId);
            const after = new Set(refreshed.data.filter(x => x.method === "webhook" && x.version === 1).map(x => x.event));
            missing = KICK_EVENT_NAMES.filter(name => !after.has(name));
        }
        session.lastSubscriptionCheckAt = Date.now();
        session.subscriptionMissing = [...missing];
        session.subscriptionHealthy = missing.length === 0;
        session.subscriptionError = "";
    }
    catch (e) {
        session.lastSubscriptionCheckAt = Date.now();
        session.subscriptionHealthy = false;
        session.subscriptionError = e.message;
        console.error("subscription health", e.message);
    }
    if (wasHealthy !== session.subscriptionHealthy) {
        pushEvent(session, { kind: "health", title: session.subscriptionHealthy ? "Kick monitoring restored" : "Kick monitoring degraded", detail: session.subscriptionHealthy ? "Required Kick event subscriptions are active." : (session.subscriptionError || `Missing: ${(session.subscriptionMissing || []).join(", ")}`), ok: !!session.subscriptionHealthy, score: session.lastAssessment.score });
    }
    await store.saveSession(session);
    broadcast(session);
}
async function revokeSessionTokens(session) {
    const errors = [];
    if (session.token.access_token)
        try {
            await revokeKickToken(session.token.access_token, "access_token");
        }
        catch (e) {
            errors.push(e.message);
        }
    if (session.token.refresh_token)
        try {
            await revokeKickToken(session.token.refresh_token, "refresh_token");
        }
        catch (e) {
            errors.push(e.message);
        }
    return errors;
}
setInterval(async () => {
    for (const session of store.sessions.values()) {
        if (session.pollBackoffUntil && Date.now() < session.pollBackoffUntil)
            continue;
        const effectivePollMs = session.isLive ? pollMs : Math.max(60_000, pollMs);
        if (session.lastPollAt && Date.now() - session.lastPollAt < effectivePollMs)
            continue;
        try {
            const token = await ensureFreshToken(session);
            const live = await getKickLivestreamForUser(token, session.broadcasterId);
            session.lastPollAt = Date.now();
            const row = live.data[0];
            const wasLive = session.isLive;
            if (row) {
                session.detector.observeViewer(row.viewer_count);
                session.isLive = true;
            }
            else
                session.isLive = false;
            if (!wasLive && session.isLive) {
                session.streamStats = newStreamStats(Date.now());
                pushEvent(session, { kind: "stream", title: "Kick stream went live", detail: "Follow Shield, Chat Raid Shield, and evidence logging are active.", ok: true });
            }
            if (wasLive && !session.isLive) {
                ensureStreamStats(session).endedAt = Date.now();
                if (session.activeIncidentId) {
                    await store.updateIncident(session.activeIncidentId, session.lastAssessment);
                    session.activeIncidentId = undefined;
                }
                pushEvent(session, { kind: "stream", title: "Kick stream ended", detail: "StreamShield is creating the end-of-stream protection report automatically.", ok: true });
                await generateStreamReport(session, { automatic: true });
            }
            await reassess(session, "Viewer anomaly detected by official Kick livestream data");
        }
        catch (e) {
            const err = e;
            if (err.status === 429)
                session.pollBackoffUntil = Date.now() + Math.max(30_000, (err.retryAfter || 60) * 1000);
            console.error("viewer poll", err.message);
        }
    }
}, 3_000).unref();
setInterval(async () => {
    if (!remoteBackendConfigured)
        return;
    for (const session of store.sessions.values())
        await ensureRemoteRegistration(session);
}, 15_000).unref();
setInterval(async () => {
    if (!remoteBackendConfigured)
        return;
    for (const session of store.sessions.values()) {
        if (!session.remoteBackendRegistered || !session.remoteInstallKey)
            continue;
        try {
            const last = session.remoteLastEventAt ? Date.parse(session.remoteLastEventAt) : 0;
            const after = new Date(last ? Math.max(0, last - 2_000) : Date.now() - 5 * 60_000).toISOString();
            const batch = await getRemoteEvents(remoteBackendUrl, session.broadcasterId, session.remoteInstallKey, after);
            session.remoteLastPollAt = Date.now();
            session.remoteBackendError = "";
            for (const event of batch.events || [])
                await processRemoteEvent(session, event);
            if (batch.events?.length) {
                session.remoteLastEventAt = batch.events[batch.events.length - 1].received_at;
                await store.saveSession(session);
            }
        }
        catch (e) {
            const message = e.message;
            session.remoteBackendError = message;
            if (/\b401\b/.test(message))
                session.remoteBackendRegistered = false;
            console.error("remote event poll", message);
        }
    }
}, 2_000).unref();
setInterval(async () => {
    if (!remoteBackendConfigured)
        return;
    for (const session of store.sessions.values())
        await processNetworkEnforcementQueue(session);
}, 3_000).unref();
setInterval(async () => {
    if (!remoteBackendConfigured)
        return;
    for (const session of store.sessions.values())
        await processVerificationQueue(session);
}, 3_000).unref();
setInterval(async () => {
    if (!remoteBackendConfigured)
        return;
    for (const session of store.sessions.values()) {
        await syncNetworkProtection(session);
        broadcast(session);
    }
}, 10_000).unref();
setInterval(async () => {
    for (const session of store.sessions.values()) {
        if (!session.lastSubscriptionCheckAt || Date.now() - session.lastSubscriptionCheckAt >= 5 * 60_000)
            await reconcileKickSubscriptions(session);
    }
}, 30_000).unref();
setInterval(async () => {
    const oauthCutoff = Date.now() - 10 * 60_000;
    for (const [k, v] of oauthState)
        if (v.at < oauthCutoff)
            oauthState.delete(k);
    store.cleanupWebhookIds();
    await Promise.allSettled([store.flushWebhookIds(), store.persistSessions()]);
}, 60_000).unref();
const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url || "/", baseUrl);
        if (req.method === "GET" && url.pathname === "/")
            return send(res, 200, landing(kickConfigured, supportEmail));
        if (req.method === "GET" && url.pathname === "/privacy")
            return send(res, 200, privacy(supportEmail));
        if (req.method === "GET" && url.pathname === "/terms")
            return send(res, 200, terms(supportEmail));
        if (req.method === "GET" && url.pathname === "/auth/kick/start") {
            if (!kickConfigured)
                return send(res, 500, "Kick connection is not configured", "text/plain");
            if (publicOauthBroker) {
                const installKey = randomBytes(32).toString("base64url");
                const handoff = `${baseUrl}/auth/kick/handoff`;
                try {
                    const started = await startRemoteKickOauth(remoteBackendUrl, handoff, installKey);
                    return redirect(res, started.authorize_url, { "Set-Cookie": cookie("ss_public_install_key", installKey, 600) });
                }
                catch (e) {
                    console.error("public oauth start", e.message);
                    return send(res, 502, "StreamShield cloud OAuth is not ready yet. Please try again shortly.", "text/plain");
                }
            }
            const state = randomBytes(24).toString("base64url"), { verifier, challenge } = makePkce();
            oauthState.set(state, { verifier, at: Date.now() });
            return redirect(res, makeKickAuthorizeUrl(kickConfig, state, challenge), { "Set-Cookie": cookie("ss_oauth_state", state, 600) });
        }
        if (req.method === "GET" && url.pathname === "/auth/kick/handoff") {
            if (!publicOauthBroker)
                return send(res, 404, "Public OAuth broker is not enabled", "text/plain");
            const ticket = url.searchParams.get("ticket") || "", installKey = parseCookies(req).ss_public_install_key || "";
            if (!ticket || !installKey)
                return send(res, 400, "Invalid or expired StreamShield OAuth handoff", "text/plain");
            try {
                const redeemed = await redeemRemoteKickOauth(remoteBackendUrl, ticket, installKey);
                const token = redeemed.token;
                const session = store.createSession({ broadcasterId: redeemed.broadcaster_id, username: redeemed.username, slug: redeemed.slug, token, tokenExpiresAt: Date.now() + Number(token.expires_in || 3600) * 1000, isLive: false });
                session.remoteInstallKey = installKey;
                await ensureRemoteRegistration(session);
                await reconcileKickSubscriptions(session);
                await store.persistSessions();
                return redirect(res, "/dashboard", { "Set-Cookie": [cookie("ss_session", session.id), cookie("ss_public_install_key", "", 0)] });
            }
            catch (e) {
                console.error("public oauth handoff", e.message);
                return send(res, 502, "Kick connected, but StreamShield could not complete the secure handoff. Return to the home page and try Connect Kick again.", "text/plain");
            }
        }
        if (req.method === "GET" && url.pathname === "/auth/kick/callback") {
            if (publicOauthBroker)
                return send(res, 410, "This legacy callback is disabled in public StreamShield builds.", "text/plain");
            const state = url.searchParams.get("state") || "", code = url.searchParams.get("code") || "", browserState = parseCookies(req).ss_oauth_state || "", pending = oauthState.get(state);
            if (!pending || !code || !browserState || !safeEqual(state, browserState))
                return send(res, 400, "Invalid or expired OAuth callback", "text/plain");
            oauthState.delete(state);
            const token = await exchangeKickCode(kickConfig, code, pending.verifier);
            const [u, c] = await Promise.all([getKickUser(token.access_token), getKickChannel(token.access_token)]);
            const user = u.data[0], channel = c.data[0];
            if (!user || !channel)
                return send(res, 502, "Kick user/channel lookup failed", "text/plain");
            const session = store.createSession({ broadcasterId: user.user_id, username: user.name, slug: channel.slug, token, tokenExpiresAt: Date.now() + Number(token.expires_in || 3600) * 1000, isLive: false });
            await ensureRemoteRegistration(session);
            await reconcileKickSubscriptions(session);
            await store.persistSessions();
            return redirect(res, "/dashboard", { "Set-Cookie": [cookie("ss_session", session.id), cookie("ss_oauth_state", "", 0)] });
        }
        if (req.method === "GET" && url.pathname === "/dashboard") {
            const s = getSession(req);
            if (!s)
                return redirect(res, "/");
            return send(res, 200, dashboard(s, store.listIncidents(s.broadcasterId), baseUrl, kickBotUsername, publicWebhookAvailable, webhookPublicUrl));
        }
        if (req.method === "GET" && url.pathname === "/compact") {
            const s = getSession(req);
            if (!s)
                return redirect(res, "/");
            return send(res, 200, compactDashboard(s, publicWebhookAvailable, temporaryWebhookTunnel));
        }
        if (req.method === "GET" && url.pathname.startsWith("/overlay/")) {
            const key = url.pathname.split("/").pop() || "", s = store.getByOverlay(key);
            if (!s)
                return send(res, 404, "Overlay not found", "text/plain");
            return send(res, 200, overlay(s, publicWebhookAvailable, temporaryWebhookTunnel));
        }
        if (req.method === "GET" && url.pathname === "/events/session") {
            const s = getSession(req);
            if (!s)
                return send(res, 401, "Unauthorized", "text/plain");
            addSse(sseBySession, s.id, req, res, snapshot(s));
            return;
        }
        if (req.method === "GET" && url.pathname.startsWith("/events/overlay/")) {
            const key = url.pathname.split("/").pop() || "", s = store.getByOverlay(key);
            if (!s)
                return send(res, 404, "Not found", "text/plain");
            addSse(sseByOverlay, key, req, res, snapshot(s));
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/network-history") {
            const s = getSession(req);
            if (!s)
                return send(res, 401, "Unauthorized", "text/plain");
            if (!remoteBackendConfigured || !s.remoteBackendRegistered || !s.remoteInstallKey)
                return send(res, 503, JSON.stringify({ ok: false, error: "StreamShield cloud backend is not connected" }), "application/json");
            try {
                const result = await getRemoteNetworkHistory(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey);
                return send(res, 200, JSON.stringify(redactNetworkHistory(result)), "application/json");
            }
            catch (e) {
                return send(res, 502, JSON.stringify({ ok: false, error: e.message }), "application/json");
            }
        }
        if (req.method === "GET" && url.pathname === "/api/verification-requests") {
            const s = getSession(req);
            if (!s)
                return send(res, 401, "Unauthorized", "text/plain");
            if (!remoteBackendConfigured || !s.remoteBackendRegistered || !s.remoteInstallKey)
                return send(res, 503, JSON.stringify({ ok: false, error: "StreamShield cloud backend is not connected" }), "application/json");
            try {
                const result = await getRemoteVerificationRecent(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey);
                return send(res, 200, JSON.stringify(result), "application/json");
            }
            catch (e) {
                return send(res, 502, JSON.stringify({ ok: false, error: e.message }), "application/json");
            }
        }
        if (req.method === "GET" && url.pathname.startsWith("/control/")) {
            const parts = url.pathname.split("/").filter(Boolean);
            const key = parts[1] || "", action = parts[2] || "";
            const remote = String(req.socket.remoteAddress || "");
            const local = remote === "127.0.0.1" || remote === "::1" || remote.endsWith(":127.0.0.1");
            const s = [...store.sessions.values()].find(x => x.controlKey === key);
            if (!local || !s) return send(res, 404, "Not found", "text/plain");
            if (action === "panic") {
                if (!s.panicActive) {
                    s.panicPrevious = { mode: s.mode, shieldActive: s.shieldActive, autoTimeoutEnabled: !!s.autoTimeoutEnabled, followShieldEnabled: s.followShieldEnabled !== false, chatRaidShieldEnabled: s.chatRaidShieldEnabled !== false, linkScamShieldEnabled: s.linkScamShieldEnabled !== false };
                    s.panicActive = true; s.mode = "auto"; s.shieldActive = true; s.autoTimeoutEnabled = true; s.followShieldEnabled = true; s.chatRaidShieldEnabled = true; s.linkScamShieldEnabled = true;
                    await store.saveSession(s); await recordAction(s, { at: Date.now(), action: "panic_mode_activated", ok: true, detail: "Local keyed control enabled maximum StreamShield protections" });
                }
                return send(res, 200, "StreamShield Panic Mode active", "text/plain");
            }
            if (action === "panic-off") {
                const p = s.panicPrevious || {};
                s.panicActive = false; s.mode = p.mode || "assist"; s.shieldActive = !!p.shieldActive; s.autoTimeoutEnabled = !!p.autoTimeoutEnabled; s.followShieldEnabled = p.followShieldEnabled !== false; s.chatRaidShieldEnabled = p.chatRaidShieldEnabled !== false; s.linkScamShieldEnabled = p.linkScamShieldEnabled !== false; s.panicPrevious = null;
                await store.saveSession(s); await recordAction(s, { at: Date.now(), action: "panic_mode_released", ok: true, detail: "Restored pre-panic StreamShield settings" });
                return send(res, 200, "StreamShield Panic Mode released", "text/plain");
            }
            return send(res, 404, "Unknown local control", "text/plain");
        }
        if (req.method === "POST" && url.pathname.startsWith("/api/")) {
            const s = getSession(req);
            if (!s)
                return send(res, 401, "Unauthorized", "text/plain");
            if (!validCsrf(req, s))
                return send(res, 403, "CSRF validation failed", "text/plain");
            if (!allowMutation(s.id))
                return send(res, 429, "Too many dashboard actions; retry shortly", "text/plain");
            if (url.pathname === "/api/preflight") {
                try {
                    const result = await runPreflight(s);
                    await recordAction(s, { at: Date.now(), action: "pre_stream_check", ok: result.ready, detail: result.label, meta: { warningCount: result.warnings.length } });
                    return send(res, 200, JSON.stringify({ ok: true, preflight: result }), "application/json");
                }
                catch (e) {
                    return send(res, 500, JSON.stringify({ ok: false, error: e.message || "Pre-stream check failed" }), "application/json");
                }
            }
            if (url.pathname === "/api/offender-case") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0)
                    return send(res, 400, "valid userId required", "text/plain");
                try {
                    const caseFile = await buildOffenderCase(s, userId);
                    return send(res, 200, JSON.stringify({ ok: true, caseFile }), "application/json");
                }
                catch (e) {
                    return send(res, 500, JSON.stringify({ ok: false, error: e.message || "Could not build offender case file" }), "application/json");
                }
            }
            if (url.pathname === "/api/recovery/undo-last") {
                try {
                    const result = await undoLastReversible(s);
                    if (!result.ok)
                        return send(res, 409, JSON.stringify(result), "application/json");
                    broadcast(s);
                    return send(res, 200, JSON.stringify(result), "application/json");
                }
                catch (e) {
                    return send(res, 502, JSON.stringify({ ok: false, error: e.message || "Recovery action failed" }), "application/json");
                }
            }
            if (url.pathname === "/api/report-verify") {
                const b = await jsonBody(req);
                const id = String(b.id || "");
                const inc = store.getIncident(id);
                if (!inc || inc.channelId !== s.broadcasterId || inc.reportType !== "stream_summary")
                    return send(res, 404, JSON.stringify({ ok: false, error: "Stream report not found" }), "application/json");
                const valid = reportSealMatches(inc);
                return send(res, 200, JSON.stringify({ ok: true, valid, evidenceSeal: inc.evidenceSeal || "", eventChainId: inc.eventChainId || "" }), "application/json");
            }
            if (url.pathname === "/api/mark-organic") {
                s.detector.markTrustedEvent(10);
                pushEvent(s, { kind: "info", title: "Surge marked organic", detail: "Streamer started a 10-minute trusted-event window.", ok: true, score: s.lastAssessment.score });
                await reassess(s, "Streamer marked surge organic/expected");
                return send(res, 204, "");
            }
            if (url.pathname === "/api/moderator-setup") {
                const b = await jsonBody(req);
                s.moderatorSetupConfirmed = Boolean(b.confirmed);
                pushEvent(s, { kind: "info", title: s.moderatorSetupConfirmed ? "Moderator setup confirmed" : "Moderator setup cleared", detail: s.moderatorSetupConfirmed ? "Dedicated StreamShield moderator account marked configured." : "Dedicated moderator account is no longer marked configured.", ok: s.moderatorSetupConfirmed });
                await store.saveSession(s);
                broadcast(s);
                return send(res, 204, "");
            }
            if (url.pathname === "/api/auto-timeout") {
                const b = await jsonBody(req);
                s.autoTimeoutEnabled = Boolean(b.enabled);
                pushEvent(s, { kind: "info", title: s.autoTimeoutEnabled ? "Targeted auto-timeouts enabled" : "Targeted auto-timeouts disabled", detail: s.autoTimeoutEnabled ? "Only high-confidence repetitive spam from untrusted Kick accounts can be timed out automatically." : "StreamShield will continue detecting and deleting qualifying repetitive spam but will not auto-timeout users.", ok: true, score: s.lastAssessment.score });
                await store.saveSession(s);
                broadcast(s);
                return send(res, 204, "");
            }
            if (url.pathname === "/api/panic") {
                const b = await jsonBody(req);
                const active = b.active !== false;
                if (active && !s.panicActive) {
                    s.panicPrevious = { mode: s.mode, shieldActive: s.shieldActive, autoTimeoutEnabled: !!s.autoTimeoutEnabled, followShieldEnabled: s.followShieldEnabled !== false, chatRaidShieldEnabled: s.chatRaidShieldEnabled !== false, linkScamShieldEnabled: s.linkScamShieldEnabled !== false };
                    s.panicActive = true; s.mode = "auto"; s.shieldActive = true; s.autoTimeoutEnabled = true; s.followShieldEnabled = true; s.chatRaidShieldEnabled = true; s.linkScamShieldEnabled = true;
                    await store.saveSession(s); await recordAction(s, { at: Date.now(), action: "panic_mode_activated", ok: true, detail: "Maximum StreamShield protections enabled; prior settings saved for restore" });
                } else if (!active && s.panicActive) {
                    const p = s.panicPrevious || {};
                    s.panicActive = false; s.mode = p.mode || "assist"; s.shieldActive = !!p.shieldActive; s.autoTimeoutEnabled = !!p.autoTimeoutEnabled; s.followShieldEnabled = p.followShieldEnabled !== false; s.chatRaidShieldEnabled = p.chatRaidShieldEnabled !== false; s.linkScamShieldEnabled = p.linkScamShieldEnabled !== false; s.panicPrevious = null;
                    await store.saveSession(s); await recordAction(s, { at: Date.now(), action: "panic_mode_released", ok: true, detail: "Restored pre-panic StreamShield protection settings" });
                }
                return send(res, 204, "");
            }
            if (url.pathname === "/api/link-scam-shield") {
                const b = await jsonBody(req); s.linkScamShieldEnabled = b.enabled !== false;
                await store.saveSession(s); await recordAction(s, { at: Date.now(), action: "link_scam_shield_changed", ok: true, detail: s.linkScamShieldEnabled ? "enabled" : "disabled" });
                return send(res, 204, "");
            }
            if (url.pathname === "/api/viewer-history") {
                const b = await jsonBody(req); const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0) return send(res, 400, "valid userId required", "text/plain");
                const messages = s.recentChat.filter(x => Number(x.userId) === userId).slice(0, 20);
                const actions = s.recentActions.filter(x => String(x.detail || "").includes(String(userId)) || messages.some(m => m.username && String(x.detail || "").includes(`@${m.username}`))).slice(0, 20);
                const trusted = (s.trustedUserIds ?? []).includes(userId);
                return send(res, 200, JSON.stringify({ userId, username: messages[0]?.username || "", trusted, messages, actions }), "application/json");
            }
            if (url.pathname === "/api/trusted-user") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0)
                    return send(res, 400, "valid userId required", "text/plain");
                const set = new Set(s.trustedUserIds ?? []);
                const previousTrusted = set.has(userId);
                if (b.trusted === false)
                    set.delete(userId);
                else
                    set.add(userId);
                const trusted = set.has(userId);
                s.trustedUserIds = [...set].slice(0, 500);
                pushEvent(s, { kind: "info", title: trusted ? "Trusted chatter added" : "Trusted chatter removed", detail: `Kick user ${userId} ${trusted ? "will never be auto-timed-out by StreamShield." : "is eligible for normal protection rules again."}`, ok: true, score: s.lastAssessment.score });
                await store.saveSession(s);
                await recordAction(s, { at: Date.now(), action: "trusted_user_changed", ok: true, detail: `Kick user ${userId} trusted=${trusted}`, meta: { userId, previousTrusted, trusted } });
                broadcast(s);
                return send(res, 204, "");
            }
            if (url.pathname === "/api/mode") {
                const b = await jsonBody(req);
                if (!["observe", "assist", "auto"].includes(String(b.mode)))
                    return send(res, 400, "Invalid mode", "text/plain");
                s.mode = b.mode;
                s.shieldActive = s.mode === "auto";
                await store.saveSession(s);
                await recordAction(s, { at: Date.now(), action: "protection_mode_changed", ok: true, detail: s.mode });
                return send(res, 204, "");
            }
            if (url.pathname === "/api/shield") {
                const b = await jsonBody(req);
                s.shieldActive = Boolean(b.active);
                s.mode = s.shieldActive ? "auto" : "assist";
                await store.saveSession(s);
                await recordAction(s, { at: Date.now(), action: s.shieldActive ? "shield_activated" : "shield_deactivated", ok: true, detail: s.mode });
                return send(res, 204, "");
            }
            if (url.pathname === "/api/bot-shields") {
                const b = await jsonBody(req);
                if (typeof b.followShieldEnabled === "boolean") s.followShieldEnabled = b.followShieldEnabled;
                if (typeof b.chatRaidShieldEnabled === "boolean") s.chatRaidShieldEnabled = b.chatRaidShieldEnabled;
                if (typeof b.linkScamShieldEnabled === "boolean") s.linkScamShieldEnabled = b.linkScamShieldEnabled;
                await store.saveSession(s);
                pushEvent(s, { kind: "info", title: "Bot protection settings updated", detail: `Follow Shield ${s.followShieldEnabled !== false ? "ON" : "OFF"} · Chat Raid Shield ${s.chatRaidShieldEnabled !== false ? "ON" : "OFF"} · Link/Scam Shield ${s.linkScamShieldEnabled !== false ? "ON" : "OFF"}`, ok: true, score: s.lastAssessment.score });
                broadcast(s);
                return send(res, 204, "");
            }
            if (url.pathname === "/api/stream-report") {
                try {
                    const item = await generateStreamReport(s, { automatic: false, force: Boolean((await jsonBody(req)).force) });
                    return send(res, 200, JSON.stringify({ ok: true, report: { id: item.id, summaryText: item.summaryText, evidenceSeal: item.evidenceSeal || "", eventChainId: item.eventChainId || "", sealValid: reportSealMatches(item), pdfUrl: `/report/${item.id}.pdf`, htmlUrl: `/report/${item.id}` } }), "application/json");
                }
                catch (e) {
                    return send(res, 500, JSON.stringify({ ok: false, error: e.message || "Could not generate stream report" }), "application/json");
                }
            }
            if (url.pathname === "/api/verification/request") {
                if (!remoteBackendConfigured || !s.remoteBackendRegistered || !s.remoteInstallKey)
                    return send(res, 503, "StreamShield cloud backend is not connected", "text/plain");
                if (!s.networkProtection?.enabled)
                    return send(res, 409, "Enable Full Protection before requiring viewer verification", "text/plain");
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                const username = String(b.username || "").slice(0, 100);
                if (!Number.isFinite(userId) || userId <= 0)
                    return send(res, 400, "valid userId required", "text/plain");
                if (userId === s.broadcasterId)
                    return send(res, 400, "cannot require verification from broadcaster", "text/plain");
                try {
                    const result = await requestUserVerification(s, userId, username);
                    const requestId = String(result?.request?.id || "");
                    await recordAction(s, { at: Date.now(), action: "verification_request", ok: true, detail: `Required verification from @${username || userId}`, meta: { userId, username, requestId } });
                    pushEvent(s, { kind: "action", title: "Channel verification required", detail: `@${username || userId} cannot chat until verification finishes. The one-time link is private to the moderator dashboard until you choose how to deliver it.`, ok: true });
                    broadcast(s);
                    return send(res, 200, JSON.stringify(result), "application/json");
                }
                catch (e) {
                    await recordAction(s, { at: Date.now(), action: "verification_request", ok: false, detail: e.message });
                    return send(res, 502, JSON.stringify({ ok: false, error: e.message }), "application/json");
                }
            }
            if (url.pathname === "/api/verification/release") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                const requestId = String(b.requestId || "");
                if (!Number.isFinite(userId) || userId <= 0 || !requestId)
                    return send(res, 400, "userId and requestId required", "text/plain");
                try {
                    await releaseUserRestriction(s, userId, "released_by_moderator");
                    if (remoteBackendConfigured && s.remoteInstallKey)
                        await completeRemoteVerification(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey, requestId, "released_by_moderator");
                    await store.saveSession(s);
                    await recordAction(s, { at: Date.now(), action: "verification_manual_release", ok: true, detail: `Kick user ${userId} chat access restored by moderator`, meta: { userId, requestId } });
                    return send(res, 204, "");
                }
                catch (e) {
                    return send(res, 502, "Kick chat release failed", "text/plain");
                }
            }
            if (url.pathname === "/api/moderate/delete-message") {
                const b = await jsonBody(req);
                if (!b.messageId)
                    return send(res, 400, "messageId required", "text/plain");
                try {
                    await deleteKickChatMessage(await ensureFreshToken(s), b.messageId);
                    await recordAction(s, { at: Date.now(), action: "delete_chat_message", ok: true, detail: b.messageId });
                    return send(res, 204, "");
                }
                catch (e) {
                    await recordAction(s, { at: Date.now(), action: "delete_chat_message", ok: false, detail: e.message });
                    return send(res, 502, "Kick message deletion failed", "text/plain");
                }
            }
            if (url.pathname === "/api/moderate/ban") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0)
                    return send(res, 400, "valid userId required", "text/plain");
                if (userId === s.broadcasterId)
                    return send(res, 400, "cannot ban broadcaster", "text/plain");
                try {
                    await applyPermanentUserBan(s, userId, b.reason || "StreamShield permanent defensive ban");
                    await recordAction(s, { at: Date.now(), action: "permanent_ban_user", ok: true, detail: `${userId}`, meta: { userId } });
                    return send(res, 204, "");
                }
                catch (e) {
                    await recordAction(s, { at: Date.now(), action: "permanent_ban_user", ok: false, detail: e.message });
                    return send(res, 502, "Kick permanent ban failed", "text/plain");
                }
            }
            if (url.pathname === "/api/moderate/unban") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0)
                    return send(res, 400, "valid userId required", "text/plain");
                if (userId === s.broadcasterId)
                    return send(res, 400, "cannot unban broadcaster", "text/plain");
                try {
                    await releaseUserRestriction(s, userId, "released_by_moderator");
                    await recordAction(s, { at: Date.now(), action: "manual_unban_user", ok: true, detail: `${userId}`, meta: { userId } });
                    return send(res, 204, "");
                }
                catch (e) {
                    await recordAction(s, { at: Date.now(), action: "manual_unban_user", ok: false, detail: e.message });
                    return send(res, 502, "Kick unban failed", "text/plain");
                }
            }
            if (url.pathname === "/api/moderate/timeout") {
                const b = await jsonBody(req);
                const userId = Math.trunc(Number(b.userId));
                if (!Number.isFinite(userId) || userId <= 0 || userId === s.broadcasterId)
                    return send(res, 400, "valid non-broadcaster userId required", "text/plain");
                const minutes = Math.max(1, Math.min(10080, Math.round(b.minutes || 10)));
                try {
                    await applyUserTimeout(s, userId, minutes, b.reason || "StreamShield defensive moderation");
                    await recordAction(s, { at: Date.now(), action: "timeout_user", ok: true, detail: `${b.userId} for ${minutes}m`, meta: { userId: Number(b.userId), minutes } });
                    return send(res, 204, "");
                }
                catch (e) {
                    await recordAction(s, { at: Date.now(), action: "timeout_user", ok: false, detail: e.message });
                    return send(res, 502, "Kick timeout failed", "text/plain");
                }
            }
            if (url.pathname === "/api/network-unblock") {
                if (!remoteBackendConfigured || !s.remoteBackendRegistered || !s.remoteInstallKey)
                    return send(res, 503, "StreamShield cloud backend is not connected", "text/plain");
                const b = await jsonBody(req);
                const networkHash = String(b.networkHash || "");
                if (!/^[a-f0-9]{64}$/i.test(networkHash))
                    return send(res, 400, "valid networkHash required", "text/plain");
                try {
                    const result = await unblockRemoteNetwork(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey, networkHash, b.reason || "manual_un_ip_ban");
                    pushEvent(s, { kind: "action", title: result.unblocked ? "IP block removed" : "IP was already unblocked", detail: result.unblocked ? `Network block removed. ${Number(result.pending_actions_cancelled || 0)} pending auto-ban action(s) cancelled. Existing KICK account bans were not changed.` : "No active network block was found for that IP. Existing KICK account bans were not changed.", ok: true });
                    await syncNetworkProtection(s);
                    await store.saveSession(s);
                    await recordAction(s, { at: Date.now(), action: "network_unblock", ok: true, detail: networkHash, meta: { networkHash, pendingActionsCancelled: Number(result.pending_actions_cancelled || 0) } });
                    broadcast(s);
                    return send(res, 200, JSON.stringify(result), "application/json");
                }
                catch (e) {
                    return send(res, 502, JSON.stringify({ ok: false, error: e.message }), "application/json");
                }
            }
            if (url.pathname === "/api/network-protection") {
                if (!remoteBackendConfigured || !s.remoteBackendRegistered || !s.remoteInstallKey)
                    return send(res, 503, "StreamShield cloud backend is not connected", "text/plain");
                const b = await jsonBody(req);
                const result = await setRemoteNetworkSettings(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey, {
                    enabled: Boolean(b.enabled),
                    autoBanExactNetworkMatch: Boolean(b.autoBanExactNetworkMatch),
                    observationRetentionDays: 30,
                });
                s.networkProtection = {
                    ...(s.networkProtection || {}),
                    enabled: Boolean(result.enabled),
                    auto_ban_exact_network_match: Boolean(result.auto_ban_exact_network_match),
                };
                pushEvent(s, { kind: "info", title: result.enabled ? "Network Protection enabled" : "Network Protection disabled", detail: result.enabled ? (result.auto_ban_exact_network_match ? "Exact blocked-network matches will be automatically banned after StreamShield verification." : "Verified network matches are being recorded; automatic network-match bans are off.") : "Viewer network verification and matching are disabled.", ok: true });
                await syncNetworkProtection(s);
                await store.saveSession(s);
                broadcast(s);
                return send(res, 204, "");
            }
            if (url.pathname === "/api/disconnect") {
                const errors = await revokeSessionTokens(s);
                await store.disconnectSession(s);
                return send(res, 204, "", "text/plain", { "Set-Cookie": cookie("ss_session", "", 0), "X-StreamShield-Revoke": errors.length ? "partial" : "ok" });
            }
            if (url.pathname === "/api/delete-data") {
                const errors = await revokeSessionTokens(s);
                if (remoteBackendConfigured && s.remoteInstallKey) {
                    try {
                        await deleteRemoteChannelData(remoteBackendUrl, s.broadcasterId, s.remoteInstallKey);
                    }
                    catch (e) {
                        console.error("remote delete", e.message);
                    }
                }
                await store.deleteChannelData(s);
                return send(res, 204, "", "text/plain", { "Set-Cookie": cookie("ss_session", "", 0), "X-StreamShield-Revoke": errors.length ? "partial" : "ok" });
            }
            return send(res, 404, "API route not found", "text/plain");
        }
        if (req.method === "GET" && url.pathname.startsWith("/report/")) {
            const s = getSession(req);
            if (!s)
                return redirect(res, "/");
            const part = url.pathname.split("/").pop() || "";
            const wantsPdf = part.endsWith(".pdf");
            const id = wantsPdf ? part.slice(0, -4) : part;
            const inc = store.getIncident(id);
            if (!inc || inc.channelId !== s.broadcasterId)
                return send(res, 404, "Report not found", "text/plain");
            if (wantsPdf) {
                const pdf = buildIncidentPdf(inc);
                const safeName = `streamshield-${inc.channelSlug.replace(/[^a-z0-9_-]+/gi, "-")}-${inc.id}.pdf`;
                return sendBuffer(res, 200, pdf, "application/pdf", { "content-disposition": `attachment; filename="${safeName}"` });
            }
            return send(res, 200, report(inc));
        }
        if (req.method === "POST" && url.pathname === "/webhooks/kick") {
            const raw = await bodyBuffer(req, 512 * 1024);
            const h = { messageId: String(req.headers["kick-event-message-id"] || ""), timestamp: String(req.headers["kick-event-message-timestamp"] || ""), signature: String(req.headers["kick-event-signature"] || "") };
            if (!h.messageId || !h.timestamp || !h.signature)
                return send(res, 400, "Missing Kick webhook headers", "text/plain");
            const sentAt = Date.parse(h.timestamp);
            const age = Date.now() - sentAt;
            if (!Number.isFinite(sentAt) || age > maxWebhookAgeMs || age < -5 * 60_000)
                return send(res, 400, "Kick webhook timestamp outside accepted window", "text/plain");
            if (!(await verifyKickWebhook(raw, h)))
                return send(res, 401, "Invalid Kick webhook signature", "text/plain");
            if (store.hasWebhookSeen(h.messageId))
                return send(res, 204, "");
            if (processingWebhookIds.has(h.messageId))
                return send(res, 503, "Kick webhook is already being processed", "text/plain", { "retry-after": "2" });
            processingWebhookIds.add(h.messageId);
            res.once("close", () => processingWebhookIds.delete(h.messageId));
            const eventType = String(req.headers["kick-event-type"] || "");
            let payload;
            try {
                payload = JSON.parse(raw.toString("utf8"));
            }
            catch {
                processingWebhookIds.delete(h.messageId);
                return send(res, 400, "Invalid JSON", "text/plain");
            }
            const broadcasterId = Number(payload?.broadcaster?.user_id);
            const s = store.getByBroadcaster(broadcasterId);
            if (!s) {
                store.markWebhookSeen(h.messageId, Date.now());
                processingWebhookIds.delete(h.messageId);
                return send(res, 202, "Unknown broadcaster", "text/plain");
            }
            const firstWebhook = !s.lastWebhookAt;
            s.lastWebhookAt = Date.now();
            if (firstWebhook)
                pushEvent(s, { kind: "health", title: "Kick webhook delivery verified", detail: `Received a signed ${eventType || "Kick"} event from Kick. End-to-end webhook delivery is working.`, ok: true, score: s.lastAssessment.score });
            if (eventType === "moderation.banned" && payload?.metadata?.expires_at === null)
                await observePermanentUserBan(s, Number(payload?.banned_user?.user_id), String(payload?.metadata?.created_at || h.timestamp || ""));
            let chatMessageId = "";
            let chatContent = "";
            if (eventType === "chat.message.sent") {
                chatMessageId = String(payload.message_id || "");
                chatContent = String(payload.content || "");
                const senderId = Number(payload?.sender?.user_id) || undefined;
                const eventAt = Date.parse(payload.created_at) || Date.now();
                s.detector.observeChat(chatContent, senderId, chatMessageId || undefined, eventAt);
                ensureStreamStats(s).chatsSeen = (ensureStreamStats(s).chatsSeen || 0) + 1;
                if (chatMessageId) {
                    s.recentChat.unshift({ messageId: chatMessageId, userId: senderId, username: String(payload?.sender?.username || ""), content: chatContent, at: eventAt });
                    s.recentChat = s.recentChat.slice(0, 50);
                }
            }
            else if (eventType === "channel.followed") {
                s.detector.observeFollow(Number(payload?.follower?.user_id) || undefined, Date.parse(payload?.created_at) || Date.now());
                ensureStreamStats(s).followsSeen = (ensureStreamStats(s).followsSeen || 0) + 1;
            }
            else if (eventType === "livestream.status.updated") {
                const wasLive = s.isLive;
                s.isLive = Boolean(payload.is_live);
                if (wasLive !== s.isLive)
                    pushEvent(s, { kind: "stream", title: s.isLive ? "Kick stream went live" : "Kick stream ended", detail: s.isLive ? "Silent monitoring is active." : "Live protection monitoring is idle until the next stream.", ok: true });
                if (s.isLive) {
                    s.detector = new StreamShieldDetector(s.detector.getBaseline());
                    s.previousScore = 0;
                    s.activeIncidentId = undefined;
                    s.streamStats = newStreamStats(Date.now());
                }
                else {
                    ensureStreamStats(s).endedAt = Date.now();
                }
                if (!s.isLive && s.activeIncidentId) {
                    await store.updateIncident(s.activeIncidentId, s.lastAssessment);
                    s.activeIncidentId = undefined;
                }
                if (wasLive && !s.isLive)
                    await generateStreamReport(s, { automatic: true });
            }
            const assessment = await reassess(s, `Kick webhook anomaly: ${eventType}`);
            if (eventType === "chat.message.sent" && chatMessageId && chatContent)
                await applyAutoProtection(s, chatMessageId, chatContent, Number(payload?.sender?.user_id) || 0, assessment);
            store.markWebhookSeen(h.messageId, Date.now());
            processingWebhookIds.delete(h.messageId);
            return send(res, 204, "");
        }
        if (req.method === "GET" && url.pathname === "/health")
            return send(res, 200, JSON.stringify({ ok: true, kickConfigured, publicOauthBroker, sessions: store.sessions.size, kickPrimary: true, encryptedStateAtRest: true, persistentWebhookIdempotency: true, nativeIncidentPdf: true, nativeStreamSummaryPdf: true, automaticStreamReports: true, sha256EvidenceSeals: true, offenderCaseFiles: true, preStreamProtectionCheck: true, recoveryCenter: true, followShield: true, chatRaidShield: true, networkProtectionAvailable: remoteBackendConfigured, targetedVerificationAvailable: remoteBackendConfigured, firstPartyDeviceTokens: true, invasiveDeviceFingerprinting: false, storesRawViewerIps: false, storesEncryptedVerifiedIps: false, storesHashedNetworkIdentifiers: true, publicWebhookAvailable, temporaryWebhookTunnel, webhookPublicUrl: publicWebhookAvailable ? webhookPublicUrl : "", remoteBackendConfigured, remoteBackendUrl: remoteBackendConfigured ? remoteBackendUrl : "", requiredKickEvents: KICK_EVENT_NAMES }), "application/json");
        return send(res, 404, "Not found", "text/plain");
    }
    catch (e) {
        const err = e;
        console.error(err.message);
        return send(res, err.statusCode || 500, err.statusCode === 413 ? "Request body too large" : "Internal error", "text/plain");
    }
});
const pidPath = resolve(dataDir, "streamshield.pid");
server.listen(port, async () => {
    try {
        await writeFile(pidPath, String(process.pid), { encoding: "utf8", mode: 0o600 });
    }
    catch { }
    console.log(`StreamShield listening on ${baseUrl}`);
});
let shuttingDown = false;
async function shutdown() {
    if (shuttingDown)
        return;
    shuttingDown = true;
    try {
        await unlink(pidPath);
    }
    catch { }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
}
process.on("SIGINT", () => { void shutdown(); });
process.on("SIGTERM", () => { void shutdown(); });

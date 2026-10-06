import { createHash, randomBytes } from "node:crypto";
export const KICK_EVENT_NAMES = [
    "chat.message.sent",
    "channel.followed",
    "livestream.status.updated",
    "livestream.metadata.updated",
    "moderation.banned",
];
export const KICK_SCOPES = [
    "user:read",
    "channel:read",
    "events:subscribe",
    "chat:write",
    "moderation:ban",
    "moderation:chat_message:manage",
];
export function makePkce() {
    const verifier = randomBytes(48).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    return { verifier, challenge };
}
export function makeKickAuthorizeUrl(config, state, challenge) {
    const u = new URL("https://id.kick.com/oauth/authorize");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", config.clientId);
    u.searchParams.set("redirect_uri", config.redirectUri);
    u.searchParams.set("scope", KICK_SCOPES.join(" "));
    u.searchParams.set("state", state);
    u.searchParams.set("code_challenge", challenge);
    u.searchParams.set("code_challenge_method", "S256");
    return u.toString();
}
async function jsonFetch(url, init = {}) {
    const res = await fetch(url, init);
    const text = await res.text();
    let parsed = undefined;
    try {
        parsed = text ? JSON.parse(text) : undefined;
    }
    catch {
        parsed = text;
    }
    if (!res.ok) {
        const err = new Error(`Kick API ${res.status}: ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
        err.status = res.status;
        const retry = res.headers.get("retry-after");
        if (retry)
            err.retryAfter = Number(retry);
        throw err;
    }
    return parsed;
}
export async function exchangeKickCode(config, code, verifier) {
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
        code_verifier: verifier,
        code,
    });
    return jsonFetch("https://id.kick.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
    });
}
export async function refreshKickToken(config, refreshToken) {
    const body = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: config.clientId,
        client_secret: config.clientSecret,
        refresh_token: refreshToken,
        redirect_uri: config.redirectUri,
    });
    return jsonFetch("https://id.kick.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
    });
}
export async function revokeKickToken(token, hint = "access_token") {
    const u = new URL("https://id.kick.com/oauth/revoke");
    u.searchParams.set("token", token);
    u.searchParams.set("token_type_hint", hint);
    const res = await fetch(u, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    if (!res.ok)
        throw new Error(`Kick revoke failed: ${res.status} ${await res.text()}`);
}
function auth(token) {
    return { Authorization: `Bearer ${token}`, Accept: "application/json" };
}
export async function getKickUser(token) {
    return jsonFetch("https://api.kick.com/public/v1/users", { headers: auth(token) });
}
export async function getKickChannel(token) {
    return jsonFetch("https://api.kick.com/public/v1/channels", { headers: auth(token) });
}
export async function subscribeKickEvents(token, names = KICK_EVENT_NAMES) {
    const events = names.map(name => ({ name, version: 1 }));
    return jsonFetch("https://api.kick.com/public/v1/events/subscriptions", {
        method: "POST",
        headers: { ...auth(token), "Content-Type": "application/json" },
        body: JSON.stringify({ events, method: "webhook" }),
    });
}
export async function listKickSubscriptions(token, broadcasterUserId) {
    const u = new URL("https://api.kick.com/public/v1/events/subscriptions");
    if (broadcasterUserId)
        u.searchParams.set("broadcaster_user_id", String(broadcasterUserId));
    return jsonFetch(u.toString(), { headers: auth(token) });
}
export async function getKickLivestreamForUser(token, userId) {
    const u = new URL("https://api.kick.com/public/v1/users/livestreams");
    u.searchParams.append("user_id", String(userId));
    return jsonFetch(u.toString(), { headers: auth(token) });
}
export async function deleteKickChatMessage(token, messageId) {
    return jsonFetch(`https://api.kick.com/public/v1/chat/${encodeURIComponent(messageId)}`, {
        method: "DELETE",
        headers: auth(token),
    });
}
export async function sendKickChatMessage(token, broadcasterUserId, content, replyToMessageId = "") {
    const body = {
        broadcaster_user_id: broadcasterUserId,
        content: String(content || "").slice(0, 500),
        type: "user",
    };
    if (replyToMessageId)
        body.reply_to_message_id = String(replyToMessageId);
    return jsonFetch("https://api.kick.com/public/v1/chat", {
        method: "POST",
        headers: { ...auth(token), "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
}
export async function timeoutKickUser(token, broadcasterUserId, userId, minutes, reason) {
    return jsonFetch("https://api.kick.com/public/v1/moderation/bans", {
        method: "POST",
        headers: { ...auth(token), "Content-Type": "application/json" },
        body: JSON.stringify({
            broadcaster_user_id: broadcasterUserId,
            user_id: userId,
            duration: Math.max(1, Math.min(10080, Math.round(minutes))),
            reason: reason.slice(0, 100),
        }),
    });
}
export async function banKickUser(token, broadcasterUserId, userId, reason) {
    return jsonFetch("https://api.kick.com/public/v1/moderation/bans", {
        method: "POST",
        headers: { ...auth(token), "Content-Type": "application/json" },
        body: JSON.stringify({
            broadcaster_user_id: broadcasterUserId,
            user_id: userId,
            reason: String(reason || "StreamShield permanent defensive ban").slice(0, 100),
        }),
    });
}
export async function unbanKickUser(token, broadcasterUserId, userId) {
    return jsonFetch("https://api.kick.com/public/v1/moderation/bans", {
        method: "DELETE",
        headers: { ...auth(token), "Content-Type": "application/json" },
        body: JSON.stringify({
            broadcaster_user_id: broadcasterUserId,
            user_id: userId,
        }),
    });
}

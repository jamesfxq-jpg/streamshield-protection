function base(url) {
    return url.replace(/\/+$/, "");
}
async function parse(res) {
    const text = await res.text();
    let body = undefined;
    try {
        body = text ? JSON.parse(text) : undefined;
    }
    catch {
        body = text;
    }
    if (!res.ok)
        throw new Error(`StreamShield cloud ${res.status}: ${typeof body === "string" ? body : JSON.stringify(body)}`);
    return body;
}
export async function startRemoteKickOauth(url, localCallback, installKey) {
    const res = await fetch(`${base(url)}/oauth/start`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ local_callback: localCallback, install_key: installKey }),
    });
    return parse(res);
}
export async function redeemRemoteKickOauth(url, ticket, installKey) {
    const res = await fetch(`${base(url)}/oauth/redeem`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ ticket, install_key: installKey }),
    });
    return parse(res);
}
export async function refreshRemoteKickToken(url, broadcasterId, refreshToken, installKey) {
    const res = await fetch(`${base(url)}/oauth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId, refresh_token: refreshToken }),
    });
    const parsed = await parse(res);
    return parsed.token;
}
export async function registerRemoteBackend(url, kickAccessToken, installKey) {
    const res = await fetch(`${base(url)}/register`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ kick_access_token: kickAccessToken, install_key: installKey }),
    });
    return parse(res);
}
export async function getRemoteEvents(url, broadcasterId, installKey, after) {
    const u = new URL(`${base(url)}/events`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    if (after)
        u.searchParams.set("after", after);
    const res = await fetch(u, {
        headers: { accept: "application/json", "x-streamshield-install-key": installKey },
    });
    return parse(res);
}
export async function getRemoteStatus(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/status`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, {
        headers: { accept: "application/json", "x-streamshield-install-key": installKey },
    });
    return parse(res);
}
export async function deleteRemoteChannelData(url, broadcasterId, installKey) {
    const res = await fetch(`${base(url)}/delete-data`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId }),
    });
    return parse(res);
}

export async function getRemoteNetworkStatus(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/network/status`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, { headers: { accept: "application/json", "x-streamshield-install-key": installKey } });
    return parse(res);
}
export async function getRemoteNetworkHistory(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/network/history`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, { headers: { accept: "application/json", "x-streamshield-install-key": installKey } });
    return parse(res);
}
export async function unblockRemoteNetwork(url, broadcasterId, installKey, networkHash, reason = "manual_un_ip_ban") {
    const res = await fetch(`${base(url)}/network/unblock`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId, network_hash: networkHash, reason }),
    });
    return parse(res);
}
export async function setRemoteNetworkSettings(url, broadcasterId, installKey, settings = {}) {
    const res = await fetch(`${base(url)}/network/settings`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({
            broadcaster_id: broadcasterId,
            enabled: Boolean(settings.enabled),
            auto_ban_exact_network_match: Boolean(settings.autoBanExactNetworkMatch),
            observation_retention_days: Number(settings.observationRetentionDays || 30),
        }),
    });
    return parse(res);
}
export async function getRemoteNetworkQueue(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/network/queue`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, { headers: { accept: "application/json", "x-streamshield-install-key": installKey } });
    return parse(res);
}
export async function completeRemoteNetworkQueue(url, broadcasterId, installKey, id, outcome) {
    const res = await fetch(`${base(url)}/network/queue/complete`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId, id, outcome }),
    });
    return parse(res);
}

export async function createRemoteVerificationRequest(url, broadcasterId, installKey, userId, username = "", note = "") {
    const res = await fetch(`${base(url)}/verification/request`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId, kick_user_id: userId, kick_username: username, note }),
    });
    return parse(res);
}
export async function getRemoteVerificationQueue(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/verification/queue`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, { headers: { accept: "application/json", "x-streamshield-install-key": installKey } });
    return parse(res);
}
export async function getRemoteVerificationRecent(url, broadcasterId, installKey) {
    const u = new URL(`${base(url)}/verification/recent`);
    u.searchParams.set("broadcaster_id", String(broadcasterId));
    const res = await fetch(u, { headers: { accept: "application/json", "x-streamshield-install-key": installKey } });
    return parse(res);
}
export async function completeRemoteVerification(url, broadcasterId, installKey, id, outcome) {
    const res = await fetch(`${base(url)}/verification/complete`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-streamshield-install-key": installKey },
        body: JSON.stringify({ broadcaster_id: broadcasterId, id, outcome }),
    });
    return parse(res);
}

export async function createRemoteModeratorInvite(url,broadcasterId,installKey,userId,username="") {
    const res=await fetch(`${base(url)}/moderator/install/invite`,{
        method:"POST",headers:{"content-type":"application/json",accept:"application/json","x-streamshield-install-key":installKey},
        body:JSON.stringify({broadcaster_id:broadcasterId,kick_user_id:userId,kick_username:username}),
    });
    return parse(res);
}
export async function getRemoteModeratorAccess(url,broadcasterId,installKey) {
    const u=new URL(`${base(url)}/moderator/install/access`);
    u.searchParams.set("broadcaster_id",String(broadcasterId));
    const res=await fetch(u,{headers:{accept:"application/json","x-streamshield-install-key":installKey}});
    return parse(res);
}
export async function revokeRemoteModerator(url,broadcasterId,installKey,userId) {
    const res=await fetch(`${base(url)}/moderator/install/revoke`,{
        method:"POST",headers:{"content-type":"application/json",accept:"application/json","x-streamshield-install-key":installKey},
        body:JSON.stringify({broadcaster_id:broadcasterId,kick_user_id:userId}),
    });
    return parse(res);
}
export async function getRemoteModeratorCommands(url,broadcasterId,installKey) {
    const u=new URL(`${base(url)}/moderator/install/commands`);
    u.searchParams.set("broadcaster_id",String(broadcasterId));
    const res=await fetch(u,{headers:{accept:"application/json","x-streamshield-install-key":installKey}});
    return parse(res);
}
export async function completeRemoteModeratorCommand(url,broadcasterId,installKey,id,ok,outcome="",result={}) {
    const res=await fetch(`${base(url)}/moderator/install/commands/complete`,{
        method:"POST",headers:{"content-type":"application/json",accept:"application/json","x-streamshield-install-key":installKey},
        body:JSON.stringify({broadcaster_id:broadcasterId,id,ok:Boolean(ok),outcome,result}),
    });
    return parse(res);
}

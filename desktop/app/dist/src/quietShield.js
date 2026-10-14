/**
 * Quiet Shield: privacy-preserving status and short-lived delivery state.
 * No raw IPs, persistent verification URLs, fingerprints, or KICK API calls.
 */
export function summarizeBanShield(history, userId, { enabled = false } = {}) {
    if (!enabled) return { state: "protection_off", message: "Account banned. Network Shield is off; no network protection is claimed." };
    if (history === null || history === undefined) return { state: "history_unavailable", message: "Account banned. Network history could not be checked. The account ban was not undone." };
    const value = history.history ?? history;
    const rows = Array.isArray(value) ? value : [value?.observations, value?.blocks, value?.items, value?.networks].filter(Array.isArray).flat();
    if (!Array.isArray(value) && ![value?.observations, value?.blocks, value?.items, value?.networks].some(Array.isArray)) {
        return { state: "history_unavailable", message: "Account banned. Network history could not be checked. The account ban was not undone." };
    }
    // Match stable account IDs only. Usernames can change or be reused.
    const matches = rows.filter(row => row && [row.kick_user_id, row.user_id, row.source_user_id, ...(Array.isArray(row.accounts) ? row.accounts.map(a => a?.kick_user_id) : [])].some(id => Number.isSafeInteger(Number(id)) && Number(id) > 0 && Number(id) === Number(userId)));
    if (!matches.length) return { state: "no_retained_network", retained_networks: 0, message: "Account banned. No retained verified network was found for this account; network protection cannot be confirmed." };
    const blocked = matches.filter(row => typeof row.blocked === "boolean" ? row.blocked : typeof row.is_blocked === "boolean" ? row.is_blocked : Boolean(row.blocked_at && (!row.unblocked_at || Date.parse(row.blocked_at) > Date.parse(row.unblocked_at)))).length;
    return blocked === matches.length
        ? { state: "network_shield_active", retained_networks: matches.length, blocked_networks: blocked, message: "Account banned. Its retained verified network history is marked for repeat-abuse checks. Network matches are signals, not proof of identity." }
        : { state: "network_sync_pending", retained_networks: matches.length, blocked_networks: blocked, message: "Account banned. Verified history exists; the network update is not yet confirmed. Refresh Network & Ban History after the signed KICK ban event arrives." };
}

export function validateVerificationResult(result, backendUrl, now = Date.now()) {
    const id = String(result?.request?.id || "");
    let link, backend;
    try { link = new URL(String(result?.verification_url || "")); backend = new URL(backendUrl); } catch { throw new Error("The backend returned an invalid verification link; no chat restriction was applied."); }
    const expires = Date.parse(result?.expires_at || "");
    const token = link.searchParams.get("request") || "";
    if (!id || backend.protocol !== "https:" || link.origin !== backend.origin || link.pathname !== backend.pathname.replace(/\/$/, "") + "/verification/start" || link.username || link.password || link.hash || link.searchParams.getAll("request").length !== 1 || !/^[A-Za-z0-9_-]{32,128}$/.test(token) || !Number.isFinite(expires) || expires <= now || expires > now + 31 * 60_000) {
        throw new Error("The backend returned an invalid verification request; no chat restriction was applied.");
    }
    return { requestId: id, expiresAt: expires };
}

/** In-memory only; session-scoped, bounded, and never extends a link's expiry. */
export function createVerificationDeliveryCache({ maxEntries = 500, now = () => Date.now() } = {}) {
    const entries = new Map();
    const prune = () => {
        for (const [key, entry] of entries) if (entry.expiresAt <= now()) entries.delete(key);
        while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
    };
    return {
        remember(key, result, expiresAt) {
            prune();
            entries.set(key, { result, expiresAt, sentAt: 0, sentMessageId: "" });
            prune();
        },
        get(key, requestId) {
            prune();
            const entry = entries.get(key);
            return entry && String(entry.result.request.id) === String(requestId) ? entry : undefined;
        },
        forget(key) { entries.delete(key); },
        markSent(key, requestId, messageId) {
            const entry = this.get(key, requestId);
            if (entry) { entry.sentAt = now(); entry.sentMessageId = String(messageId || ""); }
        },
        get size() { prune(); return entries.size; },
    };
}

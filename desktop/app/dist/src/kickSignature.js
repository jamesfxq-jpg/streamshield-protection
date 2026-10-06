import { createPublicKey, verify } from "node:crypto";
let cachedPublicKey = null;
let cachedAt = 0;
export async function getKickPublicKey(force = false) {
    if (!force && cachedPublicKey && Date.now() - cachedAt < 6 * 60 * 60_000)
        return cachedPublicKey;
    const res = await fetch("https://api.kick.com/public/v1/public-key", { headers: { Accept: "application/json" } });
    if (!res.ok)
        throw new Error(`Kick public-key fetch failed: ${res.status}`);
    const body = await res.json();
    const key = body.data?.public_key;
    if (!key)
        throw new Error("Kick public key missing from API response");
    cachedPublicKey = key;
    cachedAt = Date.now();
    return key;
}
export function verifyKickWebhookWithKey(rawBody, headers, publicKeyPem) {
    if (!headers.messageId || !headers.timestamp || !headers.signature)
        return false;
    const signed = Buffer.concat([
        Buffer.from(headers.messageId + "." + headers.timestamp + ".", "utf8"),
        rawBody,
    ]);
    try {
        return verify("RSA-SHA256", signed, createPublicKey(publicKeyPem), Buffer.from(headers.signature, "base64"));
    }
    catch {
        return false;
    }
}
export async function verifyKickWebhook(rawBody, headers) {
    const key = await getKickPublicKey();
    if (verifyKickWebhookWithKey(rawBody, headers, key))
        return true;
    const fresh = await getKickPublicKey(true);
    return verifyKickWebhookWithKey(rawBody, headers, fresh);
}

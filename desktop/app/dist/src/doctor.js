import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getKickPublicKey } from "./kickSignature.js";
async function loadDotEnv() {
    try {
        const text = await readFile(resolve(process.cwd(), ".env"), "utf8");
        for (const line of text.split(/\r?\n/)) {
            const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
            if (m && process.env[m[1]] === undefined)
                process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, "");
        }
    }
    catch { }
}
await loadDotEnv();
const checks = [];
const major = Number(process.versions.node.split(".")[0]);
checks.push(["Node.js 20+", major >= 20, process.version]);
const base = process.env.PUBLIC_BASE_URL || "http://localhost:8787";
let baseUrl;
try {
    baseUrl = new URL(base);
    checks.push(["PUBLIC_BASE_URL parses", true, baseUrl.toString()]);
}
catch {
    checks.push(["PUBLIC_BASE_URL parses", false, base]);
}
const liveHost = baseUrl && !["localhost", "127.0.0.1", "::1"].includes(baseUrl.hostname);
checks.push(["Public live host uses HTTPS", !liveHost || baseUrl?.protocol === "https:", liveHost ? String(baseUrl?.protocol) : "local-development host"]);
const legacyKickConfigured = Boolean(process.env.KICK_CLIENT_ID && process.env.KICK_CLIENT_SECRET && process.env.KICK_REDIRECT_URI);
const remoteBackend = (process.env.STREAMSHIELD_REMOTE_BACKEND_URL || "https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend").trim().replace(/\/+$/, "");
const publicOauthBroker = Boolean(remoteBackend) && process.env.STREAMSHIELD_PUBLIC_OAUTH !== "0";
checks.push(["Kick connection mode", legacyKickConfigured || publicOauthBroker, publicOauthBroker ? "StreamShield public OAuth broker" : legacyKickConfigured ? "legacy owner credentials" : "not configured"]);
if (legacyKickConfigured && baseUrl && process.env.KICK_REDIRECT_URI) {
    const expected = `${baseUrl.origin}/auth/kick/callback`;
    checks.push(["Legacy Kick redirect matches StreamShield host", process.env.KICK_REDIRECT_URI === expected, `expected ${expected}`]);
}
if (remoteBackend) {
    try {
        const u = new URL(remoteBackend);
        checks.push(["StreamShield cloud backend URL", u.protocol === "https:", u.toString()]);
    }
    catch {
        checks.push(["StreamShield cloud backend URL", false, remoteBackend]);
    }
}
const skipNetwork = process.env.STREAMSHIELD_DOCTOR_SKIP_NETWORK === "1";
if (skipNetwork) {
    checks.push(["Kick public-key endpoint reachable", true, "skipped in CI/offline doctor mode"]);
    if (remoteBackend)
        checks.push(["StreamShield cloud backend reachable", true, "skipped in CI/offline doctor mode"]);
}
else {
    try {
        const key = await getKickPublicKey(true);
        checks.push(["Kick public-key endpoint reachable", key.includes("BEGIN PUBLIC KEY"), "official signature key fetched"]);
    }
    catch (e) {
        checks.push(["Kick public-key endpoint reachable", false, e.message]);
    }
    if (remoteBackend) {
        try {
            const r = await fetch(`${remoteBackend}/health`, { headers: { accept: "application/json" } });
            const b = await r.json();
            checks.push(["StreamShield cloud backend reachable", r.ok && b.ok === true, `${r.status} ${remoteBackend}/health`]);
        }
        catch (e) {
            checks.push(["StreamShield cloud backend reachable", false, e.message]);
        }
    }
}
const allowUnconfigured = process.env.STREAMSHIELD_DOCTOR_ALLOW_UNCONFIGURED === "1";
console.log("StreamShield Kick readiness doctor\n");
for (const [name, ok, detail] of checks) {
    console.log(`${ok ? "PASS" : "FAIL"}  ${name} — ${detail}`);
}
const configuredWebhook = process.env.KICK_WEBHOOK_PUBLIC_URL || (remoteBackend ? `${remoteBackend}/kick-webhook` : (baseUrl ? `${baseUrl.origin}/webhooks/kick` : "invalid PUBLIC_BASE_URL"));
console.log(`\nWebhook URL: ${configuredWebhook}`);
console.log(`OAuth mode: ${publicOauthBroker ? "StreamShield public cloud broker" : "legacy local app credentials"}`);
const criticalFailed = checks.some(([, ok]) => !ok);
if (criticalFailed && !allowUnconfigured)
    process.exitCode = 2;

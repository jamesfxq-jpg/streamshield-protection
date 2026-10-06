import { chmod, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { StreamShieldDetector } from "./detector.js";
function parseConfiguredKey(raw) {
    if (!raw)
        return undefined;
    const trimmed = raw.trim();
    if (/^[0-9a-f]{64}$/i.test(trimmed))
        return Buffer.from(trimmed, "hex");
    try {
        const buf = Buffer.from(trimmed, "base64");
        if (buf.length === 32)
            return buf;
    }
    catch { }
    throw new Error("STREAMSHIELD_STORAGE_KEY must be 32 bytes encoded as base64 or 64 hex characters");
}
async function atomicWrite(path, content) {
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, content, { encoding: "utf8", mode: 0o600 });
    await rename(tmp, path);
}
export class RuntimeStore {
    dataDir;
    sessions = new Map();
    byBroadcaster = new Map();
    overlayToSession = new Map();
    incidents = [];
    baselines = new Map();
    seenWebhookIds = new Map();
    storageKey;
    webhookDirty = false;
    constructor(dataDir) {
        this.dataDir = dataDir;
    }
    async init() {
        await mkdir(this.dataDir, { recursive: true });
        this.storageKey = await this.loadOrCreateStorageKey();
        const encryptedIncidents = await this.readEncryptedState("incidents.enc.json");
        if (encryptedIncidents) {
            this.incidents = encryptedIncidents;
        }
        else {
            try {
                const raw = await readFile(`${this.dataDir}/incidents.ndjson`, "utf8");
                this.incidents = raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).reverse();
                await this.rewriteIncidents();
                await this.removeLegacyFile("incidents.ndjson");
            }
            catch (error) {
                if (!this.isMissingFile(error))
                    throw error;
            }
        }
        const encryptedBaselines = await this.readEncryptedState("baselines.enc.json");
        if (encryptedBaselines) {
            for (const [id, baseline] of Object.entries(encryptedBaselines))
                this.baselines.set(Number(id), baseline);
        }
        else {
            try {
                const raw = JSON.parse(await readFile(`${this.dataDir}/baselines.json`, "utf8"));
                for (const [id, baseline] of Object.entries(raw))
                    this.baselines.set(Number(id), baseline);
                await this.persistBaselines();
                await this.removeLegacyFile("baselines.json");
            }
            catch (error) {
                if (!this.isMissingFile(error))
                    throw error;
            }
        }
        const encryptedWebhookIds = await this.readEncryptedState("webhook-ids.enc.json");
        if (encryptedWebhookIds) {
            const cutoff = Date.now() - 48 * 60 * 60_000;
            for (const [id, at] of Object.entries(encryptedWebhookIds))
                if (Number(at) >= cutoff)
                    this.seenWebhookIds.set(id, Number(at));
        }
        else {
            try {
                const raw = JSON.parse(await readFile(`${this.dataDir}/webhook-ids.json`, "utf8"));
                const cutoff = Date.now() - 48 * 60 * 60_000;
                for (const [id, at] of Object.entries(raw))
                    if (Number(at) >= cutoff)
                        this.seenWebhookIds.set(id, Number(at));
                this.webhookDirty = true;
                await this.flushWebhookIds();
                await this.removeLegacyFile("webhook-ids.json");
            }
            catch (error) {
                if (!this.isMissingFile(error))
                    throw error;
            }
        }
        await this.loadPersistedSessions();
    }
    isMissingFile(error) {
        return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
    }
    async readEncryptedState(name) {
        let raw;
        try {
            raw = await readFile(`${this.dataDir}/${name}`, "utf8");
        }
        catch (error) {
            if (this.isMissingFile(error))
                return undefined;
            throw error;
        }
        try {
            return this.decrypt(raw);
        }
        catch (error) {
            throw new Error(`Unable to decrypt ${name}. Verify STREAMSHIELD_STORAGE_KEY or the local .streamshield-key file.`, { cause: error });
        }
    }
    async removeLegacyFile(name) {
        try {
            await unlink(`${this.dataDir}/${name}`);
        }
        catch (error) {
            if (!this.isMissingFile(error))
                throw error;
        }
    }
    async loadOrCreateStorageKey() {
        const configured = parseConfiguredKey(process.env.STREAMSHIELD_STORAGE_KEY);
        if (configured)
            return configured;
        const keyPath = `${this.dataDir}/.streamshield-key`;
        try {
            const raw = (await readFile(keyPath, "utf8")).trim();
            const key = Buffer.from(raw, "base64");
            if (key.length !== 32)
                throw new Error("invalid local key length");
            return key;
        }
        catch {
            const key = randomBytes(32);
            await writeFile(keyPath, key.toString("base64"), { encoding: "utf8", mode: 0o600 });
            try {
                await chmod(keyPath, 0o600);
            }
            catch { }
            return key;
        }
    }
    encrypt(value) {
        const iv = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", this.storageKey, iv);
        const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
        const envelope = {
            v: 1,
            iv: iv.toString("base64"),
            tag: cipher.getAuthTag().toString("base64"),
            ciphertext: ciphertext.toString("base64"),
        };
        return JSON.stringify(envelope);
    }
    decrypt(raw) {
        const envelope = JSON.parse(raw);
        if (envelope.v !== 1)
            throw new Error("unsupported encrypted session format");
        const decipher = createDecipheriv("aes-256-gcm", this.storageKey, Buffer.from(envelope.iv, "base64"));
        decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
        const plaintext = Buffer.concat([
            decipher.update(Buffer.from(envelope.ciphertext, "base64")),
            decipher.final(),
        ]).toString("utf8");
        return JSON.parse(plaintext);
    }
    async loadPersistedSessions() {
        const rows = await this.readEncryptedState("sessions.enc.json");
        if (!rows)
            return;
        for (const row of rows) {
            const detector = new StreamShieldDetector(this.baselines.get(row.broadcasterId));
            const session = {
                ...row,
                autoTimeoutEnabled: row.autoTimeoutEnabled ?? false,
                followShieldEnabled: row.followShieldEnabled ?? true,
                chatRaidShieldEnabled: row.chatRaidShieldEnabled ?? true,
                linkScamShieldEnabled: row.linkScamShieldEnabled ?? true,
                panicActive: row.panicActive ?? false,
                panicPrevious: row.panicPrevious ?? null,
                streamStats: row.streamStats ?? { startedAt: row.createdAt ?? Date.now(), followsSeen: 0, chatsSeen: 0, maxThreatScore: 0, maxFollows60s: 0, maxChats60s: 0, maxViewerDelta30s: 0, maxViewers: 0, followSpikes: 0, chatRaidMessagesDeleted: 0, chatRaidTimeouts: 0, verificationRequests: 0, permanentBans: 0, networkAutoBans: 0, followSpikeActive: false },
                trustedUserIds: row.trustedUserIds ?? [],
                verificationLocks: row.verificationLocks ?? {},
                permanentBanHolds: row.permanentBanHolds ?? {},
                remoteInstallKey: row.remoteInstallKey ?? randomBytes(32).toString("base64url"),
                controlKey: row.controlKey ?? randomBytes(24).toString("base64url"),
                remoteLastEventAt: row.remoteLastEventAt,
                remoteBackendRegistered: row.remoteBackendRegistered ?? false,
                remoteBackendError: row.remoteBackendError ?? "",
                detector,
                lastAssessment: detector.assess(),
                previousScore: 0,
                recentChat: [],
                recentActions: [],
                recentEvents: [],
            };
            this.sessions.set(session.id, session);
            this.byBroadcaster.set(session.broadcasterId, session.id);
            this.overlayToSession.set(session.overlayKey, session.id);
        }
    }
    serializeSessions() {
        return [...this.sessions.values()].map(session => ({
            id: session.id,
            overlayKey: session.overlayKey,
            csrfToken: session.csrfToken,
            createdAt: session.createdAt,
            broadcasterId: session.broadcasterId,
            username: session.username,
            slug: session.slug,
            token: session.token,
            tokenExpiresAt: session.tokenExpiresAt,
            mode: session.mode,
            shieldActive: session.shieldActive,
            isLive: session.isLive,
            lastWebhookAt: session.lastWebhookAt,
            lastPollAt: session.lastPollAt,
            lastSubscriptionCheckAt: session.lastSubscriptionCheckAt,
            subscriptionHealthy: session.subscriptionHealthy,
            subscriptionMissing: session.subscriptionMissing,
            subscriptionError: session.subscriptionError,
            moderatorSetupConfirmed: session.moderatorSetupConfirmed,
            autoTimeoutEnabled: session.autoTimeoutEnabled,
            followShieldEnabled: session.followShieldEnabled ?? true,
            chatRaidShieldEnabled: session.chatRaidShieldEnabled ?? true,
            linkScamShieldEnabled: session.linkScamShieldEnabled ?? true,
            panicActive: session.panicActive ?? false,
            panicPrevious: session.panicPrevious ?? null,
            controlKey: session.controlKey,
            streamStats: session.streamStats ?? {},
            trustedUserIds: session.trustedUserIds ?? [],
            verificationLocks: session.verificationLocks ?? {},
            permanentBanHolds: session.permanentBanHolds ?? {},
            remoteInstallKey: session.remoteInstallKey,
            remoteLastEventAt: session.remoteLastEventAt,
            remoteBackendRegistered: session.remoteBackendRegistered,
            remoteBackendError: session.remoteBackendError,
        }));
    }
    async persistSessions() {
        await atomicWrite(`${this.dataDir}/sessions.enc.json`, this.encrypt(this.serializeSessions()));
    }
    createSession(input) {
        const existingId = this.byBroadcaster.get(input.broadcasterId);
        const existing = existingId ? this.sessions.get(existingId) : undefined;
        if (existing) {
            this.removeSession(existingId);
            // Reauthorization replaces login credentials, while the same channel's
            // active restrictions and protection settings remain owned by this PC.
            // Retaining the object also keeps in-flight moderation on the same state.
            const isLive = existing.isLive;
            Object.assign(existing, input, {
                id: randomUUID(),
                csrfToken: randomBytes(24).toString("base64url"),
                isLive,
                remoteBackendRegistered: false,
                remoteBackendError: "",
            });
            existing.verificationLocks ||= {};
            existing.permanentBanHolds ||= {};
            this.sessions.set(existing.id, existing);
            this.byBroadcaster.set(existing.broadcasterId, existing.id);
            this.overlayToSession.set(existing.overlayKey, existing.id);
            return existing;
        }
        const detector = new StreamShieldDetector(this.baselines.get(input.broadcasterId));
        const session = {
            ...input,
            id: randomUUID(),
            overlayKey: randomBytes(24).toString("base64url"),
            csrfToken: randomBytes(24).toString("base64url"),
            createdAt: Date.now(),
            detector,
            mode: "assist",
            shieldActive: false,
            autoTimeoutEnabled: false,
            followShieldEnabled: true,
            chatRaidShieldEnabled: true,
            linkScamShieldEnabled: true,
            panicActive: false,
            panicPrevious: null,
            controlKey: randomBytes(24).toString("base64url"),
            streamStats: { startedAt: Date.now(), followsSeen: 0, chatsSeen: 0, maxThreatScore: 0, maxFollows60s: 0, maxChats60s: 0, maxViewerDelta30s: 0, maxViewers: 0, followSpikes: 0, chatRaidMessagesDeleted: 0, chatRaidTimeouts: 0, verificationRequests: 0, permanentBans: 0, networkAutoBans: 0, scamMessagesDeleted: 0, panicActivations: 0, followSpikeActive: false },
            trustedUserIds: [],
            verificationLocks: {},
            permanentBanHolds: {},
            remoteInstallKey: randomBytes(32).toString("base64url"),
            remoteBackendRegistered: false,
            remoteBackendError: "",
            lastAssessment: detector.assess(),
            previousScore: 0,
            recentChat: [],
            recentActions: [],
            recentEvents: [],
        };
        this.sessions.set(session.id, session);
        this.byBroadcaster.set(session.broadcasterId, session.id);
        this.overlayToSession.set(session.overlayKey, session.id);
        return session;
    }
    removeSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session)
            return;
        this.sessions.delete(session.id);
        this.byBroadcaster.delete(session.broadcasterId);
        this.overlayToSession.delete(session.overlayKey);
    }
    async disconnectSession(session) {
        this.removeSession(session.id);
        await this.persistSessions();
    }
    async deleteChannelData(session) {
        const id = session.broadcasterId;
        this.removeSession(session.id);
        this.baselines.delete(id);
        this.incidents = this.incidents.filter(x => x.channelId !== id);
        await this.persistSessions();
        await this.persistBaselines();
        await this.rewriteIncidents();
    }
    async saveSession(session) {
        if (this.sessions.has(session.id))
            await this.persistSessions();
    }
    async saveBaseline(session) {
        this.baselines.set(session.broadcasterId, session.detector.getBaseline());
        await this.persistBaselines();
    }
    async persistBaselines() {
        const obj = Object.fromEntries([...this.baselines.entries()].map(([id, baseline]) => [String(id), baseline]));
        await atomicWrite(`${this.dataDir}/baselines.enc.json`, this.encrypt(obj));
    }
    getByBroadcaster(id) {
        const sessionId = this.byBroadcaster.get(id);
        return sessionId ? this.sessions.get(sessionId) : undefined;
    }
    getByOverlay(key) {
        const id = this.overlayToSession.get(key);
        return id ? this.sessions.get(id) : undefined;
    }
    async addIncident(session, assessment, note) {
        const incident = {
            id: randomUUID(),
            channelId: session.broadcasterId,
            channelSlug: session.slug,
            platform: "kick",
            startedAt: new Date(assessment.assessedAt).toISOString(),
            lastObservedAt: new Date(assessment.assessedAt).toISOString(),
            score: assessment.score,
            peakScore: assessment.score,
            level: assessment.level,
            reasons: assessment.reasons,
            metrics: assessment.metrics,
            protectionMode: session.mode,
            note,
            actions: [],
        };
        this.incidents.unshift(incident);
        await this.rewriteIncidents();
        return incident;
    }
    async updateIncident(id, assessment) {
        const incident = this.incidents.find(x => x.id === id);
        if (!incident)
            return;
        incident.lastObservedAt = new Date(assessment.assessedAt).toISOString();
        incident.score = assessment.score;
        incident.peakScore = Math.max(incident.peakScore ?? incident.score, assessment.score);
        incident.level = assessment.level;
        incident.reasons = assessment.reasons;
        incident.metrics = assessment.metrics;
        await this.rewriteIncidents();
    }
    async addIncidentAction(id, action) {
        if (!id)
            return;
        const incident = this.incidents.find(x => x.id === id);
        if (!incident)
            return;
        incident.actions ??= [];
        incident.actions.push({ at: new Date(action.at).toISOString(), action: action.action, ok: action.ok, detail: action.detail, ...(action.meta ? { meta: action.meta } : {}) });
        await this.rewriteIncidents();
    }
    async addStreamReport(session, report) {
        const item = {
            id: randomUUID(),
            reportType: "stream_summary",
            channelId: session.broadcasterId,
            channelSlug: session.slug,
            platform: "kick",
            startedAt: report.startedAt,
            lastObservedAt: report.endedAt,
            score: report.peakThreatScore,
            peakScore: report.peakThreatScore,
            level: report.needsReview ? "review_recommended" : "no_major_incident_detected",
            reasons: report.reasons ?? [],
            metrics: report.metrics,
            protectionMode: session.mode,
            note: "End-of-stream protection summary",
            actions: report.actions ?? [],
            streamStats: report.streamStats,
            incidentCount: report.incidentCount ?? 0,
            summaryText: report.summaryText ?? "",
            evidenceSeal: report.evidenceSeal ?? "",
            eventChainId: report.eventChainId ?? "",
            evidenceAlgorithm: report.evidenceAlgorithm ?? "SHA-256",
            evidenceVersion: report.evidenceVersion ?? 1,
            generatedAt: report.generatedAt ?? new Date().toISOString(),
            autoGenerated: Boolean(report.autoGenerated),
        };
        this.incidents.unshift(item);
        await this.rewriteIncidents();
        return item;
    }
    async rewriteIncidents() {
        await atomicWrite(`${this.dataDir}/incidents.enc.json`, this.encrypt(this.incidents));
    }
    listIncidents(channelId) {
        return this.incidents.filter(x => channelId === undefined || x.channelId === channelId).slice(0, 100);
    }
    getIncident(id) {
        return this.incidents.find(x => x.id === id);
    }
    hasWebhookSeen(id) {
        return this.seenWebhookIds.has(id);
    }
    markWebhookSeen(id, at = Date.now()) {
        this.seenWebhookIds.set(id, at);
        this.webhookDirty = true;
    }
    cleanupWebhookIds(now = Date.now()) {
        const cutoff = now - 48 * 60 * 60_000;
        for (const [id, at] of this.seenWebhookIds)
            if (at < cutoff)
                this.seenWebhookIds.delete(id);
        if (this.seenWebhookIds.size > 10_000) {
            const keep = [...this.seenWebhookIds.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10_000);
            this.seenWebhookIds = new Map(keep);
        }
        this.webhookDirty = true;
    }
    async flushWebhookIds() {
        if (!this.webhookDirty)
            return;
        this.webhookDirty = false;
        const obj = Object.fromEntries(this.seenWebhookIds);
        await atomicWrite(`${this.dataDir}/webhook-ids.enc.json`, this.encrypt(obj));
    }
}

const clamp = (n, min, max) => Math.min(max, Math.max(min, n));
const normalizedText = (s) => s.toLowerCase().replace(/\s+/g, " ").trim();
function levelFor(score) {
    if (score >= 81)
        return "active_attack";
    if (score >= 61)
        return "likely_bot";
    if (score >= 41)
        return "suspicious";
    if (score >= 21)
        return "elevated";
    return "normal";
}
function coefficientOfVariation(times) {
    if (times.length < 4)
        return 1;
    const intervals = times.slice(1).map((t, i) => t - times[i]);
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean <= 0)
        return 1;
    const variance = intervals.reduce((sum, x) => sum + Math.pow(x - mean, 2), 0) / intervals.length;
    return Math.sqrt(variance) / mean;
}
export class StreamShieldDetector {
    viewers = [];
    follows = [];
    chats = [];
    trustedUntil = 0;
    baseline;
    lastBaselineLearnAt = 0;
    constructor(baseline) {
        this.baseline = {
            avgViewers: baseline?.avgViewers ?? 25,
            peakViewers: baseline?.peakViewers ?? 60,
            followsPerMinute: baseline?.followsPerMinute ?? 0.5,
            chatsPerMinute: baseline?.chatsPerMinute ?? 4,
        };
    }
    setBaseline(next) {
        this.baseline = { ...this.baseline, ...next };
    }
    getBaseline() {
        return { ...this.baseline };
    }
    markTrustedEvent(minutes = 10, now = Date.now()) {
        this.trustedUntil = Math.max(this.trustedUntil, now + minutes * 60_000);
    }
    learnFromCalmActivity(assessment, now = Date.now()) {
        if (assessment.score > 20 || now < this.trustedUntil || now - this.lastBaselineLearnAt < 5 * 60_000)
            return false;
        this.lastBaselineLearnAt = now;
        const m = assessment.metrics;
        const nextAvg = this.baseline.avgViewers * 0.92 + m.viewers * 0.08;
        const nextPeak = Math.max(this.baseline.peakViewers * 0.995, m.viewers);
        const nextFollows = this.baseline.followsPerMinute * 0.90 + m.follows60s * 0.10;
        const nextChats = this.baseline.chatsPerMinute * 0.90 + m.chats60s * 0.10;
        this.baseline = {
            avgViewers: Number(nextAvg.toFixed(2)),
            peakViewers: Number(nextPeak.toFixed(2)),
            followsPerMinute: Number(nextFollows.toFixed(3)),
            chatsPerMinute: Number(nextChats.toFixed(3)),
        };
        return true;
    }
    observeViewer(count, at = Date.now()) {
        this.viewers.push({ at, count: Math.max(0, Math.round(count)) });
        this.trim(at);
    }
    observeFollow(userId, at = Date.now()) {
        this.follows.push({ at, userId });
        this.trim(at);
    }
    observeChat(content, userId, messageId, at = Date.now()) {
        this.chats.push({ at, content, userId, messageId });
        this.trim(at);
    }
    recentExactChatCount(content, seconds = 60, now = Date.now()) {
        const text = normalizedText(content);
        if (!text)
            return 0;
        const cutoff = now - seconds * 1000;
        return this.chats.filter(x => x.at >= cutoff && normalizedText(x.content) === text).length;
    }
    recentUserExactChatCount(userId, content, seconds = 20, now = Date.now()) {
        const text = normalizedText(content);
        if (!text || !Number.isFinite(userId))
            return 0;
        const cutoff = now - seconds * 1000;
        return this.chats.filter(x => x.at >= cutoff && x.userId === userId && normalizedText(x.content) === text).length;
    }
    trim(now) {
        const oldest = now - 15 * 60_000;
        this.viewers = this.viewers.filter(x => x.at >= oldest);
        this.follows = this.follows.filter(x => x.at >= oldest);
        this.chats = this.chats.filter(x => x.at >= oldest);
    }
    assess(now = Date.now()) {
        this.trim(now);
        const reasons = [];
        const v30 = this.viewers.filter(x => x.at >= now - 30_000);
        const currentViewers = this.viewers.at(-1)?.count ?? 0;
        const viewerDelta30s = v30.length > 1 ? currentViewers - v30[0].count : 0;
        const f60 = this.follows.filter(x => x.at >= now - 60_000);
        const c60 = this.chats.filter(x => x.at >= now - 60_000);
        const uniqueChatters = new Set(c60.map(x => x.userId).filter((x) => typeof x === "number")).size;
        const normalized = c60.map(x => normalizedText(x.content)).filter(Boolean);
        const uniqueMessages = new Set(normalized).size;
        const duplicateRatio = normalized.length ? 1 - uniqueMessages / normalized.length : 0;
        const base = this.baseline;
        const add = (code, label, points, detail) => reasons.push({ code, label, points, detail });
        const majorViewerBurst = viewerDelta30s >= Math.max(100, base.avgViewers * 2) && currentViewers >= Math.max(base.peakViewers * 2, base.avgViewers * 4);
        const moderateViewerBurst = viewerDelta30s >= Math.max(30, base.avgViewers * 0.75);
        if (majorViewerBurst)
            add("viewer_burst_major", "Abnormal viewer acceleration", 40, `+${viewerDelta30s} viewers in ~30s vs ${Math.round(base.avgViewers)} average`);
        else if (moderateViewerBurst)
            add("viewer_burst", "Elevated viewer acceleration", 20, `+${viewerDelta30s} viewers in ~30s`);
        const extremeFollowBurst = f60.length >= Math.max(100, Math.ceil(base.followsPerMinute * 20));
        const majorFollowBurst = f60.length >= Math.max(20, Math.ceil(base.followsPerMinute * 8));
        const moderateFollowBurst = f60.length >= Math.max(8, Math.ceil(base.followsPerMinute * 4));
        if (extremeFollowBurst)
            add("follow_burst_extreme", "Extreme follow velocity", 50, `${f60.length} follows in 60s`);
        else if (majorFollowBurst)
            add("follow_burst_major", "Abnormal follow velocity", 25, `${f60.length} follows in 60s`);
        else if (moderateFollowBurst)
            add("follow_burst", "Elevated follow velocity", 15, `${f60.length} follows in 60s`);
        if (c60.length >= 12 && duplicateRatio >= 0.65)
            add("duplicate_chat", "Highly repetitive chat", 20, `${Math.round(duplicateRatio * 100)}% duplicate/near-identical normalized messages`);
        if (c60.length >= 20 && uniqueChatters / c60.length <= 0.25)
            add("low_chatter_diversity", "Low chatter diversity", 15, `${uniqueChatters} unique chatters across ${c60.length} messages`);
        if (c60.length >= Math.max(30, Math.ceil(base.chatsPerMinute * 8)) && duplicateRatio >= 0.80)
            add("extreme_chat_wave", "Extreme repetitive chat wave", 45, `${c60.length} messages in 60s at ${Math.round(duplicateRatio * 100)}% repetition`);
        if (c60.length >= 20 && coefficientOfVariation(c60.map(x => x.at)) < 0.15)
            add("regular_chat_cadence", "Machine-like chat timing", 15, "Chat message intervals are unusually regular");
        if (majorViewerBurst && c60.length <= Math.max(2, viewerDelta30s * 0.01)) {
            add("engagement_mismatch", "Viewer/engagement mismatch", 30, `Large viewer increase with only ${c60.length} chat messages in the last minute`);
        }
        if (f60.length >= 8 && coefficientOfVariation(f60.map(x => x.at)) < 0.20) {
            add("regular_follow_cadence", "Machine-like follow timing", 10, "Follow intervals are unusually regular");
        }
        if (majorViewerBurst && c60.length >= Math.max(10, viewerDelta30s * 0.08)) {
            add("organic_chat_offset", "Organic engagement signal", -15, "Chat rose proportionally with viewer growth");
        }
        if (majorViewerBurst && f60.length >= Math.max(5, viewerDelta30s * 0.05)) {
            add("organic_follow_offset", "Organic follow signal", -10, "Follows rose proportionally with viewer growth");
        }
        if (now < this.trustedUntil)
            add("trusted_event", "Streamer marked expected/organic surge", -50, "Trusted-event window is active");
        const score = clamp(Math.round(reasons.reduce((sum, r) => sum + r.points, 0)), 0, 100);
        return {
            score,
            level: levelFor(score),
            reasons,
            assessedAt: now,
            metrics: {
                viewers: currentViewers,
                viewerDelta30s,
                follows60s: f60.length,
                chats60s: c60.length,
                uniqueChatters60s: uniqueChatters,
                duplicateRatio60s: Number(duplicateRatio.toFixed(3)),
            },
        };
    }
}

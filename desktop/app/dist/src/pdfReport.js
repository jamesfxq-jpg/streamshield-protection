function ascii(input) {
    return input
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[\u201c\u201d]/g, '"')
        .replace(/[\u2013\u2014]/g, "-")
        .replace(/\u2192/g, "->")
        .replace(/[^\x20-\x7E]/g, "?");
}
function wrap(text, width = 88) {
    const clean = ascii(text).replace(/\s+/g, " ").trim();
    if (!clean)
        return [""];
    const words = clean.split(" ");
    const lines = [];
    let line = "";
    for (const word of words) {
        if (!line) {
            line = word;
            continue;
        }
        if ((line + " " + word).length <= width)
            line += " " + word;
        else {
            lines.push(line);
            line = word;
        }
    }
    if (line)
        lines.push(line);
    return lines;
}
function pdfEscape(line) {
    return line.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
function incidentLines(incident) {
    const lines = [];
    const add = (text = "") => lines.push(...wrap(text));
    if (incident.reportType === "stream_summary") {
        const st = incident.streamStats || {};
        add("STREAMSHIELD END-OF-STREAM PROTECTION REPORT");
        add("KICK support-ready defensive evidence summary.");
        add();
        add(`Platform: Kick`);
        add(`Channel: ${incident.channelSlug}`);
        add(`Report ID: ${incident.id}`);
        add(`Stream window: ${incident.startedAt} to ${incident.lastObservedAt}`);
        if (incident.evidenceSeal) {
            add(`Evidence integrity: ${incident.evidenceAlgorithm || "SHA-256"}`);
            add(`Evidence seal: ${incident.evidenceSeal}`);
        }
        if (incident.eventChainId)
            add(`Event-chain ID: ${incident.eventChainId}`);
        add(`Peak threat score: ${incident.peakScore ?? incident.score}/100`);
        add(`Recorded incidents: ${incident.incidentCount || 0}`);
        add();
        add("STREAM ACTIVITY SUMMARY");
        add(`Peak viewers: ${st.maxViewers || 0}`);
        add(`Largest viewer change / 30s: ${(st.maxViewerDelta30s || 0) >= 0 ? "+" : ""}${st.maxViewerDelta30s || 0}`);
        add(`Follows observed: ${st.followsSeen || 0}`);
        add(`Peak follow rate: ${st.maxFollows60s || 0}/minute`);
        add(`Suspicious follow spikes: ${st.followSpikes || 0}`);
        add(`Chat messages observed: ${st.chatsSeen || 0}`);
        add(`Peak chat rate: ${st.maxChats60s || 0}/minute`);
        add();
        add("DEFENSIVE ACTIONS");
        add(`Chat Raid Shield deletions: ${st.chatRaidMessagesDeleted || 0}`);
        add(`Automatic spam timeouts: ${st.chatRaidTimeouts || 0}`);
        add(`Targeted verification requests: ${st.verificationRequests || 0}`);
        add(`Permanent KICK bans: ${st.permanentBans || 0}`);
        add(`Exact-network evasion auto-bans: ${st.networkAutoBans || 0}`);
        if ((incident.reasons || []).length) {
            add();
            add("NOTABLE SIGNALS");
            for (const reason of incident.reasons || []) {
                add(`${reason.label}`);
                add(`  ${reason.detail}`);
            }
        }
        add();
        add("COPY FOR KICK SUPPORT");
        for (const line of String(incident.summaryText || "").split(/\r?\n/)) add(line);
        add();
        add("INTERPRETATION");
        add("StreamShield did not generate or request the suspicious engagement described in this report. The report documents defensive detection and moderation and should be treated as supporting evidence only. KICK platform logs remain the authoritative source for enforcement decisions.");
        return lines;
    }
    add("STREAMSHIELD INCIDENT REPORT");
    add("Supporting evidence - not proof of who initiated activity.");
    add();
    add(`Platform: Kick`);
    add(`Channel: ${incident.channelSlug}`);
    add(`Incident ID: ${incident.id}`);
    add(`Started: ${incident.startedAt}`);
    if (incident.lastObservedAt)
        add(`Last observed: ${incident.lastObservedAt}`);
    add(`Peak threat score: ${incident.peakScore ?? incident.score}/100`);
    add(`Latest classification: ${incident.level}`);
    add(`Protection mode: ${incident.protectionMode}`);
    add();
    add("OBSERVED METRICS");
    add(`Viewers: ${incident.metrics.viewers}`);
    add(`Viewer change / 30s: ${incident.metrics.viewerDelta30s >= 0 ? "+" : ""}${incident.metrics.viewerDelta30s}`);
    add(`Follows / 60s: ${incident.metrics.follows60s}`);
    add(`Chat messages / 60s: ${incident.metrics.chats60s}`);
    add(`Unique chatters / 60s: ${incident.metrics.uniqueChatters60s}`);
    add(`Duplicate chat ratio: ${Math.round(incident.metrics.duplicateRatio60s * 100)}%`);
    add();
    add("DETECTION REASONS");
    if (!incident.reasons.length)
        add("No abnormal reason rows were recorded.");
    for (const reason of incident.reasons) {
        add(`${reason.points >= 0 ? "+" : ""}${reason.points} - ${reason.label}`);
        add(`  ${reason.detail}`);
    }
    add();
    add("DEFENSIVE ACTIONS");
    if (!(incident.actions || []).length)
        add("No automated or manual StreamShield actions were recorded on this incident.");
    for (const action of incident.actions || []) {
        add(`${action.at} - ${action.action} - ${action.ok ? "successful" : "failed"}${action.detail ? ` - ${action.detail}` : ""}`);
    }
    add();
    add("INTERPRETATION");
    add("StreamShield recorded a pattern that differed from the channel's learned or seeded baseline and preserved the streamer's defensive response. This report is supporting evidence only and does not identify who initiated the activity.");
    return lines;
}
export function buildIncidentPdf(incident) {
    const allLines = incidentLines(incident);
    const maxLinesPerPage = 44;
    const pages = [];
    for (let i = 0; i < allLines.length; i += maxLinesPerPage)
        pages.push(allLines.slice(i, i + maxLinesPerPage));
    if (!pages.length)
        pages.push(["STREAMSHIELD INCIDENT REPORT"]);
    const objects = new Map();
    const pageObjectIds = [];
    const contentObjectIds = [];
    let nextId = 4;
    for (let i = 0; i < pages.length; i++) {
        pageObjectIds.push(nextId++);
        contentObjectIds.push(nextId++);
    }
    objects.set(1, Buffer.from(`<< /Type /Catalog /Pages 2 0 R >>`, "ascii"));
    objects.set(2, Buffer.from(`<< /Type /Pages /Kids [${pageObjectIds.map(id => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`, "ascii"));
    objects.set(3, Buffer.from(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`, "ascii"));
    pages.forEach((lines, index) => {
        const pageId = pageObjectIds[index];
        const contentId = contentObjectIds[index];
        objects.set(pageId, Buffer.from(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`, "ascii"));
        const commands = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"];
        lines.forEach((line, i) => {
            if (i > 0)
                commands.push("T*");
            commands.push(`(${pdfEscape(line)}) Tj`);
        });
        commands.push("ET");
        const stream = Buffer.from(commands.join("\n") + "\n", "ascii");
        objects.set(contentId, Buffer.concat([
            Buffer.from(`<< /Length ${stream.length} >>\nstream\n`, "ascii"),
            stream,
            Buffer.from("endstream", "ascii"),
        ]));
    });
    const maxId = Math.max(...objects.keys());
    const chunks = [Buffer.from("%PDF-1.4\n%StreamShield\n", "ascii")];
    const offsets = new Array(maxId + 1).fill(0);
    let offset = chunks[0].length;
    for (let id = 1; id <= maxId; id++) {
        const body = objects.get(id);
        if (!body)
            throw new Error(`Missing PDF object ${id}`);
        offsets[id] = offset;
        const obj = Buffer.concat([Buffer.from(`${id} 0 obj\n`, "ascii"), body, Buffer.from("\nendobj\n", "ascii")]);
        chunks.push(obj);
        offset += obj.length;
    }
    const xrefOffset = offset;
    const xrefLines = [`xref`, `0 ${maxId + 1}`, `0000000000 65535 f `];
    for (let id = 1; id <= maxId; id++)
        xrefLines.push(`${String(offsets[id]).padStart(10, "0")} 00000 n `);
    const trailer = `${xrefLines.join("\n")}\ntrailer\n<< /Size ${maxId + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    chunks.push(Buffer.from(trailer, "ascii"));
    return Buffer.concat(chunks);
}

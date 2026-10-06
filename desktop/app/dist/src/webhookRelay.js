import http from "node:http";
const relayPort = Number(process.env.STREAMSHIELD_WEBHOOK_RELAY_PORT || 8788);
const target = process.env.STREAMSHIELD_WEBHOOK_TARGET || "http://127.0.0.1:8787/webhooks/kick";
const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url || "/", `http://127.0.0.1:${relayPort}`);
        if (req.method === "GET" && url.pathname === "/health") {
            res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
            return res.end(JSON.stringify({ ok: true, relay: "kick-webhook-only" }));
        }
        if (req.method !== "POST" || url.pathname !== "/webhooks/kick") {
            res.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
            return res.end("Not found");
        }
        const chunks = [];
        let total = 0;
        for await (const c of req) {
            const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
            total += b.length;
            if (total > 512 * 1024) {
                res.writeHead(413, { "content-type": "text/plain" });
                return res.end("Payload too large");
            }
            chunks.push(b);
        }
        const raw = Buffer.concat(chunks);
        const headers = { "content-type": String(req.headers["content-type"] || "application/json") };
        for (const [k, v] of Object.entries(req.headers)) {
            if (k.startsWith("kick-event-") && v !== undefined)
                headers[k] = Array.isArray(v) ? v.join(",") : String(v);
        }
        const upstream = await fetch(target, { method: "POST", headers, body: raw });
        const body = await upstream.arrayBuffer();
        res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") || "text/plain; charset=utf-8", "cache-control": "no-store" });
        res.end(Buffer.from(body));
    }
    catch (error) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        res.end(`Webhook relay error: ${error.message}`);
    }
});
server.listen(relayPort, "127.0.0.1", () => {
    console.log(`StreamShield Kick webhook relay listening on http://127.0.0.1:${relayPort}`);
});

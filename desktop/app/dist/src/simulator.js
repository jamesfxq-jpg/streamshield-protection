import { StreamShieldDetector } from "./detector.js";
function result(name, detector, now) {
    const a = detector.assess(now);
    console.log(`${name.padEnd(20)} score=${String(a.score).padStart(3)} level=${a.level}`);
    for (const r of a.reasons)
        console.log(`  ${r.points >= 0 ? "+" : ""}${r.points} ${r.label}: ${r.detail}`);
}
const base = { avgViewers: 35, peakViewers: 70, followsPerMinute: 0.5, chatsPerMinute: 6 };
const t = Date.now();
{
    const d = new StreamShieldDetector(base);
    d.observeViewer(33, t - 30_000);
    d.observeViewer(38, t);
    for (let i = 0; i < 6; i++)
        d.observeChat(`normal message ${i}`, 100 + i, `m${i}`, t - 50_000 + i * 7000);
    result("normal stream", d, t);
}
{
    const d = new StreamShieldDetector(base);
    d.markTrustedEvent(10, t);
    d.observeViewer(35, t - 30_000);
    d.observeViewer(700, t);
    for (let i = 0; i < 80; i++)
        d.observeChat(`hype ${i}`, 1000 + i, `r${i}`, t - 55_000 + i * 600);
    for (let i = 0; i < 35; i++)
        d.observeFollow(2000 + i, t - 55_000 + i * 1500);
    result("legitimate raid", d, t);
}
{
    const d = new StreamShieldDetector(base);
    d.observeViewer(35, t - 25_000);
    d.observeViewer(1800, t);
    d.observeChat("what happened?", 1, "v1", t - 3000);
    result("viewbot spike", d, t);
}
{
    const d = new StreamShieldDetector(base);
    for (let i = 0; i < 45; i++)
        d.observeFollow(5000 + i, t - 58_000 + i * 1200);
    result("followbot burst", d, t);
}
{
    const d = new StreamShieldDetector(base);
    d.observeViewer(40, t - 30_000);
    d.observeViewer(55, t);
    for (let i = 0; i < 50; i++)
        d.observeChat("FREE FOLLOWERS HERE", 9000 + (i % 4), `c${i}`, t - 59_000 + i * 1100);
    result("chat spam", d, t);
}

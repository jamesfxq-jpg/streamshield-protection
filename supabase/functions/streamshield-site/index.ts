const ORIGIN = "https://streamshield-protection-public.vercel.app";
const VERSION = "0.6.0-beta.11";
const SHA256 = "4819d3994490beb3eb75e0dfca9c236158e66b648a927de1efb2e0a5a6f9f36f";
const ZIP = `/releases/StreamShield-Protection-${VERSION}-Windows.zip`;

Deno.serve((req: Request) => {
  const headers: Record<string, string> = {
    "Cache-Control": "no-store, max-age=0",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { ...headers, Allow: "GET, HEAD" } });
  }
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const isDownload = path.endsWith("/download");
  if (isDownload) {
    const versions = url.searchParams.getAll("version");
    if (versions.length > 1 || (versions.length === 1 && versions[0] !== VERSION)) {
      return new Response(null, { status: 404, headers });
    }
    headers["X-StreamShield-Version"] = VERSION;
    headers["X-StreamShield-Sha256"] = SHA256;
  }
  const destination = isDownload ? ZIP
    : /\/privacy(?:\.html)?$/.test(path) ? "/privacy"
    : /\/terms(?:\.html)?$/.test(path) ? "/terms"
    : "/";
  return new Response(null, {
    status: 302,
    headers: { ...headers, Location: new URL(destination, ORIGIN).toString() },
  });
});

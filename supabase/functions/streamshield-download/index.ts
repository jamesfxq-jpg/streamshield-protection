const VERSION = "0.6.0-beta.12";
const SHA256 = "2e9d0e557cf2b37e6a27ff834b621b5ddb6857be4af000b0f12af47b2d6e1292";
const DOWNLOAD = `https://streamshield-protection-public.vercel.app/releases/StreamShield-Protection-${VERSION}-Windows.zip`;

Deno.serve((req: Request) => {
  const headers: Record<string, string> = {
    "Cache-Control": "no-store, max-age=0",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { ...headers, Allow: "GET, HEAD" } });
  }
  const versions = new URL(req.url).searchParams.getAll("version");
  if (versions.length > 1 || (versions.length === 1 && versions[0] !== VERSION)) {
    return new Response(null, { status: 404, headers });
  }
  return new Response(null, {
    status: 302,
    headers: {
      ...headers,
      Location: DOWNLOAD,
      "X-StreamShield-Version": VERSION,
      "X-StreamShield-Sha256": SHA256,
    },
  });
});

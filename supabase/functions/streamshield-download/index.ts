const VERSION = "0.6.0-beta.14";
// Preserve the previously advertised link as an alias to the current build.
const ACCEPTED_VERSIONS = new Set([VERSION, "0.6.0-beta.12"]);
const SHA256 = "936a482919ecd3147d828c7946fbc0ac449b91ae1d872de7d79804ef8cd673b0";
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
  if (versions.length > 1 || (versions.length === 1 && !ACCEPTED_VERSIONS.has(versions[0]))) {
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

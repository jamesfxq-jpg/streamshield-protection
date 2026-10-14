import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const version = '0.6.0-beta.14';
const digest = '936a482919ecd3147d828c7946fbc0ac449b91ae1d872de7d79804ef8cd673b0';
const origin = 'https://streamshield-protection-public.vercel.app';
const download = `${origin}/releases/StreamShield-Protection-${version}-Windows.zip`;
let checks = 0;
for (const slug of ['streamshield-site', 'streamshield-download']) {
  let handler;
  const source = readFileSync(new URL(`../supabase/functions/${slug}/index.ts`, import.meta.url), 'utf8')
    .replaceAll('req: Request', 'req').replaceAll('headers: Record<string, string>', 'headers');
  vm.runInNewContext(source, { Deno: { serve(fn) { handler = fn; } }, URL, Request, Response, Set });
  const base = `https://example.invalid/functions/v1/${slug}${slug === 'streamshield-site' ? '/download' : ''}`;
  for (const method of ['GET', 'HEAD']) {
    for (const suffix of ['', `?version=${version}`, '?version=0.6.0-beta.12']) {
      const response = await handler(new Request(base + suffix, { method }));
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), download);
      assert.equal(response.headers.get('x-streamshield-version'), version);
      assert.equal(response.headers.get('x-streamshield-sha256'), digest);
      assert.match(response.headers.get('cache-control'), /no-store/);
      assert.equal(await response.text(), '');
      checks++;
    }
  }
  for (const suffix of ['?version=', '?version=0.6.0-beta.99', '?version=https://evil.invalid', '?version=0.6.0-beta.14&version=0.6.0-beta.14']) {
    assert.equal((await handler(new Request(base + suffix))).status, 404);
    checks++;
  }
  assert.equal((await handler(new Request(base, { method: 'POST' }))).status, 405);
  checks++;
  if (slug === 'streamshield-site') {
    for (const path of ['', '/privacy', '/privacy.html', '/terms', '/terms.html']) {
      const response = await handler(new Request(`https://example.invalid/functions/v1/${slug}${path}`));
      assert.equal(response.headers.get('location'), origin + (path ? path.replace('.html', '') : '/'));
      checks++;
    }
  }
}
console.log(`PASS: ${checks} local download-redirect checks; no network requests or user sessions.`);

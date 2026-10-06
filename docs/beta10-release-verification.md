# Beta 10 release verification

Release date: 2026-10-06. Version: **0.6.0-beta.10**.

## Published artifact

- Public site: https://streamshield-protection-public.vercel.app/
- Windows ZIP: https://streamshield-protection-public.vercel.app/releases/StreamShield-Protection-0.6.0-beta.10-Windows.zip
- Bytes: **2,726,565**
- SHA-256: `7c982c9c47d616a8a25c6761e95c706f0b166a1da4cbf2bc563caeabd48f8358`
- The downloaded ZIP passed its integrity check, contains 24 distribution files, and reports the correct version in `app/package.json`.
- The package contains public runtime configuration and OBS branding. It contains no generated installation data or encryption keys.

## Automated app checks

The five scripts documented in the root README passed against the packaged desktop snapshot and backend source using Node.js 24.19.0. They exercise generated dashboard scripts, compact IP and verification controls, health and update states, local HTTP endpoints, authorization/CSRF guards, recovery, sealed reports/PDFs, and backend consent/cancellation logic. The moderation ordering suite passed **15/15** cases.

External KICK/cloud calls in the app tests used deterministic fixtures with a reject-all fallback. Test state was isolated from any real channel. The existing Windows installer runtime URL returned HTTP 200; its pinned SHA-256 matches the official Node.js 22.23.3 Windows x64 checksum.

## Production web and cloud checks

- Canonical home, legal pages, consent and result pages returned HTTP 200 and HTML content types. Styles, scripts, and all four branding PNGs returned their expected types.
- The canonical ZIP was downloaded and hashed independently; both legacy download routes were also followed and reached identical bytes.
- Existing Supabase home/privacy/terms/download links now redirect to the canonical website or ZIP with `Cache-Control: no-store, max-age=0`.
- The release feed retains a versioned Supabase-hosted download URL so older desktop update-banner hostname checks remain compatible. The website metadata uses the direct Vercel URL.
- The consent page returns `Referrer-Policy: strict-origin` in both its response header and HTML meta policy. Its CSP explicitly allows the first-party result destination and the fixed Supabase/KICK destinations.
- A real Chrome form submission using a nonexistent test request successfully navigated to the first-party result page with status 410. It did not create a verification request or reach KICK authorization.
- Direct HTTP checks rejected null/untrusted origins with status 400 informational redirects, returned status 410 for an inactive test request with the correct origin, and issued no device cookie on these paths.
- Unauthenticated event polling returned 401; an unsigned webhook returned 400. General network GET links redirected to the consent page without starting OAuth.
- The database migration was checked in a transaction using isolated test records, then rolled back. Only matching older requests were cancelled; newer requests and other users were preserved. A repeated cancellation changed zero rows.

## Deployment records

- Production Vercel deployment: `dpl_Hv3mNkqLSuyc5BPycECvxDLRxPwG`.
- Supabase backend function: version 10.
- Supabase legacy site redirect: version 11.
- Supabase legacy download redirect: version 2.
- Permanent-ban cancellation migration: `20261006005711_cancel_verification_on_permanent_ban.sql`.

## Remaining live validation

The Windows installer was not executed in a Windows session. No real KICK account was connected, no real viewer completed OAuth verification, and no live channel moderation was performed in this release check. Validate installation, signed live events, a controlled verification request, clean restoration, permanent-ban preservation, manual recovery, and the stream report on an authorized test channel.

KICK's unban API cannot conditionally remove only one earlier timeout. A separate moderation decision whose webhook has not yet arrived can race an already-started unlock. StreamShield serializes its own operations, preserves observed permanent bans, and records conflicts requiring review; moderators must still inspect KICK state after concurrent external actions.

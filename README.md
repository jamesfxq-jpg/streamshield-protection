# StreamShield Protection

**0.6.0-beta.12** — a Windows desktop application for monitoring and moderating a connected KICK channel, with a public download site and a cloud OAuth/webhook service.

Public website: [streamshield-protection-public.vercel.app](https://streamshield-protection-public.vercel.app)

## Install and start on Windows

1. Download the Windows ZIP from the public website.
2. Right-click the ZIP and choose **Extract All**.
3. Open the extracted folder and double-click **Install StreamShield.cmd**. The installer downloads the pinned official Node.js runtime, checks its SHA-256 checksum, installs the application and OBS branding assets, and creates a desktop launcher.
4. At `http://localhost:8787`, select **Connect KICK** and review the permissions shown by KICK.
5. Run **Pre-Stream Protection Check** before going live. Resolve reported connection or relay problems; the app waits for a signed KICK event before reporting full protection readiness.

For later sessions, open the **StreamShield Protection** desktop launcher. **Compact Control** opens a smaller moderation window. The included `Streamer Branding` folder contains optional OBS graphics and setup instructions.

To update an existing installation, stop StreamShield, extract the new ZIP, and run its installer. It replaces program files while retaining the existing application data directory. Reopen the application and run the pre-stream check again. See [desktop/README.txt](desktop/README.txt) for the full release notes and Windows instructions.

## Features and limits

- **Follow Shield** records suspicious follow bursts for review. **Chat Raid Shield** and **Link / Scam Shield** can delete qualifying spam using the connected channel's moderation authorization.
- **Compact Control** provides recent chat, verification requests, blocked verified networks, account moderation, offender case files, supported recovery actions, and a one-click Moderator Guide. Targeted verification now automatically replies to the selected viewer in KICK chat with the @username message plus the one-time link; clipboard fallback is used if the post fails.
- **Stream reports** collect local protection events and offer PDF export, a summary, and an evidence integrity seal. A matching seal checks report integrity; it does not identify an attacker or independently validate the events.
- **Recovery Center** can reverse supported recent actions. Removing a StreamShield network block with **UN-IP BAN** and removing a KICK account ban are separate actions.

The channel connection requests account/channel reading, event subscriptions, chat sending (`chat:write`), account moderation, and chat-message moderation permissions. Automatic user timeouts are a separate opt-in. Optional Network Protection and exact-network automatic bans are also separate settings; review them before enabling them. A dedicated moderator account, if configured, is optional and does not replace OAuth authorization.

Viewer verification requires an explicit consent step before KICK authorization and optional network/browser-token recording. KICK does not supply viewer IP addresses to StreamShield. During verification, the connection address is processed transiently to create a keyed one-way network identifier and then discarded; full viewer IP addresses are not stored or shown. Targeted verification may also use a random first-party browser token. Shared or reassigned IP addresses and browser-token matches are risk signals, not proof that two accounts belong to the same person. Browser tokens are not hardware identifiers and can be reset by clearing site data or changing browsers.

StreamShield cannot stop someone from sending fake follows to KICK's servers. Its follow protection detects and documents suspicious activity. It does not create viewers, followers, messages, or other artificial engagement. See the [privacy policy](privacy.html) and [terms](terms.html) for data handling and use conditions.

### Beta 10 reliability work

This version restores dashboard initialization and compact verification/IP controls, preserves channel settings and moderation holds across reconnects, exposes relay failures in readiness checks, and orders moderation operations for the same user. Automatic verification release requires an owned local restriction, recent healthy relay polling, a received signed event, and a fresh cloud verification result. Observed permanent bans supersede earlier verification requests; failed verification setup does not impose a new timeout.

KICK's unban endpoint cannot remove only a specific earlier timeout. A separate moderator action performed directly on KICK can still race an automatic unlock already in progress before its webhook arrives. Check the channel's current moderation state after concurrent actions.

## Repository layout

| Path | Contents |
| --- | --- |
| `index.html`, `privacy.html`, `terms.html` | Public landing page and policies. |
| `verify.html`, `verification-result.html` | Hosted viewer consent and informational result pages. |
| `assets/` | Website styles, verification scripts, and downloadable branding graphics. |
| `vercel.json` | Static hosting paths and response security/cache headers. |
| `desktop/` | Windows launchers, installer, instructions, and OBS branding assets. |
| `desktop/app/dist/src/` | Runnable desktop JavaScript: HTTP server/UI, KICK integration, detection, encrypted local state, reports, relay, diagnostics, and simulation. |
| `desktop/app/package.json` | Desktop runtime version and package commands. |
| `supabase/functions/` | Cloud backend TypeScript/Deno configuration and legacy site/download redirects. |
| `supabase/migrations/`, `supabase/operations/` | Incremental permanent-ban cancellation SQL and guarded release-publication SQL. |
| `tools/package_release.py` | Deterministic ZIP packaging and public metadata/checksum generation. |
| `docs/beta10-release-verification.md` | Original release, deployment, and verification evidence. |
| `docs/beta10-windows-validation.md` | Successful Windows installation follow-up and remaining live-channel acceptance. |
| `tests/` | Isolated regression scripts, Windows smoke/diagnostic scripts, and supporting fixtures. |
| `.github/workflows/windows-beta-smoke.yml` | Repeatable published-release installation check on Windows. |
| `releases/`, `release.json` | Windows release ZIP/checksum and public release metadata. |
| `release/beta9/`, `release_parts/beta9/` | Retained historical beta 9 release fragments. |

The desktop snapshot contains runnable JavaScript, but not the original desktop TypeScript project or its `tsconfig.json`/compiled unit-test tree. The package's inherited `build` and `test` commands therefore are not the verification entry points for this checkout. The SQL here is an incremental change to an existing backend, not a complete database bootstrap.

## Local development and regression checks

The regression commands below passed on Linux with **Node.js 22.23.3 and 24.21.0**. The original release check also used 24.19.0. The backend consent test uses Node's TypeScript-stripping API. The desktop runtime itself declares Node.js 20 or newer, and the Windows installer pins Node.js 22.23.3; this does not establish test compatibility with every older Node release.

To start the desktop HTTP application from source:

```sh
cd desktop/app
node dist/src/server.js
```

This creates local application data and, by default, uses the configured StreamShield cloud service. To inspect synthetic detection scenarios without connecting a KICK channel, run `node dist/src/simulator.js` from the same directory.

Run the committed regression scripts **from the repository root**:

```sh
node tests/compact-fixtures.mjs
node tests/health-ui-fixtures.mjs
node tests/runtime.mjs
node tests/moderation-regression.mjs
node tests/backend-consent.test.mjs
```

| Script | Coverage |
| --- | --- |
| `compact-fixtures.mjs` | Compact verified-network controls and verification release request IDs. |
| `health-ui-fixtures.mjs` | Main/compact health states, recovery controls, and allowed update URLs. |
| `runtime.mjs` | Local HTTP startup, authorization/CSRF guards, recovery, reports, PDF output, and network-history responses with fixture upstream services. |
| `moderation-regression.mjs` | Moderation ordering, permanent-ban preservation, verification ownership, reconnect state, and readiness failures. |
| `backend-consent.test.mjs` | Consent/origin checks, browser-token cookie handling, cancelled verification callbacks, ban-event cancellation, and backend authorization gates. |

Supporting files in `tests/fixtures/` include the historical beta 9 UI for before/after assertions and an upstream-response preload. The runtime script uses an OS temporary directory for application state and local port `18897`; that port must be available.

All five scripts passed on both runtime versions in the follow-up; the moderation suite passed all 15 cases. These scripts use isolated state and mocked KICK/cloud responses. UI fixtures use a simulated document environment; runtime checks exercise a local Node server. A separate original Chrome test verified the deployed consent form's inactive-request result navigation. These checks do not establish that a complete viewer OAuth round trip or a live KICK channel workflow succeeds. See [the original release record](docs/beta10-release-verification.md) and [the latest Windows validation follow-up](docs/beta10-windows-validation.md).

### Published Windows installer check

The earlier Beta 10 ZIP passed fresh installation and reinstallation on a GitHub-hosted **Windows Server 2025** runner using its own pinned Node.js runtime. Checks included local startup/HTML, unauthenticated history rejection, desktop-launcher creation, intact OBS assets, and preservation of a synthetic data file. No KICK account was connected, and application cloud access was disabled. This is not a Windows 10/11 interactive desktop test or a real-account migration test.

The **Windows published beta smoke test** GitHub Actions workflow runs on relevant main-branch release/test changes and can be manually dispatched. It downloads the published ZIP and checks its manifest hash before running the unchanged installer in a disposable profile. The workflow does not publish, deploy, or moderate a channel. Startup failures remain failures; the separate diagnostics step only collects bounded test logs.

Before relying on the beta for a live channel, verify the user's Windows desktop experience and, on an explicitly authorized test channel, check connection, signed events, a controlled verification request, clean chat restoration, permanent-ban preservation, manual recovery, and the end-of-stream report. Keep the runtime data and installation-specific encryption key private and out of release archives.


### Beta 11 privacy hardening

Beta 11 no longer persists encrypted full viewer IP addresses. Verification uses the connecting address only long enough to derive a keyed HMAC network identifier for exact-match ban-evasion checks. Existing encrypted IP material was erased from the private network tables, the ciphertext columns were removed, and the reversible IP encryption key/helpers were removed. StreamShield UI and APIs expose only masked network IDs, not full viewer IP addresses.


### Beta 12 automatic verification delivery

Beta 12 adds KICK's documented `chat:write` permission. After **Require Verification** successfully creates the one-time request and applies the temporary chat restriction, StreamShield automatically posts the verification message into KICK chat and replies to the selected chatter's message when a message ID is available. The post uses the connected broadcaster's user authorization. If KICK refuses or cannot send the message, StreamShield keeps the verification request active and copies the ready-made message as a manual fallback.

Existing installations should reconnect KICK once after updating to Beta 12 so the new chat permission can be approved.

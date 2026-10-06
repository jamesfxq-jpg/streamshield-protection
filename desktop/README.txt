StreamShield 0.6.0 Beta 11

Adds automatic evidence-sealed end-of-stream reports, Pre-Stream Protection Check, Offender Case Files, and Recovery Center on top of the Beta 8 live protection controls.

STREAMSHIELD PROTECTION 0.6.0 BETA 11 - KICK

INSTALL
0. Right-click the downloaded ZIP and choose Extract All.
1. Double-click "Install StreamShield.cmd".
2. The installer downloads the official Node.js 22.23.3 Windows runtime from nodejs.org and verifies its SHA-256 checksum before using it.
3. Your browser opens StreamShield at http://localhost:8787.
4. Click "Connect Kick" and approve the displayed Kick permissions.

NORMAL USE
Double-click the "StreamShield Protection" shortcut created on your Desktop.

PRIVACY
Your Kick OAuth tokens are encrypted locally on your PC. The StreamShield cloud OAuth broker processes authorization codes and refresh tokens only long enough to exchange/refresh them and does not persist them. Public Kick chat text buffered by the cloud webhook expires after 15 minutes; event rows expire after 24 hours. Optional Network Protection processes the viewer's public IP only when that viewer uses the StreamShield verification gateway. StreamShield immediately converts it to a keyed one-way network signature for exact matching, then discards the full IP. Full IP addresses are not stored or shown to streamers/moderators. Targeted Channel Verification also uses a random first-party browser token for up to 90 days and stores only a keyed one-way hash of that token. It is not a hardware ID and StreamShield does not use invasive browser fingerprinting.

SAFETY
StreamShield is defensive-only. It does not generate viewers, followers, chat, subscriptions, raids, or artificial engagement. Automatic timeouts are off by default.

BETA
This is a closed beta build. It is not yet code-signed with a commercial Windows publisher certificate. Windows may show an unknown-publisher warning because of that.

UPDATE CHECKS
StreamShield checks the official StreamShield release feed hourly while running. If a newer verified beta is available, the dashboard shows a download button. Updates are never silently installed while StreamShield is running.

NETWORK PROTECTION (OPTIONAL)
- Disabled by default.
- Uses a StreamShield-controlled KICK verification link; KICK itself does not expose viewer IP addresses.
- Full viewer IP addresses are not stored. A keyed one-way network signature is retained for automatic exact-network matching.
- A permanent KICK ban can mark previously verified network signatures as blocked.
- Exact-network auto-ban is a separate opt-in because shared/dynamic IPs can cause false positives.
- StreamShield does not fingerprint devices or ban subnets.


NEW IN 0.6.0-beta.2
-------------------
Easy Ban-Evasion Protection:
1. Connect KICK.
2. Click Enable Full Protection.
3. Click Copy Viewer Verification Link and place that link where viewers/moderators can use it.

The dashboard keeps masked verified-network records under the collapsed "Network & Ban History" subsection. The full IP is never displayed and is not persisted; only a keyed one-way network identifier is retained. StreamShield does not receive viewer IPs from KICK.


NEW IN 0.6.0-beta.3
-------------------
Easy undo for network mistakes:
- Open Network & Ban History.
- A blocked IP has an UN-IP BAN button.
- Confirm once to remove the network block and cancel any pending auto-ban action for that IP.
- The masked network record remains in history as UNBLOCKED for audit purposes.
- Existing KICK account bans are NOT automatically removed.


NEW IN 0.6.0-beta.4
-------------------
Always-visible Quick Start help:
- A StreamShield Quick Start pop-out opens every time the platform loads.
- It explains Connect KICK, Enable Full Protection, the Viewer Verification Link, Permanent Ban, future exact-network matching, Network & Ban History, and UN-IP BAN.
- A permanent Help button reopens the instructions at any time.
- The guide explains that the connecting address is processed only during voluntary verification to create a one-way network ID, and that shared/mobile/VPN/reassigned networks can cause false matches.


NEW IN 0.6.0-beta.5
-------------------
Targeted Channel Verification:
- In Recent Kick Chat, moderators can click Require Verification for a specific chatter.
- StreamShield applies a temporary chat restriction (up to 7 days) and creates a one-time Channel Verification link.
- A clean verification automatically removes the temporary chat restriction.
- Exact blocked-network matches remain subject to the existing network enforcement setting.
- A previously blocked first-party device token produces REVIEW REQUIRED and keeps chat locked for moderator review; device-token evidence alone does not automatically permanently ban an account.
- Device tokens are random first-party browser tokens, not hardware serial numbers or invasive fingerprints, and can be reset by clearing site data or changing browsers/devices.
- KICK does not currently provide third-party apps a private per-viewer popup API, so the one-time verification link is shown only in the moderator dashboard for the moderator to deliver directly.


NEW IN 0.6.0-beta.6
-------------------
Bot Attack Protection + Stream Reports:
- Follow Shield is enabled by default. It detects suspicious follow bursts, records them as evidence, and includes them in the end-of-stream report. It does not auto-ban followers based on follow velocity alone.
- Chat Raid Shield is enabled by default. It automatically deletes only high-confidence repetitive bot-spam messages using KICK's documented message-deletion API.
- Automatic user timeouts remain a separate opt-in and still require very high confidence, repeated identical spam, and an untrusted account.
- The dashboard now has a one-click Generate Stream Report button after a stream.
- Stream Reports include suspicious follow spikes, chat-raid deletions/timeouts, targeted verification activity, permanent bans, exact-network evasion bans, peak threat score, and incident count.
- Copy Summary for KICK Support produces a paste-ready defensive summary; the matching PDF is available from the same card.
- The existing targeted verification, first-party device-token review, exact verified-network matching, automatic exact-network ban option, and UN-IP BAN controls remain intact.
- StreamShield still cannot prevent a third party from sending fake follows to KICK's servers; Follow Shield detects, documents, and isolates the event in StreamShield's evidence workflow instead.


NEW IN 0.6.0-beta.7
-------------------
Compact Live Control:
- The main dashboard now has a Compact Control button that opens a resizable pop-out window for stream-time moderation.
- Compact Control shows threat level, live state, Follow Shield, Chat Raid Shield, recent chat, verification queue, blocked verified networks, and recent protection events.
- Per-chatter quick actions include Require Verification, 10-minute timeout, Permanent Ban, and manual KICK Unban.
- Pending targeted-verification restrictions can be released from the compact window.
- Blocked verified networks expose the existing UN-IP BAN action without opening the full dashboard.
- Shield Mode and Full Protection can be activated from the compact window with confirmations for consequential actions.
- The full dashboard remains available for detailed history, reports, settings, and evidence review.

NEW IN 0.6.0-beta.9
-------------------
Security Workflow + Evidence Integrity:
- Pre-Stream Protection Check verifies KICK authorization, required event monitoring, cloud relay readiness, Follow Shield, Chat Raid Shield, Link/Scam Shield, evidence logging, and optional Network Protection before the streamer goes live.
- End-of-stream reports are created automatically when StreamShield detects that a live stream has ended. The manual Generate / Refresh Report button remains available.
- New stream reports carry a SHA-256 evidence integrity seal and a chained event digest so later changes can be detected. The dashboard includes Verify Evidence Seal.
- Offender Case Files combine the viewer's recent in-memory chat, StreamShield moderation history, incident involvement, targeted-verification history, and verified-network history into one moderator view.
- Recovery Center can undo the latest supported reversible action: permanent KICK ban, timeout, targeted verification lock, Panic Mode activation, or trusted-viewer change. StreamShield IP blocks remain separate and still require UN-IP BAN.
- The Compact Control now includes a Case button and Undo Last action for fast stream-time moderation.
- Beta 9 removes generated local encryption-key files from the release package. Every installation creates its own local key on first run instead of receiving a shared packaged key.

EVIDENCE NOTE
The SHA-256 seal verifies that the StreamShield report content matches the locally recorded sealed report. It does not prove who initiated an attack and does not replace KICK's platform-side logs.


NEW IN 0.6.0-beta.10
--------------------
Public site: https://streamshield-protection-public.vercel.app

Reliability fixes:
- The main dashboard initializes all controls and renders recent moderation actions.
- Compact Control uses the actual verified-network history and verification request IDs.
- UN-IP BAN shows only currently blocked networks, while preserving audit history.
- The Windows installer copies the OBS branding assets into the installed app. The dashboards also link to the public branding downloads.
- Health waits for a signed KICK event before claiming Protected; current relay errors remain visible and fail the pre-stream check.
- Reconnecting the same KICK channel preserves verification restrictions, permanent-ban holds, trusted viewers, protection settings, and overlay/control keys.
- Moderation actions for the same user run in order. Permanent bans and newer timeouts supersede older verification unlocks.
- Clean automatic verification unlock requires local ownership, healthy recent relay polling, a received signed KICK event, and a fresh cloud verification result.
- A failed cloud verification setup does not impose a new chat timeout.
- Viewer verification shows a hosted information/consent page before KICK authorization and any optional network/device recording.
- Observed permanent KICK bans cancel earlier pending verification requests.

UPDATING AN EXISTING INSTALLATION
Stop StreamShield, extract this ZIP, and run Install StreamShield.cmd. The installer updates program files while retaining the existing application data directory. Reopen StreamShield and run Pre-Stream Protection Check.

LIVE BETA VALIDATION
Automated tests use isolated fixtures; they are not proof of a live KICK channel test. On a consenting test channel, verify KICK connection, live signed events, one controlled verification request, clean chat restoration, permanent-ban preservation, manual release, and the end-of-stream report.

KICK's unban API cannot conditionally remove only a particular earlier timeout. A separate moderator action performed directly on KICK can race an already-started automatic unlock before its webhook arrives. StreamShield preserves observed permanent bans and records review-required conflicts; channel moderators should verify KICK's current state after a concurrent action.


NEW IN 0.6.0-beta.11
--------------------
Moderator workflow clarity:
- The full dashboard now includes a Moderator Guide button.
- Compact Control now includes a Mod Guide button for an easy live-stream reference.
- Require Verification now copies a ready-to-paste message containing the selected @username, short instructions, and the one-time verification link instead of copying only the raw URL.
- The public Moderator Guide explains what human KICK moderators can and cannot access in this beta.
- The streamer can now select a specific recent KICK chatter and create a private StreamShield moderator invite bound to that exact KICK user ID.
- Selected moderators connect with their own KICK account and receive a restricted remote Mod Dashboard plus Compact Pop-Out.
- Remote moderator actions are queued through the StreamShield cloud service and executed by the streamer’s authorized desktop, so the streamer’s KICK password, OAuth token, stream key, and Windows credentials are never shared.
- The streamer can revoke a selected moderator at any time; active remote sessions are revoked with it.
- Remote mods can Delete, Verify, Timeout 10m, Permanent Ban, Unban, and open Case Files. They cannot change Full Protection, disconnect KICK, delete StreamShield data, or view full IP addresses.


PRIVACY HARDENING - BETA 11
---------------------------
- Full viewer IP addresses are not persisted.
- The verification edge receives the connection address transiently, converts it to a keyed HMAC network identifier, and discards the full address.
- StreamShield dashboards, Compact Control, case files, reports, and moderator views display only masked network IDs such as NET-12AB34CD.
- Previous encrypted IP ciphertext was erased from the StreamShield network tables and those storage columns were removed.
- Exact-network matching and UN-IP BAN continue to use the non-reversible keyed network hash.

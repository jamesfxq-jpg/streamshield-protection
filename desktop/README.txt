STREAMSHIELD PROTECTION — 0.6.0-beta.14
REQUIRED UPDATE / QUIET SHIELD

This candidate requires the matching Beta 14 backend before cloud sign-in.
Release status is tracked in docs/beta14-required-update.md. A ZIP build is not
proof that production website/backend publication or global sign-out occurred.

UPDATE
1. Close StreamShield and keep a private backup of its existing data directory.
2. Extract the current Windows ZIP with Extract All.
3. Run Install StreamShield.cmd.
4. Open the desktop shortcut and Connect KICK again.
5. Run Pre-Stream Check. Choose review-first Network Shield for the recommended
   setup. Installation preserves saved settings; it does not silently reset them.

The first Beta 14 launch expires older local StreamShield credentials while
retaining saved settings, verification locks, permanent-ban holds and reports.
Cloud policy can require a minimum version and a fresh OAuth sign-in for every
installation. Supported clients check authorization before using cached KICK
credentials, with a lease of up to 30 seconds; already in-flight calls can finish.
Offline PCs cannot be remotely made to download, quit or install an update.
Old clients can show a connection error rather than a new sign-out screen.
This does not log the user out of the KICK website.

MODERATOR WORKFLOW
Verify / Resend creates an account-bound request, temporarily restricts the
account and posts the neutral link in public KICK chat. A still-pending request
can be reused without a second timeout. Ban & Shield applies an account ban and
privately checks retained verified network history. Network updates may still
be syncing; missing history is shown honestly. Review-first does not enable
permanent automatic bans for shared-network matches.

Unban and Remove Network Block are separate actions. Newer permanent bans take
priority over older verification requests. Keep the desktop running for remote
moderator commands. After a session reset, web moderators reload and use a valid
private invite; the streamer can issue a fresh invite if needed.

PRIVACY
Account verification and privacy-protected network/browser-token processing
remain disclosed. No raw-IP storage, covert tracking or hardware fingerprinting
was added. Version/authentication/check-in metadata support required updates;
a client-reported version is not executable-file attestation.

TESTING
Synthetic regression and Windows installer checks do not establish live KICK
OAuth or interactive Windows 10/11 acceptance. Use a consenting test account
on an authorized test channel before enabling the global rollout.

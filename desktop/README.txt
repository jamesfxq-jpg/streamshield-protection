STREAMSHIELD PROTECTION — 0.6.0-beta.13
QUIET SHIELD

INSTALL OR UPDATE
1. Close the running StreamShield application.
2. Right-click the Windows ZIP and choose Extract All.
3. Open the extracted folder and run Install StreamShield.cmd.
4. Open StreamShield from the desktop launcher and run Pre-Stream Check.
   Existing application data is retained by the installer. Keep a private backup.
5. Choose Enable Network Shield / Use review-first settings.
   This deliberately turns OFF automatic exact-network bans while keeping
   existing account bans and network blocks. Saved settings are not changed
   merely by installing the update.

Beta 13 adds no new KICK permission. Users updating from before Beta 12 must
reconnect KICK once to approve chat:write for automatic verification replies.

THE SIMPLER WORKFLOW
Verify / Resend: temporarily restrict the selected account and send a neutral,
account-bound verification link. Repeat clicks reuse a still-pending request
within its original 30-minute window. At most one successful automatic chat
post for that active link is made per 60 seconds. There is no extra timeout.
If KICK cannot send it, use the copied fallback message.

Ban & Shield: permanently ban the selected KICK account and privately check
its retained verified network history. The result distinguishes protection off,
no retained network, unavailable history, an update still syncing, or confirmed
blocked history. A network lookup failure does not undo the account ban.
Normal bans made in KICK use the existing signed-ban-event backend path too.
Network marking is asynchronous; check history if the update is still pending.

Remove Network Block: the clearer name for the former UN-IP BAN control.
This removes the network block and associated pending network enforcement;
existing KICK account bans are separate and stay in place.

REVIEW FIRST
Shared, mobile, VPN and reassigned connections may belong to different people.
A network or first-party browser-token match is a review signal, not proof of
identity. The recommended preset does not permanently auto-ban network matches.
A targeted request can remain restricted while a moderator reviews the result.
The advanced exact-network auto-ban option is still available separately; it
rechecks current policy and retained blocked history before acting on a queue.
Trusted accounts are excluded from that automatic queue.

PRIVACY
KICK does not supply viewer IP addresses to StreamShield. A viewer must complete
the consented verification flow before a network can be associated with them.
StreamShield stores/displays keyed one-way network identifiers, not full viewer
IP addresses. No hidden tracking or invasive hardware fingerprinting was added.
Verification URLs used for resend are held only in bounded, expiring desktop
memory, not written to disk. Restarting or reconnecting can make resend
unavailable; existing restrictions are preserved for deliberate review.

VERIFICATION SAFETY
A clean result only releases a restriction this installation still owns, after
fresh cloud checks. Newer permanent bans take precedence. Expired, completed,
blocked, wrong-account or unconfirmed requests are not silently reused.
Account unban, network unblock and trusted-viewer changes remain distinct.

LIMITS AND TESTING
This is beta software. Local and CI fixtures use synthetic accounts; they do not
prove a live KICK OAuth round trip or live channel operation. Windows installer
checks use a disposable profile with application network access disabled.
Before relying on a live channel, test with an authorized consenting account:
connection, signed events, verification delivery, clean release, permanent-ban
preservation, shared-network review and manual recovery.

The matching hosted consent/moderator-page changes need website deployment;
installing this ZIP updates the desktop, not the separately hosted website.
No backend migration or new cloud function is required for the desktop update.

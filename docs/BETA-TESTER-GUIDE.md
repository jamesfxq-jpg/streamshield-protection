# StreamShield Beta Tester Guide - Beta 10

Current beta: **0.6.0-beta.10**  
Website: https://streamshield-protection-public.vercel.app/  
Tester page and feedback form: https://streamshield-protection-public.vercel.app/beta

## Purpose

The beta is for finding real-world reliability, usability and moderation problems before a broader release. Test normal streaming first. Controlled moderation, viewer-verification and recovery tests should use only accounts whose owners explicitly agreed to participate.

## Before testing

- Extract the ZIP before running the installer.
- Keep Windows security protections enabled.
- Connect KICK only through the normal KICK authorization screen.
- For the first live test, leave automatic user timeouts and exact-network auto-ban off.
- Never place passwords, OAuth tokens, stream keys, private messages or exact viewer IP addresses in feedback.
- Treat anomaly scores and network/device matches as review signals, not proof of identity or misconduct.

## Core test pass

1. Install Beta 10 and confirm the dashboard opens at localhost:8787.
2. Connect KICK and confirm the expected channel.
3. Run Pre-Stream Protection Check.
4. During an authorized test, generate an ordinary KICK event and confirm signed-event health updates.
5. Open Compact Control and test resizing, chat/event refresh and access to moderation/recovery controls.
6. With a consenting test account, test one targeted verification request and confirm the intended temporary restriction is handled correctly.
7. Test a reversible moderation action and recovery. Confirm an independent permanent ban is not undone by an older verification release.
8. Generate/review a stream report and verify its evidence seal.
9. Load one included PNG into OBS as an Image source.
10. Close StreamShield, reinstall the newest beta over the existing installation, reopen it and report any unexpected reset or lost setting.

## How the streamer or moderator selects a viewer for verification

1. Open **Recent KICK Chat** in the full StreamShield dashboard or **Compact Control**.
2. Find the specific chatter and click **Require Verification** beside that KICK account.
3. StreamShield creates a targeted verification request and places a temporary StreamShield-owned chat restriction on that account while the request is pending.
4. When **Require Verification** succeeds, StreamShield copies the one-time verification link to the moderator’s clipboard. StreamShield does **not** automatically send a private KICK message. Paste the link into KICK chat while mentioning the selected viewer, or send it through a private contact method you already use. The request is bound to the selected KICK user ID, so a different KICK account cannot complete that targeted verification.
5. The viewer opens the link, selects **Continue with KICK**, and completes KICK authorization using the account named by the request.
6. StreamShield records the verification outcome. A clean result can automatically release the temporary restriction when StreamShield still owns that restriction and the relay/event health requirements are satisfied.
7. A blocked-network or blocked first-party browser-token signal is a moderation signal that can remain locked for review. An exact blocked-network match can also use the optional exact-network auto-ban setting.
8. A moderator can release a pending verification manually. A separate permanent KICK ban should not be removed by an older verification completion.

Use only consenting test accounts when testing this workflow during the closed beta.

## What to report

Report successful tests as well as failures. Prioritize:
- crashes or freezes;
- KICK connection, webhook/event, viewer-count or relay failures;
- false positives or missed suspicious behavior;
- unexpected bans, timeouts, unbans or verification unlocks;
- lost settings or reconnect/update problems;
- Compact Control problems;
- confusing wording/workflows;
- broken report/PDF/evidence-seal behavior;
- OBS branding or overlay problems.

## Severity

- **None:** successful test or general suggestion.
- **Low:** cosmetic or minor usability issue.
- **Medium:** feature works poorly or requires a workaround.
- **High:** major feature broken, repeated false moderation, or unsafe behavior.
- **Critical:** crash/data loss or behavior that could materially harm channel moderation. Stop that test path and report it.

## Update instructions

1. Close StreamShield.
2. Download the latest beta ZIP from the official StreamShield site.
3. Right-click the ZIP and choose **Extract All**.
4. Open the extracted folder and run **Install StreamShield.cmd**.
5. Reopen StreamShield and rerun Pre-Stream Protection Check.

The installer is intended to update application files while keeping the existing application data directory. Any lost settings, lost moderation state or unexpected reconnect behavior is a beta issue and should be reported.

## Bug-report template

**StreamShield version:**  
**Windows version:**  
**KICK username (optional):**  
**Area tested:**  
**Outcome:**  
**Severity:**  
**Short summary:**  
**Steps to reproduce:**  
**Expected result:**  
**Actual result:**  
**Did restarting StreamShield change the result?:**  
**Anything else that may matter?:**

Do not include passwords, tokens, stream keys, private messages or exact viewer IP addresses.

## Beta disclaimer

StreamShield Beta 10 is pre-release defensive software. Features can fail, change or produce incorrect results. It does not guarantee detection or prevention of botting, ban evasion, fake engagement, harassment or other abuse. Automated and network-based actions can produce false positives, especially with shared, mobile, VPN or reassigned networks.

KICK controls its own platform, enforcement, monetization and Partner Program decisions. StreamShield is not a KICK service.

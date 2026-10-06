# Beta 10 Windows validation follow-up

Checked on 2026-10-06 at approximately 01:52 UTC (October 5 in US Eastern time).

## Result

The unchanged published **0.6.0-beta.10** Windows ZIP passed an actual Windows installer smoke test. The test ran on a GitHub-hosted **Windows Server 2025** machine in a disposable user profile, not on James's computer. This does not replace a Windows 10/11 user-desktop check or real KICK-channel acceptance.

Successful GitHub Actions runs:

- https://github.com/jamesfxq-jpg/streamshield-protection/actions/runs/37401170635
- https://github.com/jamesfxq-jpg/streamshield-protection/actions/runs/37401241420

The first successful run's full job log was inspected. The final follow-up run also completed successfully.

## Verified on Windows

1. The public ZIP downloaded successfully. Its byte count and SHA-256 matched the committed release manifest; the packaged application version matched Beta 10.
2. The unchanged installer supplied its pinned Node.js runtime and started the installed application. The application health endpoint and HTML landing page responded successfully.
3. The application and uninstall desktop launchers were created. The test did not run the uninstaller.
4. OBS setup instructions, full overlay, horizontal overlay, shield badge and brand-kit preview copied byte-for-byte correctly.
5. Private network history returned HTTP 401 without authentication.
6. Stopping the isolated application and reinstalling the same published ZIP succeeded. A synthetic marker in the existing data directory survived reinstallation. This is a data-file preservation test, not a real-account migration or token-restoration test.

No KICK account was connected. Cloud integration was disabled for the local application and a preload rejected application fetch calls. Installer downloads from the fixed public release and Node.js hosts remained enabled.

## Test-harness correction

The initial smoke test failed before the application became healthy. Its own quoted NODE_OPTIONS preload path used Windows backslashes, which Node interpreted as escapes. The failure was reproduced independently with Node.js 22.23.3. The test now normalizes that preload argument to forward slashes. The network block remains enabled; startup assertions were not removed. Diagnostic output is retained for future failures.

The correction affected test code only. The published application ZIP, release manifest, backend and production site were not changed during this follow-up.

The committed workflow runs on relevant main-branch release/test changes and supports manual workflow dispatch. It has read-only repository permissions and a ten-minute timeout. Failed installation checks remain failures even when the separate diagnostic step succeeds.

## Regression and live-service rechecks

All five committed regression scripts passed again on Linux with both Node.js **22.23.3** and **24.21.0**:

- compact-fixtures.mjs
- health-ui-fixtures.mjs
- runtime.mjs
- moderation-regression.mjs (15 of 15 cases)
- backend-consent.test.mjs

These cover compact verification/network controls, health/readiness states, authorization and CSRF guards, recovery, reports, moderation ordering, reconnect behavior and consent handling using isolated fixtures. They are not live KICK moderation results.

The canonical home, privacy, terms, verification and result pages returned HTTP 200 with HTML content types. The backend reported ok=true, database=true, app_configured=true and public_version=0.6.0-beta.10. Backend health is not evidence that a particular user's channel is connected or protected.

The downloaded release remains **2,726,565 bytes**, with SHA-256:

`7c982c9c47d616a8a25c6761e95c706f0b166a1da4cbf2bc563caeabd48f8358`

## Remaining live acceptance

Use a channel and test viewer accounts whose owners have explicitly agreed to the test. Keep broad automatic moderation and exact-network auto-ban off during initial acceptance. Do not test against ordinary viewers.

Start by opening the installed Beta 10 application and running **Pre-Stream Protection Check**. Record the result, installed version and any connection/relay warning. Connect KICK through its normal authorization screen only when needed; never share tokens, passwords or stream keys in a report.

After that, verify a signed real KICK event reaches the dashboard and compact window; test one controlled viewer-verification flow; verify only the intended temporary restriction is restored; confirm an independent permanent ban is not automatically removed; check manual account and verified-network recovery separately; and inspect the resulting stream report. Moderation changes must be explicitly authorized and confined to consenting test accounts.

Real viewer OAuth, live-channel moderation, concurrent external-moderator races, ordinary Windows desktop/OBS usability and Windows publisher signing remain outside the completed checks. No claim of full production readiness or guaranteed prevention of botting is made.

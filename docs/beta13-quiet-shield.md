# Beta 13 Quiet Shield — implementation and acceptance

## Scope

Desktop moderation and hosted consent/moderator UI improvements, compatible
with the existing backend. No database migration, cloud function change or
live KICK moderation is part of this update.

The recommended setup is review-first. Existing opt-ins are retained until the
streamer explicitly selects the new preset. Network matches are not identities.

## Changes

The desktop adds private Ban & Shield results, validates verification links
before applying a restriction, reuses still-pending requests without another
timeout, limits successful resend posts to once per minute, and uses a bounded
in-memory cache that cannot extend a request's expiry. Both moderation screens
and the hosted moderator panel prevent duplicate in-flight submissions.

New account bans preserve verification-release cancellation even if token
refresh fails. Fresh network policy and retained blocked history are required
before an old network queue entry can produce an automatic ban. Local network
settings and network-unblock operations are serialized against that check.

The hosted verification page remains click-to-consent with an explicit, visible
network/browser-token disclosure. Invalid-link and disabled-form protections
remain. The new text neither claims universal viewer-IP access nor hides data
collection. It provides no invisible fingerprinting or platform-wide IP ban.

## Tests

Run from the repository root:

```
node tests/compact-fixtures.mjs
node tests/health-ui-fixtures.mjs
node tests/runtime.mjs
node tests/moderation-regression.mjs
node tests/backend-consent.test.mjs
node tests/quiet-shield.test.mjs
```

At implementation time all six scripts passed locally on Node 22.16.0. The
moderation/reauthorization suite has 29 cases; Quiet Shield adds 13 status,
privacy, expiry, consent and browser-handler cases. The original compact,
health, HTTP runtime and backend consent suites remain part of the checks.
These are fixtures and do not contact a real account or apply live moderation.
CI evidence and Windows candidate installation results are recorded separately.

## Release procedure

Build the deterministic desktop ZIP with `python tools/package_release.py`.
Validate archive safety, checksum, version and fresh/reinstallation behavior on
a disposable Windows profile. The existing Windows smoke script accepts
`-LocalZipPath` for this purpose; otherwise it still checks the published ZIP.

Deploy the matching static files only to the existing StreamShield site, and
verify that its landing-page version, ZIP, SHA-256 and release.json agree.
Do not advertise a production release just because a branch candidate passed.

## Live acceptance still required

With a consenting test account on an explicitly authorized test channel, check
real OAuth delivery, clean verification/release, permanent-ban precedence,
pending-link reuse, review of a shared-network match and separate network
unblock/account-unban behavior. Keep production settings unchanged otherwise.

KICK actions and webhooks are asynchronous. A signed ban event can arrive after
the immediate account-ban response; the UI reports this as unconfirmed syncing,
not an already-applied network block. Concurrent changes outside this desktop
cannot be made transactional with KICK's APIs. Always check the current account
state after conflicting moderator actions.

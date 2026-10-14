# Beta 14: clearer website and required-update rollout

## Implemented source

- Rewritten homepage focused on live monitoring, verification, Ban & Shield, moderator tools and reporting.
- New `/how-it-works` walkthrough, refreshed `/mods` and `/beta`, and a dedicated `/update` page with live policy status.
- Privacy and consent remain visible; the main marketing sections no longer lead with a catalogue of limitations.
- Current version reporting unified to `0.6.0-beta.14`; earlier Beta 13 source still had Beta 12 in the runtime constant and several hosted labels.
- All cloud desktop calls now include compatibility metadata. Installation and moderator authentication stay separate from that reported version.
- A dormant backend minimum-version policy, epoch-bound fresh OAuth reconnect, conditional check-ins, and guarded one-time activation SQL.
- Existing local credentials expire on first Beta 14 launch. Stored channel settings, trusted accounts, verification ownership, permanent-ban holds and reports are preserved.
- Supported-client authorization lease is up to 30 seconds; a revoked session clears local cached credentials and prompts reconnect. Network failures deny actions without deleting credentials.

## Not activated by preparing this release

A new candidate does not publish a site or sign anyone out. Do not activate the rollout until all required publication and consenting-account checks below pass. Vercel deployment access was refused for the existing StreamShield project during this work; no replacement project or weaker access controls should be created.

## Safe publication order

1. Apply `20261014023000_required_client_update.sql`. It creates the policy with enforcement **off**, adds only compatibility/authentication/check-in fields, and leaves existing bans/settings intact.
2. Deploy the matching `streamshield-backend` files and existing Deno configuration, preserving custom install/moderator authentication, KICK signature verification and viewer consent checks. Existing backend `verify_jwt` is false because it uses these custom paths.
3. Deploy the existing Vercel website project from the exact tested source. Do not replace the project or alter protection settings to work around a denied deployment.
4. Download the public Windows ZIP through its real production URL; compare its size and SHA-256 with `release.json`. Publish the verified release record and update the existing download redirects. Keep the old release available for controlled rollback testing, not as the new required download.
5. Use a consenting account on an authorized KICK test channel to verify fresh login, event relay, verification reply, clean release, permanent-ban preservation, shared-network review and recovery. Test an old client update error without applying real bans.
6. Only then execute `supabase/operations/activate_required_client_update.sql`. It refuses a missing release, malformed hash, incorrect download URL or already-active repeat rollout. It increments the session epoch, invalidates cloud installation keys, revokes web moderator sessions, and fails pending moderator commands. It does not delete channels, moderator approvals, bans, network history or preferences.
7. Reconnect through the new app and verify authenticated current-version check-ins. An offline installation remains unknown until it connects. Web moderators use a valid private invite and refresh their sign-in.

## Rollout boundaries

The server can stop old StreamShield clients accessing its cloud relay and authorization services; it cannot close an arbitrary process or make a PC download/install files. Old clients without a remote sign-out UI may display cloud errors while still showing their local dashboard. Already-issued KICK tokens reside on those PCs and are not globally revoked by a database epoch change; local direct actions already in flight may finish. KICK website logins are separate. Do not claim every PC has installed the update merely because old cloud sessions were revoked.

Version metadata is reported by the client, not cryptographic executable-file attestation. Authentication gates and epoch checks prevent cached registrations or stale signed login tickets from restoring a revoked cloud session.

## Validation

Run all six existing regression entry points plus `tests/required-update.test.mjs` (20 cases), the static website checks, and the candidate Windows installer/reinstaller check. Browser rendering checks use synthetic policy responses and no live login or moderation.

This document records the rollout procedure, not a claim that production deployment, global sign-out or live-channel acceptance has completed. Consult the current PR and observed deployment results for status.

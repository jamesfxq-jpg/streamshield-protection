-- Publish only after the canonical ZIP and legacy redirects are verified.
begin;
do $publish$
declare
  current_version text;
begin
  select public_version into current_version
    from public.streamshield_app_config
    where singleton = true for update;
  if current_version is distinct from '0.6.0-beta.4' then
    raise exception 'Publication state changed; expected Beta 4, found %', current_version;
  end if;
  insert into public.streamshield_releases
    (version, channel, download_url, sha256, published_at, notes)
  values ('0.6.0-beta.10', 'beta', 'https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-site/download?version=0.6.0-beta.10', '7c982c9c47d616a8a25c6761e95c706f0b166a1da4cbf2bc563caeabd48f8358', '2026-10-06T01:07:38Z', 'Corrected dashboard and compact controls, conservative verification recovery, preserved reconnect state, honest relay readiness, hosted consent pages, sealed stream reports and OBS branding. Live KICK channel validation remains pending.');
  update public.streamshield_app_config
    set public_version = '0.6.0-beta.10'
    where singleton = true;
end;
$publish$;
commit;

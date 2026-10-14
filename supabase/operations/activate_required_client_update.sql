-- Run ONLY after deploying backend and website, verifying the public Windows ZIP
-- against release.json, and completing a consenting test-channel reconnect.
-- No bans, network identifiers, channel preferences or moderator approvals are deleted.
begin;
lock table public.streamshield_client_policy in row exclusive mode;
do $$
declare rel public.streamshield_releases%rowtype;
begin
 perform 1 from public.streamshield_client_policy where singleton for update;
 if not found then raise exception 'Install the dormant client policy before activation'; end if;
 select * into rel from public.streamshield_releases where version='0.6.0-beta.14' and channel='beta';
 if rel.version is null or rel.sha256 is null or rel.download_url is null or rel.sha256 !~ '^[0-9a-f]{64}$' or rel.download_url <> 'https://streamshield-protection-public.vercel.app/releases/StreamShield-Protection-0.6.0-beta.14-Windows.zip' then
   raise exception 'Publish and verify the Beta 14 release before activating required update';
 end if;
 if exists(select 1 from public.streamshield_client_policy where singleton and enforced and minimum_version=rel.version) then
   raise exception 'This rollout is already active; refusing to sign out newly reconnected users';
 end if;
 update public.streamshield_client_policy set enforced=true,minimum_version=rel.version,auth_epoch=auth_epoch+1,force_reauth_after=clock_timestamp(),download_url=rel.download_url,release_sha256=rel.sha256,updated_at=clock_timestamp() where singleton;
 update public.streamshield_channels set install_key_hash=null,updated_at=clock_timestamp() where install_key_hash is not null;
 update public.streamshield_moderator_sessions set revoked_at=clock_timestamp() where revoked_at is null;
 update public.streamshield_moderator_commands set status='failed',outcome='session_ended_required_update',completed_at=clock_timestamp() where status in ('queued','claimed');
end $$;
commit;

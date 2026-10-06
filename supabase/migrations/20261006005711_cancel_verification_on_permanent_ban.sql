-- A permanent KICK ban supersedes older pending/clean verification requests.
-- The implementation remains in the private schema; only the authenticated
-- service role may call the narrowly scoped public RPC wrapper.
create or replace function streamshield_private.cancel_verification_for_ban(
  p_broadcaster_id bigint, p_kick_user_id bigint, p_event_at timestamptz
) returns integer
language plpgsql
security definer
set search_path = ''
as $function$
declare affected integer := 0;
begin
  if p_broadcaster_id <= 0 or p_kick_user_id <= 0 or p_event_at is null then
    raise exception 'valid broadcaster, user, and event time required';
  end if;
  update streamshield_private.verification_requests
     set status = 'cancelled',
         desktop_outcome = 'superseded_by_permanent_ban',
         desktop_completed_at = now()
   where broadcaster_id = p_broadcaster_id
     and kick_user_id = p_kick_user_id
     and requested_at <= p_event_at
     and status in ('pending','verified','review','blocked')
     and desktop_completed_at is null;
  get diagnostics affected = row_count;
  return affected;
end;
$function$;

revoke all on function streamshield_private.cancel_verification_for_ban(bigint,bigint,timestamptz) from public, anon, authenticated;
grant usage on schema streamshield_private to service_role;
grant execute on function streamshield_private.cancel_verification_for_ban(bigint,bigint,timestamptz) to service_role;

create or replace function public.streamshield_verification_cancel_for_ban(
  p_broadcaster_id bigint, p_kick_user_id bigint, p_event_at timestamptz
) returns integer
language sql
security invoker
set search_path = ''
as $function$
  select streamshield_private.cancel_verification_for_ban(p_broadcaster_id,p_kick_user_id,p_event_at);
$function$;

revoke all on function public.streamshield_verification_cancel_for_ban(bigint,bigint,timestamptz) from public, anon, authenticated;
grant execute on function public.streamshield_verification_cancel_for_ban(bigint,bigint,timestamptz) to service_role;

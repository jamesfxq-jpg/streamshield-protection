-- Applied to StreamShield Protection on 2026-10-14.
-- These functions are called only by authenticated StreamShield backend routes.
-- Do not grant public RPC access: their bodies operate on the supplied channel.
revoke execute on function public.streamshield_moderator_claim_commands(bigint,integer) from public,anon,authenticated;
revoke execute on function public.streamshield_moderator_complete_command(bigint,uuid,boolean,text,jsonb) from public,anon,authenticated;
grant execute on function public.streamshield_moderator_claim_commands(bigint,integer) to service_role;
grant execute on function public.streamshield_moderator_complete_command(bigint,uuid,boolean,text,jsonb) to service_role;

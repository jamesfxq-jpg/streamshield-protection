-- Streamer-selected remote moderator access.
create table if not exists public.streamshield_moderator_invites (
  id uuid primary key default gen_random_uuid(),
  broadcaster_id bigint not null,
  kick_user_id bigint not null,
  kick_username text,
  invite_token_hash text not null unique,
  permissions jsonb not null default '{"delete_message":true,"verify":true,"timeout":true,"ban":true,"unban":true,"case_file":true,"network_view":true}'::jsonb,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  redeemed_at timestamptz,
  revoked_at timestamptz
);
create index if not exists streamshield_mod_invites_channel_idx on public.streamshield_moderator_invites (broadcaster_id,created_at desc);
create index if not exists streamshield_mod_invites_target_idx on public.streamshield_moderator_invites (broadcaster_id,kick_user_id,expires_at desc);

create table if not exists public.streamshield_moderators (
  broadcaster_id bigint not null,
  kick_user_id bigint not null,
  kick_username text,
  permissions jsonb not null default '{"delete_message":true,"verify":true,"timeout":true,"ban":true,"unban":true,"case_file":true,"network_view":true}'::jsonb,
  active boolean not null default true,
  approved_at timestamptz not null default now(),
  last_login_at timestamptz,
  revoked_at timestamptz,
  primary key (broadcaster_id,kick_user_id)
);

create table if not exists public.streamshield_moderator_sessions (
  id uuid primary key default gen_random_uuid(),
  broadcaster_id bigint not null,
  kick_user_id bigint not null,
  kick_username text,
  session_token_hash text not null unique,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz,
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index if not exists streamshield_mod_sessions_lookup_idx on public.streamshield_moderator_sessions (session_token_hash);
create index if not exists streamshield_mod_sessions_channel_idx on public.streamshield_moderator_sessions (broadcaster_id,kick_user_id,expires_at desc);

create table if not exists public.streamshield_moderator_commands (
  id uuid primary key default gen_random_uuid(),
  broadcaster_id bigint not null,
  moderator_user_id bigint not null,
  moderator_username text,
  action text not null check (action in ('delete_message','verification_request','timeout_10','permanent_ban','unban','case_file')),
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'queued' check (status in ('queued','claimed','completed','failed')),
  created_at timestamptz not null default now(),
  claimed_at timestamptz,
  completed_at timestamptz,
  outcome text,
  result jsonb
);
create index if not exists streamshield_mod_commands_queue_idx on public.streamshield_moderator_commands (broadcaster_id,status,created_at);
create index if not exists streamshield_mod_commands_owner_idx on public.streamshield_moderator_commands (broadcaster_id,moderator_user_id,created_at desc);

alter table public.streamshield_moderator_invites enable row level security;
alter table public.streamshield_moderators enable row level security;
alter table public.streamshield_moderator_sessions enable row level security;
alter table public.streamshield_moderator_commands enable row level security;

create or replace function public.streamshield_moderator_claim_commands(p_broadcaster_id bigint,p_limit integer default 20)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_temp'
as $function$
declare out_rows jsonb;
begin
  with picked as (
    select id
      from public.streamshield_moderator_commands
     where broadcaster_id=p_broadcaster_id
       and (status='queued' or (status='claimed' and claimed_at<now()-interval '90 seconds'))
     order by created_at asc
     limit greatest(1,least(coalesce(p_limit,20),50))
     for update skip locked
  ),
  updated as (
    update public.streamshield_moderator_commands c
       set status='claimed',claimed_at=now()
      from picked
     where c.id=picked.id
    returning c.id,c.broadcaster_id,c.moderator_user_id,c.moderator_username,c.action,c.payload,c.created_at,c.claimed_at
  )
  select coalesce(jsonb_agg(to_jsonb(updated) order by created_at asc),'[]'::jsonb)
    into out_rows
    from updated;
  return coalesce(out_rows,'[]'::jsonb);
end;
$function$;

create or replace function public.streamshield_moderator_complete_command(
  p_broadcaster_id bigint,p_id uuid,p_ok boolean,p_outcome text,p_result jsonb default null
)
returns boolean
language plpgsql
security definer
set search_path to 'public','pg_temp'
as $function$
declare changed integer:=0;
begin
  update public.streamshield_moderator_commands
     set status=case when p_ok then 'completed' else 'failed' end,
         completed_at=now(),
         outcome=left(coalesce(p_outcome,''),200),
         result=coalesce(p_result,'{}'::jsonb)
   where id=p_id and broadcaster_id=p_broadcaster_id and status='claimed';
  get diagnostics changed=row_count;
  return changed=1;
end;
$function$;

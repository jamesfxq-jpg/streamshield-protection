-- Hash-only network identity hardening.
-- Full viewer IP addresses are processed transiently only to create a keyed HMAC.
-- They are not persisted or returned to StreamShield clients.

create or replace function public.streamshield_network_observe(
  p_broadcaster_id bigint,
  p_kick_user_id bigint,
  p_kick_username text,
  p_ip text,
  p_source text default 'edge'::text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','streamshield_private','pg_temp'
as $function$
declare
  s streamshield_private.network_settings%rowtype;
  h text;
  b streamshield_private.network_blocks%rowtype;
  queued boolean := false;
begin
  if p_broadcaster_id is null or p_broadcaster_id <= 0
     or p_kick_user_id is null or p_kick_user_id <= 0 then
    raise exception 'invalid_identity';
  end if;

  select * into s
  from streamshield_private.network_settings
  where broadcaster_id = p_broadcaster_id;

  if not found or not s.enabled then
    return jsonb_build_object('ok', true, 'enabled', false, 'blocked_network', false, 'action_queued', false);
  end if;

  h := streamshield_private.hash_network_ip(p_ip);

  delete from streamshield_private.network_observations
  where broadcaster_id = p_broadcaster_id
    and expires_at < now();

  insert into streamshield_private.network_observations(
    broadcaster_id, kick_user_id, kick_username, network_hash, network_source,
    first_seen_at, last_seen_at, expires_at
  )
  values(
    p_broadcaster_id, p_kick_user_id, left(coalesce(p_kick_username,''),100), h,
    left(coalesce(p_source,'edge'),40), now(), now(),
    now() + make_interval(days => s.observation_retention_days)
  )
  on conflict (broadcaster_id, kick_user_id, network_hash)
  do update set
    kick_username = excluded.kick_username,
    network_source = excluded.network_source,
    last_seen_at = excluded.last_seen_at,
    expires_at = excluded.expires_at;

  select * into b
  from streamshield_private.network_blocks
  where broadcaster_id = p_broadcaster_id
    and network_hash = h
    and permanent = true;

  if found then
    update streamshield_private.network_blocks
      set last_match_at = now(),
          match_count = match_count + 1
    where broadcaster_id = p_broadcaster_id and network_hash = h;

    if s.auto_ban_exact_network_match
       and coalesce(b.source_user_id, 0) <> p_kick_user_id then
      insert into streamshield_private.network_enforcement_queue(
        broadcaster_id, kick_user_id, kick_username, network_hash, family_id, reason
      )
      values(
        p_broadcaster_id, p_kick_user_id, left(coalesce(p_kick_username,''),100),
        h, b.family_id, 'exact_blocked_network_match'
      )
      on conflict do nothing;
      get diagnostics queued = row_count;
    end if;

    return jsonb_build_object(
      'ok', true, 'enabled', true, 'blocked_network', true,
      'action_queued', queued, 'family_id', b.family_id
    );
  end if;

  return jsonb_build_object('ok', true, 'enabled', true, 'blocked_network', false, 'action_queued', false);
end;
$function$;

create or replace function public.streamshield_network_mark_banned(
  p_broadcaster_id bigint,
  p_kick_user_id bigint,
  p_kick_username text,
  p_reason text,
  p_permanent boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','streamshield_private','pg_temp'
as $function$
declare
  s streamshield_private.network_settings%rowtype;
  inserted_count integer := 0;
begin
  if not coalesce(p_permanent, false) then
    return jsonb_build_object('ok', true, 'permanent', false, 'network_blocks_created', 0);
  end if;

  select * into s
  from streamshield_private.network_settings
  where broadcaster_id = p_broadcaster_id;

  if not found or not s.enabled then
    return jsonb_build_object('ok', true, 'enabled', false, 'network_blocks_created', 0);
  end if;

  insert into streamshield_private.network_blocks(
    broadcaster_id, network_hash, source_user_id, source_username, reason,
    permanent, blocked_at, unblocked_at, unblocked_reason
  )
  select
    o.broadcaster_id,
    o.network_hash,
    p_kick_user_id,
    left(coalesce(p_kick_username,''),100),
    left(coalesce(nullif(p_reason,''),'permanent_kick_ban'),500),
    true, now(), null, null
  from streamshield_private.network_observations o
  where o.broadcaster_id = p_broadcaster_id
    and o.kick_user_id = p_kick_user_id
    and o.expires_at >= now()
  on conflict (broadcaster_id, network_hash)
  do update set
    source_user_id = excluded.source_user_id,
    source_username = excluded.source_username,
    reason = excluded.reason,
    permanent = true,
    blocked_at = now(),
    unblocked_at = null,
    unblocked_reason = null;

  get diagnostics inserted_count = row_count;

  return jsonb_build_object(
    'ok', true, 'enabled', true, 'permanent', true,
    'network_blocks_created', inserted_count
  );
end;
$function$;

create or replace function public.streamshield_network_history(
  p_broadcaster_id bigint,
  p_limit integer default 100
)
returns jsonb
language sql
security definer
set search_path to 'public','streamshield_private','pg_temp'
as $function$
with network_ids as (
  select network_hash from streamshield_private.network_observations where broadcaster_id = p_broadcaster_id
  union
  select network_hash from streamshield_private.network_blocks where broadcaster_id = p_broadcaster_id
),
rows as (
  select
    n.network_hash,
    'NET-' || upper(right(n.network_hash, 8)) as network_label,
    coalesce(b.permanent, false) as blocked,
    b.family_id,b.source_user_id,b.source_username,b.reason,b.blocked_at,b.unblocked_at,
    b.unblocked_reason,b.last_match_at,coalesce(b.match_count,0) as match_count,
    o.first_seen_at,o.last_seen_at,o.expires_at,coalesce(o.accounts,'[]'::jsonb) as accounts
  from network_ids n
  left join streamshield_private.network_blocks b
    on b.broadcaster_id=p_broadcaster_id and b.network_hash=n.network_hash
  left join lateral (
    select
      min(x.first_seen_at) as first_seen_at,
      max(x.last_seen_at) as last_seen_at,
      max(x.expires_at) as expires_at,
      jsonb_agg(jsonb_build_object(
        'kick_user_id',x.kick_user_id,'kick_username',x.kick_username,
        'first_seen_at',x.first_seen_at,'last_seen_at',x.last_seen_at
      ) order by x.last_seen_at desc) as accounts
    from streamshield_private.network_observations x
    where x.broadcaster_id=p_broadcaster_id and x.network_hash=n.network_hash
  ) o on true
  order by greatest(
    coalesce(b.unblocked_at,'-infinity'::timestamptz),
    coalesce(b.last_match_at,'-infinity'::timestamptz),
    coalesce(o.last_seen_at,'-infinity'::timestamptz),
    coalesce(b.blocked_at,'-infinity'::timestamptz)
  ) desc
  limit greatest(1,least(coalesce(p_limit,100),250))
)
select coalesce(jsonb_agg(jsonb_build_object(
  'network_hash',network_hash,'network_label',network_label,'blocked',blocked,
  'family_id',family_id,'source_user_id',source_user_id,'source_username',source_username,
  'reason',reason,'blocked_at',blocked_at,'unblocked_at',unblocked_at,
  'unblocked_reason',unblocked_reason,'last_match_at',last_match_at,'match_count',match_count,
  'first_seen_at',first_seen_at,'last_seen_at',last_seen_at,'expires_at',expires_at,'accounts',accounts
)), '[]'::jsonb)
from rows;
$function$;

update streamshield_private.network_observations set ip_cipher=null where ip_cipher is not null;
update streamshield_private.network_blocks set ip_cipher=null where ip_cipher is not null;

alter table streamshield_private.network_observations drop column if exists ip_cipher;
alter table streamshield_private.network_blocks drop column if exists ip_cipher;

drop function if exists streamshield_private.encrypt_network_ip(text);
drop function if exists streamshield_private.decrypt_network_ip(bytea);
delete from vault.secrets where name='streamshield_network_ip_key';

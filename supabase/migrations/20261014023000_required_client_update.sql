-- Dormant compatibility policy. Activation is a separate, explicitly guarded operation.
create table if not exists public.streamshield_client_policy (
 singleton boolean primary key default true check(singleton),
 enforced boolean not null default false,
 minimum_version text not null default '0.6.0-beta.14',
 auth_epoch integer not null default 0 check(auth_epoch>=0),
 force_reauth_after timestamptz,
 download_url text,
 release_sha256 text,
 updated_at timestamptz not null default now()
);
alter table public.streamshield_client_policy enable row level security;
revoke all on public.streamshield_client_policy from public,anon,authenticated;
grant select,insert,update on public.streamshield_client_policy to service_role;
insert into public.streamshield_client_policy(singleton) values(true) on conflict(singleton) do nothing;
alter table public.streamshield_channels add column if not exists client_version text;
alter table public.streamshield_channels add column if not exists auth_epoch integer not null default 0;
alter table public.streamshield_channels add column if not exists authenticated_at timestamptz;
alter table public.streamshield_channels add column if not exists last_client_seen_at timestamptz;
comment on column public.streamshield_channels.client_version is 'Client-reported version, not binary attestation.';
alter table public.streamshield_moderator_sessions add column if not exists auth_epoch integer not null default 0;

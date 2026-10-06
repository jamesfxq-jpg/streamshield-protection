create table if not exists public.streamshield_beta_feedback (
  id uuid primary key default gen_random_uuid(),
  public_ref text not null unique,
  created_at timestamptz not null default now(),
  tester_name text,
  kick_username text,
  email text,
  windows_version text not null,
  streamshield_version text not null,
  test_area text not null check (test_area in ('install','kick_connect','prestream','compact','chat','verification','network','moderation','recovery','reports','obs','update','other')),
  outcome text not null check (outcome in ('worked','worked_with_issue','failed','suggestion')),
  severity text not null check (severity in ('none','low','medium','high','critical')),
  summary text not null,
  reproduction_steps text,
  expected_result text,
  actual_result text,
  notes text,
  contact_opt_in boolean not null default false
);
alter table public.streamshield_beta_feedback enable row level security;
create index if not exists streamshield_beta_feedback_created_at_idx on public.streamshield_beta_feedback (created_at desc);
create index if not exists streamshield_beta_feedback_triage_idx on public.streamshield_beta_feedback (severity, outcome, created_at desc);
comment on table public.streamshield_beta_feedback is 'Closed beta tester feedback submitted through the first-party StreamShield website.';

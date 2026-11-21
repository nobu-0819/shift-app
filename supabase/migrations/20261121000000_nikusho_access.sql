begin;

alter table public.staff
  add column auth_user_id uuid unique references auth.users(id) on delete set null,
  add column is_external_viewer boolean not null default false,
  add column password_setup_required boolean not null default true,
  add column password_reset_at timestamptz,
  add column account_locked boolean not null default false,
  add constraint nikusho_staff_one_role check (not (coalesce(is_admin, false) and is_external_viewer));

-- The active Auth session must belong to the linked staff member and have
-- started after the most recent reset. Never trust browser-supplied roles.
create unique index nikusho_staff_login_code on public.staff ((code::text)) where code is not null;

create schema if not exists nikusho_private;
revoke all on schema nikusho_private from public, anon, authenticated;
grant usage on schema nikusho_private to authenticated;

create function nikusho_private.current_member()
returns public.staff
language sql stable security definer set search_path = ''
as $$
  select s.*
  from public.staff s
  join auth.sessions session on session.user_id = s.auth_user_id
    and session.id::text = auth.jwt()->>'session_id'
  where s.auth_user_id = auth.uid()
    and not s.account_locked
    and (s.password_reset_at is null or session.created_at > s.password_reset_at)
$$;
revoke all on function nikusho_private.current_member() from public, anon, authenticated;

create function public.nikusho_current_account()
returns jsonb
language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object(
    'id', s.id, 'code', s.code, 'name', s.name,
    'is_admin', coalesce(s.is_admin, false), 'is_external_viewer', s.is_external_viewer,
    'password_setup_required', s.password_setup_required
  )
  from nikusho_private.current_member() s where s.id is not null
$$;
revoke all on function public.nikusho_current_account() from public, anon;
grant execute on function public.nikusho_current_account() to authenticated;

create function nikusho_private.ready_role()
returns text
language sql stable security definer set search_path = ''
as $$
  select case
    when s.id is null or s.password_setup_required then null
    when s.is_admin then 'admin'
    when s.is_external_viewer then 'viewer'
    else 'staff'
  end
  from nikusho_private.current_member() s
$$;
revoke all on function nikusho_private.ready_role() from public, anon, authenticated;
grant execute on function nikusho_private.ready_role() to authenticated;

create function nikusho_private.owns_staff(target_id text)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select coalesce(s.id::text = target_id and not s.password_setup_required, false)
  from nikusho_private.current_member() s
$$;
revoke all on function nikusho_private.owns_staff(text) from public, anon, authenticated;
grant execute on function nikusho_private.owns_staff(text) to authenticated;

-- Only the account-management function can finish releasing an account.
-- Use the database clock, which also timestamps Auth sessions.
create function public.nikusho_finish_password_change(
  target_staff_id text, target_auth_user_id uuid
)
returns boolean
language plpgsql security definer set search_path = ''
as $$
begin
  update public.staff set auth_user_id = target_auth_user_id,
    password_setup_required = false,
    password_reset_at = clock_timestamp(),
    account_locked = false
  where id::text = target_staff_id and account_locked;
  return found;
end
$$;
revoke all on function public.nikusho_finish_password_change(text, uuid) from public, anon, authenticated;
grant execute on function public.nikusho_finish_password_change(text, uuid) to service_role;

create function public.nikusho_reset_password_setup(target_staff_id text)
returns boolean
language plpgsql security definer set search_path = ''
as $$
begin
  update public.staff set password_setup_required = true,
    password_reset_at = clock_timestamp()
  where id::text = target_staff_id and not account_locked;
  return found;
end
$$;
revoke all on function public.nikusho_reset_password_setup(text) from public, anon, authenticated;
grant execute on function public.nikusho_reset_password_setup(text) to service_role;

-- Serialize attempts globally. This also caps attempts made against unknown codes.
create table nikusho_private.setup_rate_limit (
  singleton boolean primary key default true check (singleton),
  bucket bigint not null,
  attempts integer not null
);
revoke all on nikusho_private.setup_rate_limit from public, anon, authenticated;

create function public.nikusho_claim_password_setup(staff_code text)
returns jsonb
language plpgsql security definer set search_path = ''
as $$
declare
  current_bucket bigint := floor(extract(epoch from clock_timestamp()) / 60);
  allowed_attempts integer;
  account record;
begin
  insert into nikusho_private.setup_rate_limit as limit_row (bucket, attempts)
  values (current_bucket, 1)
  on conflict (singleton) do update
  set bucket = excluded.bucket,
    attempts = case when limit_row.bucket = excluded.bucket then least(limit_row.attempts + 1, 13) else 1 end
  returning attempts into allowed_attempts;

  if allowed_attempts > 12 then
    return jsonb_build_object('rate_limited', true);
  end if;
  update public.staff set account_locked = true
  where code::text = staff_code and password_setup_required
    and not account_locked
  returning id::text, code::text, auth_user_id into account;
  if not found then return null; end if;

  return jsonb_build_object('id', account.id, 'code', account.code, 'auth_user_id', account.auth_user_id);
end
$$;
revoke all on function public.nikusho_claim_password_setup(text) from public, anon, authenticated;
grant execute on function public.nikusho_claim_password_setup(text) to service_role;

-- Staff codes double as enrollment credentials before a password is set.
-- The general staff read policy and viewer lists must not expose these codes.
create function public.nikusho_admin_staff()
returns table (id text, name text, code text, is_admin boolean, is_external_viewer boolean, password_configured boolean)
language sql stable security definer set search_path = ''
as $$
  select s.id::text, s.name::text, s.code::text, coalesce(s.is_admin, false), s.is_external_viewer,
    s.auth_user_id is not null and not s.password_setup_required and not s.account_locked
  from public.staff s
  where (select nikusho_private.ready_role()) = 'admin'
  order by s.code
$$;
revoke all on function public.nikusho_admin_staff() from public, anon, authenticated;
grant execute on function public.nikusho_admin_staff() to authenticated;

-- Replace legacy policies on the app's tables in one transaction, otherwise
-- a permissive legacy policy could still authorize a request.
do $$
declare
  table_name text;
  old_policy record;
begin
  foreach table_name in array array['staff','shift_requests','shift_skip','deadlines',
    'special_holidays','announcements','shift_schedule']
  loop
    if to_regclass(format('public.%I', table_name)) is null and table_name = 'shift_schedule' then
      continue;
    end if;
    for old_policy in select policyname from pg_policies
      where schemaname = 'public' and tablename = table_name
    loop
      execute format('drop policy %I on public.%I', old_policy.policyname, table_name);
    end loop;
    execute format('alter table public.%I enable row level security', table_name);
    execute format('revoke all on public.%I from public, anon, authenticated', table_name);
  end loop;
end
$$;

-- Remove any old column-specific grants as well, especially legacy PIN access.
do $$
declare col record;
begin
  for col in select table_name, column_name from information_schema.columns
    where table_schema = 'public' and table_name in
      ('staff','shift_requests','shift_skip','deadlines','special_holidays','announcements','shift_schedule')
  loop
    execute format('revoke all (%I) on public.%I from public, anon, authenticated',
      col.column_name, col.table_name);
  end loop;
end
$$;

grant select (id, name, is_admin, is_external_viewer) on public.staff to authenticated;
grant update (is_admin, is_external_viewer) on public.staff to authenticated;
grant select, insert, update, delete on public.shift_requests, public.shift_skip,
  public.deadlines, public.special_holidays, public.announcements to authenticated;

-- PostgREST inserts use any existing serial/identity defaults on these tables.
do $$
declare col record;
declare sequence_name text;
begin
  for col in select table_name, column_name from information_schema.columns
    where table_schema = 'public' and table_name in
      ('shift_requests','shift_skip','deadlines','special_holidays','announcements')
  loop
    sequence_name := pg_get_serial_sequence(format('public.%I', col.table_name), col.column_name);
    if sequence_name is not null then
      execute format('grant usage on sequence %s to authenticated', sequence_name);
    end if;
  end loop;
end
$$;

create policy nikusho_staff_read on public.staff for select to authenticated
  using ((select nikusho_private.ready_role()) in ('admin','viewer') or nikusho_private.owns_staff(id::text));
create policy nikusho_staff_role_change on public.staff for update to authenticated
  using ((select nikusho_private.ready_role()) = 'admin' and not nikusho_private.owns_staff(id::text))
  with check ((select nikusho_private.ready_role()) = 'admin' and not nikusho_private.owns_staff(id::text));

do $$
declare table_name text;
begin
  foreach table_name in array array['shift_requests','shift_skip']
  loop
    execute format($policy$
      create policy nikusho_read on public.%I for select to authenticated
      using ((select nikusho_private.ready_role()) in ('admin','viewer')
        or nikusho_private.owns_staff(staff_id::text))
    $policy$, table_name);
    execute format($policy$
      create policy nikusho_write on public.%I for all to authenticated
      using ((select nikusho_private.ready_role()) = 'admin'
        or ((select nikusho_private.ready_role()) = 'staff' and nikusho_private.owns_staff(staff_id::text)))
      with check ((select nikusho_private.ready_role()) = 'admin'
        or ((select nikusho_private.ready_role()) = 'staff' and nikusho_private.owns_staff(staff_id::text)))
    $policy$, table_name);
  end loop;
  foreach table_name in array array['deadlines','special_holidays','announcements']
  loop
    execute format($policy$
      create policy nikusho_read on public.%I for select to authenticated
      using ((select nikusho_private.ready_role()) is not null)
    $policy$, table_name);
    execute format($policy$
      create policy nikusho_manage on public.%I for all to authenticated
      using ((select nikusho_private.ready_role()) = 'admin')
      with check ((select nikusho_private.ready_role()) = 'admin')
    $policy$, table_name);
  end loop;
end
$$;

commit;

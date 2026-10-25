-- Shahin ERP 1.10: Owner + Admin, logins the owner/admin hands out (Login ID + one-time code), password resets,
-- forced password change on first sign-in, and sign-out everywhere when a login is disabled.

alter table public.profiles add column if not exists is_owner boolean not null default false;
alter table public.profiles add column if not exists login_id text;
alter table public.profiles add column if not exists must_change_password boolean not null default false;
alter table public.profiles add column if not exists phone text;
alter table public.profiles add column if not exists login_issued_at timestamptz;
create unique index if not exists profiles_login_id on public.profiles (lower(login_id)) where login_id is not null;

-- the first admin of each company is its owner
update public.profiles p set is_owner = true
 where p.id = (select q.id from public.profiles q where q.company_id = p.company_id and q.role = 'admin' order by q.created_at limit 1)
   and not exists (select 1 from public.profiles r where r.company_id = p.company_id and r.is_owner);

create or replace function public.is_company_owner() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_owner from public.profiles where user_id = auth.uid() and status = 'Active' limit 1), false)
$$;

-- first sign-up in an empty database becomes the owner
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_company uuid;
begin
  update public.profiles
     set user_id = new.id, updated_at = now()
   where lower(email) = lower(new.email) and user_id is null;

  if not found and not exists (select 1 from public.companies) then
    insert into public.companies (name) values ('Shahin Contracting Est.') returning id into v_company;
    insert into public.profiles (company_id, user_id, full_name, email, role, title, is_owner)
    values (v_company, new.id, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)), new.email, 'admin', 'Owner', true);
    insert into public.settings (company_id) values (v_company);
  end if;
  return new;
end $$;

-- Only the owner can touch the owner account or add/remove admins. Disabling a login signs it out everywhere.
create or replace function public.guard_profiles() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then
    if old.is_owner then raise exception 'The owner account cannot be deleted'; end if;
    if auth.uid() is not null and old.role = 'admin' and not public.is_company_owner() then raise exception 'Only the owner can remove an admin'; end if;
    if old.user_id is not null then
      delete from auth.refresh_tokens where user_id = old.user_id::text;
      delete from auth.sessions where user_id = old.user_id;
    end if;
    return old;
  end if;
  if auth.uid() is not null then
    if tg_op = 'INSERT' then
      if new.is_owner and not public.is_company_owner() then new.is_owner := false; end if;
      if new.role = 'admin' and not public.is_company_owner() then raise exception 'Only the owner can create an admin'; end if;
    else
      if old.is_owner and not public.is_company_owner() then raise exception 'Only the owner can change the owner account'; end if;
      if new.is_owner is distinct from old.is_owner and not public.is_company_owner() then raise exception 'Only the owner can change who is owner'; end if;
      if (old.role = 'admin' or new.role = 'admin') and new.role is distinct from old.role and not public.is_company_owner() then raise exception 'Only the owner can make or remove an admin'; end if;
      if old.role = 'admin' and new.status is distinct from old.status and not public.is_company_owner() then raise exception 'Only the owner can disable an admin'; end if;
    end if;
  end if;
  if tg_op = 'UPDATE' then
    if old.is_owner and (new.status <> 'Active' or new.role <> 'admin') then raise exception 'The owner account always stays an active admin'; end if;
    if new.status = 'Disabled' and old.status <> 'Disabled' and old.user_id is not null then
      delete from auth.refresh_tokens where user_id = old.user_id::text;
      delete from auth.sessions where user_id = old.user_id;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists guard_profiles on public.profiles;
create trigger guard_profiles before insert or update or delete on public.profiles
for each row execute function public.guard_profiles();

-- Owner/admin creates a login (or re-issues one for an existing person). The code is set as a temporary password
-- and must be changed at the first sign-in. Returns the profile id.
create or replace function public.admin_issue_login(
  p_profile_id uuid, p_full_name text, p_login_id text, p_email text, p_role text, p_title text, p_phone text, p_employee_id uuid, p_password text)
returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare
  me public.profiles;
  t public.profiles;
  v_login text := lower(trim(coalesce(p_login_id, '')));
  v_email text;
  v_uid uuid;
  v_pid uuid;
begin
  select * into me from public.profiles where user_id = auth.uid() and status = 'Active';
  if me.id is null or me.role <> 'admin' then raise exception 'Only the owner or an admin can give logins'; end if;
  if v_login !~ '^[a-z0-9][a-z0-9._-]{2,29}$' then raise exception 'Login ID: 3 to 30 small letters or numbers, no spaces'; end if;
  if length(coalesce(p_password, '')) < 8 then raise exception 'The code must have at least 8 characters'; end if;
  if p_role not in ('admin','manager','hr','accountant','foreman','viewer','employee') then raise exception 'Unknown role'; end if;
  if p_role = 'admin' and not me.is_owner then raise exception 'Only the owner can create an admin'; end if;

  if p_profile_id is not null then
    select * into t from public.profiles where id = p_profile_id and company_id = me.company_id;
    if t.id is null then raise exception 'Person not found'; end if;
    if (t.is_owner or t.role = 'admin') and not me.is_owner then raise exception 'Only the owner can change an admin login'; end if;
  end if;
  if exists (select 1 from public.profiles where lower(login_id) = v_login and id is distinct from p_profile_id) then
    raise exception 'This Login ID is already taken — choose another';
  end if;

  v_email := lower(nullif(trim(coalesce(p_email, '')), ''));
  if v_email is null then v_email := coalesce(case when t.user_id is not null then t.email end, v_login || '@staff.shahincontracting.com'); end if;

  if t.id is null then
    insert into public.profiles (company_id, full_name, email, title, role, status, login_id, must_change_password, phone, employee_id, login_issued_at)
    values (me.company_id, trim(p_full_name), v_email, p_title, p_role, 'Active', v_login, true, p_phone, p_employee_id, now())
    returning * into t;
  else
    update public.profiles set full_name = coalesce(nullif(trim(p_full_name), ''), full_name), title = p_title, phone = p_phone,
           role = case when is_owner then 'admin' else p_role end, employee_id = p_employee_id, login_id = v_login,
           email = case when user_id is null then v_email else email end, status = 'Active',
           must_change_password = (user_id is distinct from auth.uid()), login_issued_at = now()
     where id = t.id returning * into t;
  end if;
  v_pid := t.id;

  if t.user_id is null then
    select id into v_uid from auth.users where lower(email) = lower(t.email);
    if v_uid is null then
      v_uid := gen_random_uuid();
      insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
                              created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change)
      values ('00000000-0000-0000-0000-000000000000', v_uid, 'authenticated', 'authenticated', lower(t.email), crypt(p_password, gen_salt('bf')), now(),
              '{"provider":"email","providers":["email"]}'::jsonb, jsonb_build_object('full_name', t.full_name), now(), now(), '', '', '', '');
      insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
      values (v_uid::text, v_uid, jsonb_build_object('sub', v_uid::text, 'email', lower(t.email), 'email_verified', true), 'email', now(), now(), now());
    else
      update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), email_confirmed_at = coalesce(email_confirmed_at, now()), updated_at = now() where id = v_uid;
    end if;
    update public.profiles set user_id = v_uid where id = v_pid;
  else
    update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), updated_at = now() where id = t.user_id;
    if t.user_id <> auth.uid() then
      delete from auth.refresh_tokens where user_id = t.user_id::text;
      delete from auth.sessions where user_id = t.user_id;
    end if;
  end if;
  return v_pid;
end $$;

-- Sign-in screen: turn a Login ID into the account email (nothing else is revealed).
create or replace function public.login_email(p_login text) returns text
language sql stable security definer set search_path = public as $$
  select email from public.profiles where lower(login_id) = lower(trim(p_login)) and status = 'Active' and user_id is not null limit 1
$$;

-- After the person sets a new password on first sign-in.
create or replace function public.password_changed() returns void
language sql security definer set search_path = public as $$
  update public.profiles set must_change_password = false, last_login = now() where user_id = auth.uid()
$$;

revoke all on function public.admin_issue_login(uuid, text, text, text, text, text, text, uuid, text) from public, anon;
grant execute on function public.admin_issue_login(uuid, text, text, text, text, text, text, uuid, text) to authenticated;
revoke all on function public.login_email(text) from public;
grant execute on function public.login_email(text) to anon, authenticated;
revoke all on function public.password_changed() from public, anon;
grant execute on function public.password_changed() to authenticated;

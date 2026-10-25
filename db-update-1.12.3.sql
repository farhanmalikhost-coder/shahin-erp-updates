-- Shahin ERP 1.12.3: sign-in fix.
-- The two-step (MFA) rule read auth.mfa_factors directly inside every table policy. Signed-in users are not
-- allowed to read that table, so every read failed and sign-in said "not linked". The check now runs in a
-- trusted function, and the app reads its own profile through a dedicated function.

create or replace function public.mfa_ok() returns boolean
language sql stable security definer set search_path = public, auth as $$
  select array[coalesce(auth.jwt()->>'aal', 'aal1')] <@ (
    select case when count(*) > 0 then array['aal2'] else array['aal1','aal2'] end
      from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified')
$$;
grant execute on function public.mfa_ok() to authenticated, anon;

do $$
declare t text;
begin
  for t in
    select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
  loop
    execute format('drop policy if exists %I on public.%I', t || '_mfa', t);
    execute format('create policy %I on public.%I as restrictive to authenticated using (public.mfa_ok()) with check (public.mfa_ok())', t || '_mfa', t);
  end loop;
end $$;

-- the signed-in person's own profile (used right after sign-in)
create or replace function public.my_profile() returns jsonb
language sql stable security definer set search_path = public as $$
  select to_jsonb(p) - 'pw_hash' - 'pw_salt' from public.profiles p where p.user_id = auth.uid() limit 1
$$;
grant execute on function public.my_profile() to authenticated;

-- Shahin ERP v1.8: ZATCA invoice fields and enforced two-step verification.

alter table public.invoices add column if not exists invoice_type text default 'Standard tax invoice (B2B)';
alter table public.invoices add column if not exists issued_at timestamptz;
alter table public.settings add column if not exists zatca_seller_name text;

-- Two-step verification is enforced by the database, not only by the app:
-- a user who has an authenticator set up can read or change company data only after entering the code (aal2).
do $$
declare t text;
begin
  for t in
    select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
  loop
    execute format('drop policy if exists %I on public.%I', t || '_mfa', t);
    execute format($p$create policy %I on public.%I as restrictive to authenticated using (
      array[coalesce(auth.jwt()->>'aal', 'aal1')] <@ (
        select case when count(*) > 0 then array['aal2'] else array['aal1','aal2'] end
          from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified'))
      with check (
      array[coalesce(auth.jwt()->>'aal', 'aal1')] <@ (
        select case when count(*) > 0 then array['aal2'] else array['aal1','aal2'] end
          from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified'))$p$, t || '_mfa', t);
  end loop;
end $$;

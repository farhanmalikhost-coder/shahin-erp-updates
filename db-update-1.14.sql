-- Shahin ERP: close the Supabase Security Advisor warnings "anyone without signing in can call this function".
-- Helper functions are for signed-in users only. Public functions (verify_document, tenant_portal,
-- tenant_submit_payment, login_email, mfa_ok) are deliberately NOT touched.
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as f from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
           where ns.nspname = 'public' and p.proname in ('current_app_role','current_company_id','current_employee_id',
             'guard_profiles','handle_new_user','has_role','is_company_owner','import_company_data','admin_issue_login')
  loop
    execute format('revoke execute on function %s from public, anon', r.f);
    execute format('grant execute on function %s to authenticated', r.f);
  end loop;
  for r in select p.oid::regprocedure as f from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
           where ns.nspname = 'public' and p.proname in ('set_updated_at','apply_policies','lock_zatca_invoice')
  loop
    execute format('alter function %s set search_path = public', r.f);
  end loop;
end $$;
-- Online safety copy: an offline computer/phone can store a full copy of its data here,
-- so the data survives a lost, stolen or burnt computer. Owner (admin) only.
create table if not exists public.offline_backups (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  device text not null default 'device',
  records int not null default 0,
  payload jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists offline_backups_company_idx on public.offline_backups (company_id, created_at desc);
alter table public.offline_backups enable row level security;
-- no direct table access: everything goes through the functions below
revoke all on public.offline_backups from anon, authenticated;

create or replace function public.save_offline_backup(p_device text, p_payload jsonb, p_records int)
returns uuid language plpgsql security definer set search_path = public as $$
declare cid uuid := public.current_company_id(); nid uuid;
begin
  if cid is null or not public.has_role(array['admin']) then raise exception 'Only the owner can save a safety copy'; end if;
  insert into public.offline_backups (company_id, device, records, payload)
    values (cid, coalesce(nullif(p_device, ''), 'device'), coalesce(p_records, 0), p_payload) returning id into nid;
  -- keep the newest 40 copies, plus the newest copy of each of the last 60 days
  delete from public.offline_backups b where b.company_id = cid
    and b.id not in (select id from public.offline_backups where company_id = cid order by created_at desc limit 40)
    and b.id not in (select distinct on (created_at::date) id from public.offline_backups where company_id = cid and created_at > now() - interval '60 days' order by created_at::date, created_at desc);
  return nid;
end $$;

create or replace function public.list_offline_backups()
returns table (id uuid, device text, records int, created_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if public.current_company_id() is null or not public.has_role(array['admin']) then raise exception 'Only the owner can see safety copies'; end if;
  return query select b.id, b.device, b.records, b.created_at from public.offline_backups b
    where b.company_id = public.current_company_id() order by b.created_at desc limit 100;
end $$;

create or replace function public.get_offline_backup(p_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r jsonb;
begin
  if public.current_company_id() is null or not public.has_role(array['admin']) then raise exception 'Only the owner can restore a safety copy'; end if;
  select payload into r from public.offline_backups where id = p_id and company_id = public.current_company_id();
  return r;
end $$;

revoke execute on function public.save_offline_backup(text, jsonb, int), public.list_offline_backups(), public.get_offline_backup(uuid) from public, anon;
grant execute on function public.save_offline_backup(text, jsonb, int), public.list_offline_backups(), public.get_offline_backup(uuid) to authenticated;
-- Website inquiries: the public contact form on shahincontracting.com sends a lead straight into the ERP
-- (Business Development > Target Companies + Opportunities). Callable without signing in, by design.
create or replace function public.website_inquiry(p_name text, p_company text, p_email text, p_phone text, p_service text, p_message text, p_website text default null)
returns boolean language plpgsql security definer set search_path = public as $$
declare cid uuid; pid uuid; recent int;
begin
  if coalesce(p_website, '') <> '' then return true; end if; -- hidden spam-trap field: pretend success
  if length(btrim(coalesce(p_name, ''))) < 2 or length(coalesce(p_name, '')) > 120
     or length(coalesce(p_message, '')) > 3000 or length(coalesce(p_email, '')) > 160
     or length(coalesce(p_phone, '')) > 40 or length(coalesce(p_company, '')) > 160 or length(coalesce(p_service, '')) > 120
     or (coalesce(p_email, '') !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' and length(btrim(coalesce(p_phone, ''))) < 6) then
    raise exception 'Please check your details and try again';
  end if;
  select id into cid from public.companies order by created_at limit 1;
  if cid is null then return false; end if;
  select count(*) into recent from public.prospects where company_id = cid and source = 'Website' and created_at > now() - interval '1 hour';
  if recent >= 30 then raise exception 'Too many requests, please try again later'; end if;
  insert into public.prospects (company_id, name, contact_person, public_email, phone, potential_services, source, status, priority, notes)
    values (cid, coalesce(nullif(btrim(p_company), ''), btrim(p_name)), btrim(p_name), nullif(btrim(p_email), ''), nullif(btrim(p_phone), ''),
            nullif(btrim(p_service), ''), 'Website', 'New', 'High', left(coalesce(p_message, ''), 3000)) returning id into pid;
  insert into public.opportunities (company_id, title, prospect_id, service, stage, notes)
    values (cid, 'Website inquiry - ' || btrim(p_name), pid, nullif(btrim(p_service), ''), 'Requirement Received', left(coalesce(p_message, ''), 3000));
  return true;
end $$;
grant execute on function public.website_inquiry(text, text, text, text, text, text, text) to anon, authenticated;

-- Shahin ERP 1.12: ZATCA Phase 2 (Fatoora integration) for the Saudi company's invoices only.

-- the e-invoicing device (EGS) and its keys: only the server (edge function, service role) can read this table
create table if not exists public.zatca_egs (
  company_id uuid primary key references public.companies(id) on delete cascade,
  env text not null default 'sandbox',
  egs_uuid uuid not null default gen_random_uuid(),
  common_name text,
  private_key text,
  ccsid_token text,
  ccsid_secret text,
  ccsid_request_id text,
  pcsid_token text,
  pcsid_secret text,
  icv bigint not null default 0,
  pih text not null default 'NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==',
  busy_until timestamptz,
  status text not null default 'Not connected',
  compliance jsonb,
  connected_at timestamptz,
  updated_at timestamptz not null default now()
);
alter table public.zatca_egs enable row level security;
-- (no policies on purpose: browsers can never read the private key)

-- what the ERP may see about the connection
create or replace function public.zatca_status() returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce((select jsonb_build_object('env', env, 'status', status, 'icv', icv, 'connected_at', connected_at, 'compliance', compliance, 'common_name', common_name, 'updated_at', updated_at)
                   from public.zatca_egs where company_id = public.current_company_id()
                     and public.has_role(array['admin','accountant'])), jsonb_build_object('status', 'Not connected'))
$$;
grant execute on function public.zatca_status() to authenticated;

-- invoice fields
alter table public.invoices add column if not exists doc_type text default '388';
alter table public.invoices add column if not exists ref_invoice text;
alter table public.invoices add column if not exists note_reason text;
alter table public.invoices add column if not exists supply_date date;
alter table public.invoices add column if not exists payment_means text;
alter table public.invoices add column if not exists zatca_status text;
alter table public.invoices add column if not exists zatca_uuid uuid;
alter table public.invoices add column if not exists zatca_icv bigint;
alter table public.invoices add column if not exists zatca_hash text;
alter table public.invoices add column if not exists zatca_qr text;
alter table public.invoices add column if not exists zatca_xml text;
alter table public.invoices add column if not exists zatca_result jsonb;
alter table public.invoices add column if not exists zatca_sent_at timestamptz;

-- buyer national address (needed for standard tax invoices)
alter table public.clients add column if not exists building_number text;
alter table public.clients add column if not exists street text;
alter table public.clients add column if not exists district text;
alter table public.clients add column if not exists postal_code text;

-- seller national address and EGS details
alter table public.settings add column if not exists zatca_street text;
alter table public.settings add column if not exists zatca_building text;
alter table public.settings add column if not exists zatca_district text;
alter table public.settings add column if not exists zatca_city text default 'Jeddah';
alter table public.settings add column if not exists zatca_postal text;
alter table public.settings add column if not exists zatca_short_address text;
alter table public.settings add column if not exists zatca_branch text default 'Head Office';
alter table public.settings add column if not exists zatca_industry text default 'Construction';
alter table public.settings add column if not exists zatca_auto_send boolean default true;

-- a cleared or reported invoice cannot be changed any more (ZATCA rule) — only payments and its status
create or replace function public.lock_zatca_invoice() returns trigger
language plpgsql as $$
declare
  keep constant text[] := array['paid_amount','status','updated_at','zatca_status','zatca_uuid','zatca_icv','zatca_hash','zatca_qr','zatca_xml','zatca_result','zatca_sent_at','notes'];
  k text;
  o jsonb := to_jsonb(old);
  n jsonb := to_jsonb(new);
begin
  if old.zatca_status in ('CLEARED','REPORTED') then
    if tg_op = 'DELETE' then raise exception 'This invoice is registered with ZATCA and cannot be deleted. Issue a credit note instead.'; end if;
    foreach k in array keep loop
      o := o - k;
      n := n - k;
    end loop;
    if o is distinct from n then raise exception 'This invoice is registered with ZATCA and cannot be changed. Issue a credit or debit note instead.'; end if;
  end if;
  return coalesce(new, old);
end $$;
drop trigger if exists lock_zatca_invoice on public.invoices;
create trigger lock_zatca_invoice before update or delete on public.invoices for each row execute function public.lock_zatca_invoice();

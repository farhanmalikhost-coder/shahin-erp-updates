-- Shahin ERP — full database schema
-- Run once in a NEW Supabase project: Dashboard > SQL Editor > paste > Run.
-- Every table is isolated per company and protected by row level security.

-- gen_random_uuid() is built into Postgres 13+ (Supabase runs 15+).

-- ---------------------------------------------------------------------------
-- Companies and user profiles
-- ---------------------------------------------------------------------------
create table if not exists public.companies (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  user_id uuid unique references auth.users(id) on delete set null,
  full_name text not null,
  email text not null,
  title text,
  role text not null default 'viewer' check (role in ('admin','manager','hr','accountant','foreman','viewer')),
  status text not null default 'Active' check (status in ('Active','Disabled')),
  last_login timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, email)
);

-- Helpers used by every policy. SECURITY DEFINER so they can read profiles under RLS.
create or replace function public.current_company_id() returns uuid
language sql stable security definer set search_path = public as $$
  select company_id from public.profiles where user_id = auth.uid() and status = 'Active' limit 1
$$;

create or replace function public.current_app_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where user_id = auth.uid() and status = 'Active' limit 1
$$;

create or replace function public.has_role(roles text[]) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.current_app_role() = any(roles), false)
$$;

create or replace function public.set_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

-- New sign-ups: link to a profile the admin already created (matched by email).
-- The very first sign-up in an empty database becomes the company owner (admin).
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
    insert into public.profiles (company_id, user_id, full_name, email, role, title)
    values (v_company, new.id, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)), new.email, 'admin', 'Owner');
    insert into public.settings (company_id) values (v_company);
  end if;
  return new;
end $$;

-- ---------------------------------------------------------------------------
-- Settings
-- ---------------------------------------------------------------------------
create table if not exists public.settings (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null unique references public.companies(id) on delete cascade,
  company_name text not null default 'Shahin Contracting Est.',
  company_name_ar text default 'مؤسسة صباح حسين أبو شاهين للمقاولات',
  cr_number text default '',
  vat_number text default '',
  address text default 'Bldg No. 7689, Prince Majid Street, Al Aziziyah District, Jeddah 23342',
  phone text default '',
  email text default '',
  website text default 'shahincontracting.com',
  currency text not null default 'SAR',
  vat_rate numeric(5,2) not null default 15,
  work_hours_per_day numeric(4,2) not null default 8,
  work_days_per_month numeric(4,1) not null default 30,
  ot_multiplier numeric(4,2) not null default 1.5,
  expiry_alert_days int not null default 30,
  annual_leave_days numeric(5,2) not null default 21,
  annual_leave_days_after_5y numeric(5,2) not null default 30,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Projects & sales
-- ---------------------------------------------------------------------------
create table if not exists public.clients (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  name text not null,
  contact_person text, phone text, email text,
  vat_number text, cr_number text, city text, address text,
  status text not null default 'Active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  code text not null,
  name text not null,
  client_id uuid references public.clients(id) on delete set null,
  type text, location text, site_engineer text,
  contract_value numeric(14,2) default 0,
  progress numeric(5,2) default 0 check (progress between 0 and 100),
  start_date date, end_date date,
  status text not null default 'Planning' check (status in ('Planning','Active','On Hold','Completed','Cancelled')),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, code)
);

create table if not exists public.quotations (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  number text not null,
  date date not null default current_date,
  client_id uuid references public.clients(id) on delete set null,
  project_id uuid references public.projects(id) on delete set null,
  subject text, valid_until date,
  status text not null default 'Draft' check (status in ('Draft','Sent','Approved','Rejected')),
  items jsonb not null default '[]'::jsonb,
  subtotal numeric(14,2) default 0, vat numeric(14,2) default 0, total numeric(14,2) default 0,
  terms text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, number)
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  number text not null,
  date date not null default current_date,
  client_id uuid references public.clients(id) on delete set null,
  project_id uuid references public.projects(id) on delete set null,
  due_date date,
  status text not null default 'Issued' check (status in ('Draft','Issued','Partially Paid','Paid','Overdue','Cancelled')),
  items jsonb not null default '[]'::jsonb,
  subtotal numeric(14,2) default 0, vat numeric(14,2) default 0, total numeric(14,2) default 0,
  paid_amount numeric(14,2) default 0,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, number)
);

-- ---------------------------------------------------------------------------
-- Human resources
-- ---------------------------------------------------------------------------
create table if not exists public.employees (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_code text not null,
  full_name text not null,
  nationality text, date_of_birth date, mobile text, email text, emergency_contact text,
  job_title text, department text,
  project_id uuid references public.projects(id) on delete set null,
  joining_date date not null default current_date,
  contract_type text default 'Limited', contract_end date,
  status text not null default 'Active' check (status in ('Active','Vacation','On Leave','Resigned','Terminated','Final Exit')),
  iqama_number text, iqama_expiry date, national_id text,
  passport_number text, passport_expiry date,
  medical_insurance_expiry date, gosi_number text,
  basic_salary numeric(12,2) not null default 0,
  housing_allowance numeric(12,2) default 0,
  transport_allowance numeric(12,2) default 0,
  other_allowance numeric(12,2) default 0,
  bank_name text, iban text,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, employee_code)
);

create table if not exists public.employee_documents (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_id uuid not null references public.employees(id) on delete cascade,
  doc_type text not null, doc_number text,
  issue_date date, expiry_date date,
  file_url text, notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.attendance (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_id uuid not null references public.employees(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  date date not null,
  status text not null check (status in ('Present','Absent','Sick','Leave','Off','Holiday')),
  hours numeric(4,2) default 0,
  overtime_hours numeric(4,2) default 0,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (employee_id, date)
);

create table if not exists public.leaves (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_id uuid not null references public.employees(id) on delete cascade,
  leave_type text not null,
  start_date date not null, end_date date not null,
  days numeric(5,1) default 0,
  status text not null default 'Requested' check (status in ('Requested','Approved','Rejected','Completed')),
  ticket boolean default false,
  exit_reentry_number text, notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (end_date >= start_date)
);

create table if not exists public.advances (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_id uuid not null references public.employees(id) on delete cascade,
  date date not null default current_date,
  amount numeric(12,2) not null check (amount >= 0),
  installment numeric(12,2) not null check (installment >= 0),
  start_month text not null,
  recovered numeric(12,2) not null default 0,
  status text not null default 'Active' check (status in ('Active','Settled')),
  reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.payroll_runs (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  month text not null,
  status text not null default 'Draft' check (status in ('Draft','Approved','Paid')),
  employees_count int default 0,
  total_gross numeric(14,2) default 0,
  total_net numeric(14,2) default 0,
  paid_on date, notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, month)
);

create table if not exists public.payroll_items (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  run_id uuid not null references public.payroll_runs(id) on delete cascade,
  employee_id uuid references public.employees(id) on delete set null,
  project_id uuid references public.projects(id) on delete set null,
  basic numeric(12,2) default 0, housing numeric(12,2) default 0,
  transport numeric(12,2) default 0, other_allowance numeric(12,2) default 0,
  overtime_hours numeric(6,2) default 0, overtime_amount numeric(12,2) default 0,
  absent_days numeric(5,1) default 0, absence_deduction numeric(12,2) default 0,
  advance_deduction numeric(12,2) default 0, other_deduction numeric(12,2) default 0,
  bonus numeric(12,2) default 0,
  gross numeric(12,2) default 0, net numeric(12,2) default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.eos_settlements (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  employee_id uuid references public.employees(id) on delete set null,
  last_working_day date not null,
  reason text not null,
  service_years numeric(6,2), wage_base numeric(12,2),
  eos_full numeric(14,2), eos_factor numeric(5,4), eos_amount numeric(14,2),
  leave_balance_days numeric(6,2), leave_encashment numeric(14,2),
  other_dues numeric(14,2) default 0, advance_deduction numeric(14,2) default 0, other_deductions numeric(14,2) default 0,
  net_payable numeric(14,2),
  status text not null default 'Draft' check (status in ('Draft','Approved','Paid')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Procurement & stores
-- ---------------------------------------------------------------------------
create table if not exists public.suppliers (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  name text not null, category text,
  contact_person text, phone text, email text, vat_number text, address text,
  status text not null default 'Active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.purchase_orders (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  number text not null,
  date date not null default current_date,
  supplier_id uuid references public.suppliers(id) on delete set null,
  project_id uuid references public.projects(id) on delete set null,
  delivery_date date,
  status text not null default 'Draft' check (status in ('Draft','Ordered','Received','Paid','Cancelled')),
  items jsonb not null default '[]'::jsonb,
  subtotal numeric(14,2) default 0, vat numeric(14,2) default 0, total numeric(14,2) default 0,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, number)
);

create table if not exists public.materials (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  code text not null, name text not null, category text, unit text,
  quantity numeric(14,3) default 0, min_quantity numeric(14,3) default 0,
  unit_cost numeric(12,2) default 0, location text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, code)
);

create table if not exists public.equipment (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  code text not null, name text not null,
  type text default 'Vehicle' check (type in ('Vehicle','Machine','Tool')),
  plate_number text,
  project_id uuid references public.projects(id) on delete set null,
  employee_id uuid references public.employees(id) on delete set null,
  istimara_expiry date, insurance_expiry date,
  purchase_value numeric(14,2),
  status text not null default 'Available' check (status in ('In Use','Available','Under Maintenance','Disposed')),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, code)
);

-- ---------------------------------------------------------------------------
-- Finance & audit
-- ---------------------------------------------------------------------------
create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  date date not null default current_date,
  type text not null check (type in ('Income','Expense')),
  category text not null,
  project_id uuid references public.projects(id) on delete set null,
  amount numeric(14,2) not null check (amount >= 0),
  payment_method text, reference text, description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  at timestamptz not null default now(),
  user_name text, action text, table_name text, record_id text, summary text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
create index if not exists idx_employees_company on public.employees(company_id, status);
create index if not exists idx_employees_iqama_expiry on public.employees(iqama_expiry);
create index if not exists idx_attendance_date on public.attendance(company_id, date);
create index if not exists idx_payroll_items_run on public.payroll_items(run_id);
create index if not exists idx_documents_expiry on public.employee_documents(expiry_date);
create index if not exists idx_transactions_date on public.transactions(company_id, date);
create index if not exists idx_invoices_status on public.invoices(company_id, status);
create index if not exists idx_audit_at on public.audit_logs(company_id, at desc);

-- ---------------------------------------------------------------------------
-- Triggers: updated_at, company default, sign-up hook
-- ---------------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array['companies','profiles','settings','clients','projects','quotations','invoices','employees','employee_documents','attendance','leaves','advances','payroll_runs','payroll_items','eos_settlements','suppliers','purchase_orders','materials','equipment','transactions','audit_logs']
  loop
    execute format('drop trigger if exists trg_%1$s_updated on public.%1$s', t);
    execute format('create trigger trg_%1$s_updated before update on public.%1$s for each row execute function public.set_updated_at()', t);
    if t <> 'companies' then
      execute format('alter table public.%1$s alter column company_id set default public.current_company_id()', t);
    end if;
  end loop;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Row level security
-- read:  which roles may see the table      write: which roles may change it
-- ---------------------------------------------------------------------------
alter table public.companies enable row level security;
drop policy if exists companies_read on public.companies;
create policy companies_read on public.companies for select using (id = public.current_company_id());
drop policy if exists companies_write on public.companies;
create policy companies_write on public.companies for update using (id = public.current_company_id() and public.has_role(array['admin']));

create or replace function public.apply_policies(t text, read_roles text[], write_roles text[]) returns void
language plpgsql as $$
begin
  execute format('alter table public.%I enable row level security', t);
  execute format('drop policy if exists %I on public.%I', t || '_read', t);
  execute format('drop policy if exists %I on public.%I', t || '_insert', t);
  execute format('drop policy if exists %I on public.%I', t || '_update', t);
  execute format('drop policy if exists %I on public.%I', t || '_delete', t);
  execute format('create policy %I on public.%I for select using (company_id = public.current_company_id() and public.has_role(%L))', t || '_read', t, read_roles);
  execute format('create policy %I on public.%I for insert with check (company_id = public.current_company_id() and public.has_role(%L))', t || '_insert', t, write_roles);
  execute format('create policy %I on public.%I for update using (company_id = public.current_company_id() and public.has_role(%L)) with check (company_id = public.current_company_id())', t || '_update', t, write_roles);
  execute format('create policy %I on public.%I for delete using (company_id = public.current_company_id() and public.has_role(%L))', t || '_delete', t, write_roles);
end $$;

select public.apply_policies('profiles',           array['admin','manager','hr','accountant','foreman','viewer'], array['admin']);
select public.apply_policies('settings',           array['admin','manager','hr','accountant','foreman','viewer'], array['admin']);
select public.apply_policies('clients',            array['admin','manager','accountant','hr','foreman','viewer'], array['admin','manager','accountant']);
select public.apply_policies('projects',           array['admin','manager','hr','accountant','foreman','viewer'], array['admin','manager']);
select public.apply_policies('quotations',         array['admin','manager','accountant'], array['admin','manager','accountant']);
select public.apply_policies('invoices',           array['admin','manager','accountant'], array['admin','accountant']);
select public.apply_policies('employees',          array['admin','manager','hr','accountant','foreman'], array['admin','hr']);
select public.apply_policies('employee_documents', array['admin','hr'], array['admin','hr']);
select public.apply_policies('attendance',         array['admin','manager','hr','accountant','foreman'], array['admin','manager','hr','foreman']);
select public.apply_policies('leaves',             array['admin','manager','hr','accountant'], array['admin','hr']);
select public.apply_policies('advances',           array['admin','hr','accountant'], array['admin','hr','accountant']);
select public.apply_policies('payroll_runs',       array['admin','hr','accountant'], array['admin','accountant']);
select public.apply_policies('payroll_items',      array['admin','hr','accountant'], array['admin','accountant']);
select public.apply_policies('eos_settlements',    array['admin','hr','accountant'], array['admin','hr']);
select public.apply_policies('suppliers',          array['admin','manager','accountant'], array['admin','manager','accountant']);
select public.apply_policies('purchase_orders',    array['admin','manager','accountant'], array['admin','manager','accountant']);
select public.apply_policies('materials',          array['admin','manager','accountant','foreman'], array['admin','manager','foreman']);
select public.apply_policies('equipment',          array['admin','manager','hr','foreman'], array['admin','manager']);
select public.apply_policies('transactions',       array['admin','accountant','manager'], array['admin','accountant']);

-- Payroll marking "paid" updates advances and writes a salary expense; allow the accountant those writes.
drop policy if exists advances_update on public.advances;
create policy advances_update on public.advances for update
  using (company_id = public.current_company_id() and public.has_role(array['admin','hr','accountant']))
  with check (company_id = public.current_company_id());

-- Audit log: everyone signed in may append; only the admin may read. Nobody may edit or delete.
alter table public.audit_logs enable row level security;
drop policy if exists audit_insert on public.audit_logs;
create policy audit_insert on public.audit_logs for insert with check (company_id = public.current_company_id());
drop policy if exists audit_read on public.audit_logs;
create policy audit_read on public.audit_logs for select using (company_id = public.current_company_id() and public.has_role(array['admin']));

-- Users must be able to read their own profile even before a role check succeeds.
drop policy if exists profiles_self on public.profiles;
create policy profiles_self on public.profiles for select using (user_id = auth.uid());
-- Shahin ERP v1.1 — property & household, employee accounts, business development,
-- attendance times, employee photos, employee self-service (read only), two-step-ready settings.
-- Run after 20261025000000_shahin_erp_schema.sql.

-- ---------------- existing tables: new columns ----------------
alter table public.attendance add column if not exists time_in text;
alter table public.attendance add column if not exists time_out text;
alter table public.employees add column if not exists photo text;
alter table public.employees add column if not exists photo_url text;
alter table public.employees add column if not exists whatsapp text;
alter table public.employees add column if not exists auto_attendance boolean not null default true;

alter table public.settings add column if not exists national_unified_no text default '7051219199';
alter table public.settings add column if not exists phone_2 text default '';
alter table public.settings add column if not exists phone_3 text default '';
alter table public.settings add column if not exists whatsapp text default '';
alter table public.settings add column if not exists tagline text default 'Building Solutions. Delivering Trust.';
alter table public.settings add column if not exists owner_name text default '';
alter table public.settings add column if not exists auto_attendance boolean not null default true;
alter table public.settings add column if not exists auto_attendance_last date;
alter table public.settings add column if not exists default_time_in text default '07:00';
alter table public.settings add column if not exists default_time_out text default '16:00';
alter table public.settings add column if not exists break_minutes int default 60;
alter table public.settings add column if not exists weekly_off_day int default 5;
alter table public.settings add column if not exists property_currency text default 'PKR';
alter table public.settings add column if not exists marla_sqft numeric(8,2) default 272.25;
alter table public.settings add column if not exists bigha_in_kanal numeric(6,2) default 4;
alter table public.settings add column if not exists backup_every_hours int default 2;
alter table public.settings add column if not exists backup_keep int default 60;
alter table public.settings add column if not exists verify_base text;
-- desktop-only lock fields (unused online; online sign-in uses Supabase Auth with authenticator MFA)
alter table public.settings add column if not exists lock_hash text;
alter table public.settings add column if not exists lock_salt text;
alter table public.settings add column if not exists lock_minutes int default 15;
alter table public.settings add column if not exists totp_secret text;
alter table public.settings add column if not exists totp_enabled boolean default false;

alter table public.profiles add column if not exists employee_id uuid references public.employees(id) on delete set null;
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('admin','manager','hr','accountant','foreman','viewer','employee'));

-- ---------------- new tables ----------------
create table if not exists public.employee_transactions (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  employee_id uuid not null references public.employees(id) on delete cascade,
  date date not null default current_date,
  type text not null,
  amount numeric(12,2) not null check (amount >= 0),
  method text, description text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.properties (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  code text not null, name text not null, type text, status text, location text, country text,
  area numeric(14,3), area_unit text, area_acres numeric(14,4),
  khasra_number text, registry_number text, owner text, share_pct numeric(5,2) default 100,
  purchase_date date, purchase_value numeric(16,2), current_value numeric(16,2), currency text default 'PKR', notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (company_id, code)
);

create table if not exists public.rental_agreements (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  property_id uuid references public.properties(id) on delete set null,
  tenant_name text not null, tenant_id_number text, mobile text,
  monthly_rent numeric(14,2) not null default 0, currency text default 'PKR', security_deposit numeric(14,2),
  due_day int default 5, start_date date, end_date date, annual_increase_pct numeric(5,2),
  status text not null default 'Active', notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.rent_payments (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  agreement_id uuid references public.rental_agreements(id) on delete cascade,
  month text not null, amount_due numeric(14,2), amount_received numeric(14,2),
  date date, method text, reference text, status text, notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.crop_seasons (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  property_id uuid references public.properties(id) on delete set null,
  crop text, season text, year int, label text, area_acres numeric(10,2), arrangement text, farmer_name text,
  owner_share_pct numeric(5,2), lease_amount numeric(14,2), sowing_date date, harvest_date date,
  yield_qty numeric(12,2), yield_unit text, status text, notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.property_transactions (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  date date not null default current_date,
  type text not null check (type in ('Income','Expense')),
  category text not null,
  scope text not null default 'Property' check (scope in ('Property','Agriculture','Household')),
  property_id uuid references public.properties(id) on delete set null,
  season_id uuid references public.crop_seasons(id) on delete set null,
  amount numeric(14,2) not null check (amount >= 0), currency text default 'PKR',
  member text, paid_by text, description text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.prospects (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  name text not null, arabic_name text, industry text, city text, industrial_area text, website text, potential_services text,
  contact_person text, contact_position text, department text, public_email text, procurement_email text, phone text, whatsapp text, source text,
  status text default 'New', priority text default 'Normal', verification text default 'Pending',
  requirement_stated boolean default false, responded boolean default false, meeting_scheduled boolean default false, do_not_contact boolean default false,
  last_contact_date date, next_follow_up date, score int default 0, score_reasons text, notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.outreach (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  prospect_id uuid references public.prospects(id) on delete cascade,
  date date not null default current_date, channel text, to_address text, follow_up_no text, status text default 'Sent',
  subject text, body text, notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.opportunities (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  title text not null, prospect_id uuid references public.prospects(id) on delete set null,
  service text, location text, value numeric(14,2), deadline date, stage text default 'Requirement Received',
  quotation_id uuid references public.quotations(id) on delete set null, notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.email_templates (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  name text not null, channel text default 'Email', subject text, body text not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.gallery (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  title text, category text, image text not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

do $$
declare t text;
begin
  foreach t in array array['employee_transactions','properties','rental_agreements','rent_payments','crop_seasons','property_transactions','prospects','outreach','opportunities','email_templates','gallery']
  loop
    execute format('drop trigger if exists trg_%1$s_updated on public.%1$s', t);
    execute format('create trigger trg_%1$s_updated before update on public.%1$s for each row execute function public.set_updated_at()', t);
  end loop;
end $$;

-- ---------------- security ----------------
-- the owner's personal property & household records: admin only
select public.apply_policies('properties',            array['admin'], array['admin']);
select public.apply_policies('rental_agreements',     array['admin'], array['admin']);
select public.apply_policies('rent_payments',         array['admin'], array['admin']);
select public.apply_policies('crop_seasons',          array['admin'], array['admin']);
select public.apply_policies('property_transactions', array['admin'], array['admin']);
-- employee accounts and business development
select public.apply_policies('employee_transactions', array['admin','hr','accountant'], array['admin','hr','accountant']);
select public.apply_policies('prospects',             array['admin','manager'], array['admin','manager']);
select public.apply_policies('outreach',              array['admin','manager'], array['admin','manager']);
select public.apply_policies('opportunities',         array['admin','manager','accountant'], array['admin','manager']);
select public.apply_policies('email_templates',       array['admin','manager'], array['admin']);
select public.apply_policies('gallery',               array['admin','manager','hr','accountant','foreman','viewer'], array['admin','manager']);

-- ---------------- employee self-service: see only your own records, change nothing ----------------
create or replace function public.current_employee_id() returns uuid
language sql stable security definer set search_path = public as $$
  select employee_id from public.profiles where user_id = auth.uid() and status = 'Active' and role = 'employee' limit 1
$$;

do $$
declare t text;
begin
  -- tables keyed by employee_id
  foreach t in array array['attendance','payroll_items','advances','employee_transactions','eos_settlements','leaves']
  loop
    execute format('drop policy if exists %I on public.%I', t || '_self', t);
    execute format('create policy %I on public.%I for select using (company_id = public.current_company_id() and employee_id = public.current_employee_id())', t || '_self', t);
  end loop;
end $$;
drop policy if exists employees_self on public.employees;
create policy employees_self on public.employees for select using (company_id = public.current_company_id() and id = public.current_employee_id());
drop policy if exists payroll_runs_self on public.payroll_runs;
create policy payroll_runs_self on public.payroll_runs for select using (
  company_id = public.current_company_id() and public.current_employee_id() is not null
  and exists (select 1 from public.payroll_items i where i.run_id = payroll_runs.id and i.employee_id = public.current_employee_id()));
-- settings stay readable (company name, currency); profiles: own row via profiles_self

-- ---------------- online document verification (optional, tamper-proof) ----------------
-- Lets the website verify page look up an issued document by its number without exposing other data.
create table if not exists public.issued_documents (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  doc_type text not null, reference text, person_or_client text, summary jsonb, issued_on date default current_date,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
select public.apply_policies('issued_documents', array['admin','hr','accountant','manager'], array['admin','hr','accountant','manager']);
create or replace function public.verify_document(doc_id uuid) returns table (doc_type text, reference text, person_or_client text, summary jsonb, issued_on date)
language sql stable security definer set search_path = public as $$
  select doc_type, reference, person_or_client, summary, issued_on from public.issued_documents where id = doc_id
$$;
grant execute on function public.verify_document(uuid) to anon, authenticated;

-- printing preferences (used by the desktop edition; harmless online)
alter table public.settings add column if not exists direct_print boolean default true;
alter table public.settings add column if not exists printer_name text default '';
alter table public.settings add column if not exists print_copies int default 1;
-- Shahin ERP v1.3: daily wages by trade, recycle bin, owner code / recovery, client portfolios.

-- daily-wage workers
alter table public.employees add column if not exists trade text;
alter table public.employees add column if not exists pay_type text default 'Daily wage';
alter table public.employees add column if not exists daily_rate numeric(12,2);
alter table public.employees add column if not exists ot_rate numeric(12,2);

create table if not exists public.wage_rates (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  trade text not null, daily_rate numeric(12,2) not null default 0, ot_rate numeric(12,2), notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (company_id, trade)
);

-- recycle bin: deleted records are kept here until removed for good
create table if not exists public.recycle_bin (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null default public.current_company_id() references public.companies(id) on delete cascade,
  table_name text not null, record_id text not null, summary text, record jsonb not null,
  deleted_by text, deleted_at timestamptz not null default now(),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

-- owner code, recovery key and owner profile
alter table public.settings add column if not exists owner_code_hash text;
alter table public.settings add column if not exists owner_code_salt text;
alter table public.settings add column if not exists recovery_hash text;
alter table public.settings add column if not exists recovery_salt text;
alter table public.settings add column if not exists recovery_created timestamptz;
alter table public.settings add column if not exists owner_title text;
alter table public.settings add column if not exists owner_phone text;
alter table public.settings add column if not exists owner_email text;
alter table public.settings add column if not exists owner_photo text;

-- client portfolios: photos belong to the client and project they show
alter table public.gallery add column if not exists client_id uuid references public.clients(id) on delete set null;
alter table public.gallery add column if not exists project_id uuid references public.projects(id) on delete set null;
alter table public.gallery add column if not exists description text;
alter table public.gallery add column if not exists in_portfolio boolean not null default true;
create index if not exists gallery_client_idx on public.gallery(company_id, client_id);
alter table public.clients add column if not exists portfolio_summary text;
alter table public.clients add column if not exists portfolio_cover uuid;

do $$
declare t text;
begin
  foreach t in array array['wage_rates','recycle_bin']
  loop
    execute format('drop trigger if exists trg_%1$s_updated on public.%1$s', t);
    execute format('create trigger trg_%1$s_updated before update on public.%1$s for each row execute function public.set_updated_at()', t);
  end loop;
end $$;

select public.apply_policies('wage_rates',  array['admin','manager','hr','accountant','foreman','viewer'], array['admin','hr']);
-- everyone who can delete moves rows into the bin; only the owner can see, restore or empty it
select public.apply_policies('recycle_bin', array['admin'], array['admin']);
drop policy if exists recycle_bin_insert on public.recycle_bin;
create policy recycle_bin_insert on public.recycle_bin for insert to authenticated
  with check (company_id = public.current_company_id() and public.has_role(array['admin','manager','hr','accountant','foreman']));
-- Shahin ERP: move data from the desktop / phone edition into the online database in one step.
-- Called by the owner from Settings > Go online. Every row keeps its id (already converted to uuid by the app),
-- unknown fields are ignored, and rows that already exist are left as they are (safe to run twice).

create or replace function public.import_company_data(payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_company uuid := public.current_company_id();
  t text;
  r jsonb;
  n int;
  result jsonb := '{}'::jsonb;
  -- parents before children, so links between records are valid
  allowed text[] := array[
    'clients','suppliers','projects','employees','wage_rates','materials','equipment','employee_documents','attendance',
    'leaves','advances','payroll_runs','payroll_items','eos_settlements','employee_transactions','quotations','invoices',
    'purchase_orders','transactions','properties','rental_agreements','rent_payments','crop_seasons','property_transactions',
    'prospects','opportunities','outreach','email_templates','gallery','recycle_bin','audit_logs'];
  waiting jsonb := '[]'::jsonb;
  item jsonb;
  pass int;
  failed int := 0;
begin
  if v_company is null or not public.has_role(array['admin']) then
    raise exception 'Only the owner can import data';
  end if;

  -- company settings: the imported values replace the defaults (sign-in secrets of the device are not imported)
  if payload ? 'settings' and jsonb_array_length(payload->'settings') > 0 then
    r := (payload->'settings'->0) - 'id' - 'company_id' - 'created_at' - 'updated_at'
         - 'lock_hash' - 'lock_salt' - 'totp_secret' - 'totp_enabled' - 'recovery_hash' - 'recovery_salt' - 'recovery_created';
    execute (
      select 'update public.settings set ' || string_agg(format('%I = x.%I', c.column_name, c.column_name), ', ')
             || ' from jsonb_populate_record(null::public.settings, $1) x where settings.company_id = $2'
        from information_schema.columns c
       where c.table_schema = 'public' and c.table_name = 'settings' and r ? c.column_name
    ) using r, v_company;
    result := result || jsonb_build_object('settings', 1);
  end if;

  foreach t in array allowed loop
    continue when not (payload ? t);
    n := 0;
    for r in select * from jsonb_array_elements(payload->t) loop
      r := r || jsonb_build_object(
        'company_id', v_company,
        'created_at', coalesce(r->>'created_at', now()::text),
        'updated_at', coalesce(r->>'updated_at', r->>'created_at', now()::text));
      begin
        execute format(
          'insert into public.%I select (jsonb_populate_record(null::public.%I, $1)).* on conflict (id) do nothing', t, t)
          using r;
        n := n + 1;
      exception when others then
        -- e.g. it points to a record that comes later: try again after the rest
        waiting := waiting || jsonb_build_array(jsonb_build_object('t', t, 'r', r));
      end;
    end loop;
    result := result || jsonb_build_object(t, n);
  end loop;

  for pass in 1..3 loop
    exit when jsonb_array_length(waiting) = 0;
    item := waiting;
    waiting := '[]'::jsonb;
    for r in select * from jsonb_array_elements(item) loop
      begin
        execute format(
          'insert into public.%I select (jsonb_populate_record(null::public.%I, $1)).* on conflict (id) do nothing', r->>'t', r->>'t')
          using r->'r';
        result := jsonb_set(result, array[r->>'t'], to_jsonb(coalesce((result->>(r->>'t'))::int, 0) + 1));
      exception when others then
        waiting := waiting || jsonb_build_array(r);
      end;
    end loop;
  end loop;

  -- anything still not accepted is kept whole in the recycle bin, so nothing is lost
  for r in select * from jsonb_array_elements(waiting) loop
    insert into public.recycle_bin (company_id, table_name, record_id, summary, record, deleted_by)
    values (v_company, r->>'t', coalesce(r->'r'->>'id', ''), 'Could not import automatically — restore or re-enter', r->'r', 'Import');
    failed := failed + 1;
  end loop;
  result := result || jsonb_build_object('kept_in_recycle_bin', failed);
  return result;
end $$;

revoke all on function public.import_company_data(jsonb) from public;
grant execute on function public.import_company_data(jsonb) to authenticated;

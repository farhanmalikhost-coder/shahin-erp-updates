-- Shahin ERP 1.11: authentic document verification. Every printed document is registered online with a
-- random code; its QR opens erp.shahincontracting.com/#/v/<code>, which checks the code against this table.

create table if not exists public.issued_documents (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  code text not null unique,
  doc_type text not null,
  doc_ref text,
  number text,
  party_name text,
  person_code text,
  period text,
  facts jsonb not null default '[]'::jsonb,
  content_hash text not null,
  status text not null default 'Valid',
  issued_by text,
  issued_at timestamptz not null default now()
);
create index if not exists issued_documents_ref on public.issued_documents (company_id, doc_type, doc_ref);
alter table public.issued_documents enable row level security;
drop policy if exists issued_documents_read on public.issued_documents;
create policy issued_documents_read on public.issued_documents for select to authenticated using (company_id = public.current_company_id());
drop policy if exists issued_documents_admin on public.issued_documents;
create policy issued_documents_admin on public.issued_documents for update to authenticated using (company_id = public.current_company_id() and public.has_role(array['admin','accountant','hr']));

-- Register a document when it is printed. Same content again -> same code. Changed content -> new code,
-- and the older version is marked Superseded (its QR then says a newer version exists).
create or replace function public.register_document(p_doc_type text, p_doc_ref text, p_number text, p_party text, p_person_code text, p_period text, p_facts jsonb, p_hash text)
returns text
language plpgsql security definer set search_path = public, extensions as $$
declare
  me public.profiles;
  v_code text;
  abc constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  i int;
begin
  select * into me from public.profiles where user_id = auth.uid() and status = 'Active';
  if me.id is null then raise exception 'Not signed in'; end if;
  if coalesce(p_hash, '') = '' or p_doc_type is null then raise exception 'Missing document details'; end if;
  select code into v_code from public.issued_documents
   where company_id = me.company_id and doc_type = p_doc_type and doc_ref is not distinct from p_doc_ref and content_hash = p_hash and status = 'Valid'
   limit 1;
  if v_code is not null then return v_code; end if;
  update public.issued_documents set status = 'Superseded'
   where company_id = me.company_id and doc_type = p_doc_type and doc_ref is not distinct from p_doc_ref and status = 'Valid' and p_doc_ref is not null;
  loop
    v_code := '';
    for i in 1..10 loop
      v_code := v_code || substr(abc, 1 + (get_byte(gen_random_bytes(1), 0) % 32), 1);
    end loop;
    exit when not exists (select 1 from public.issued_documents where code = v_code);
  end loop;
  insert into public.issued_documents (company_id, code, doc_type, doc_ref, number, party_name, person_code, period, facts, content_hash, issued_by)
  values (me.company_id, v_code, p_doc_type, p_doc_ref, left(p_number, 80), left(p_party, 160), left(p_person_code, 40), left(p_period, 20), coalesce(p_facts, '[]'::jsonb), p_hash, me.full_name);
  return v_code;
end $$;

-- Public check (anyone scanning the QR). Returns only what is printed on the document itself.
create or replace function public.verify_document(p_code text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'doc_type', d.doc_type, 'number', d.number, 'party', d.party_name, 'person_code', d.person_code, 'period', d.period,
    'facts', d.facts, 'status', d.status, 'issued_at', d.issued_at,
    'company', s.company_name, 'company_ar', s.company_name_ar, 'cr', s.cr_number, 'vat', s.vat_number, 'website', s.website, 'phone', s.phone)
  from public.issued_documents d left join public.settings s on s.company_id = d.company_id
  where d.code = upper(trim(p_code)) and length(trim(p_code)) between 8 and 16
$$;

revoke all on function public.register_document(text, text, text, text, text, text, jsonb, text) from public, anon;
grant execute on function public.register_document(text, text, text, text, text, text, jsonb, text) to authenticated;
revoke all on function public.verify_document(text) from public;
grant execute on function public.verify_document(text) to anon, authenticated;

-- same two-step rule as every other table
drop policy if exists issued_documents_mfa on public.issued_documents;
create policy issued_documents_mfa on public.issued_documents as restrictive to authenticated using (
  array[coalesce(auth.jwt()->>'aal', 'aal1')] <@ (
    select case when count(*) > 0 then array['aal2'] else array['aal1','aal2'] end
      from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified'))
  with check (
  array[coalesce(auth.jwt()->>'aal', 'aal1')] <@ (
    select case when count(*) > 0 then array['aal2'] else array['aal1','aal2'] end
      from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified'));

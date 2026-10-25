-- Shahin ERP 1.9: rent / shop / land-lease khata, promised dates, tenant payment link, online quotation fields.

alter table public.rental_agreements add column if not exists kind text default 'Shop rent';
alter table public.rental_agreements add column if not exists billing text default 'Monthly';
alter table public.rental_agreements add column if not exists lease_total numeric(14,2);
alter table public.rental_agreements add column if not exists advance_amount numeric(14,2);
alter table public.rental_agreements add column if not exists advance_date date;
alter table public.rental_agreements add column if not exists promise_date date;
alter table public.rental_agreements add column if not exists promise_amount numeric(14,2);
alter table public.rental_agreements add column if not exists promise_set_on date;
alter table public.rental_agreements add column if not exists whatsapp text;
alter table public.rental_agreements add column if not exists portal_token text;
create unique index if not exists rental_agreements_portal_token on public.rental_agreements (portal_token) where portal_token is not null;
alter table public.rental_agreements alter column monthly_rent drop not null;

alter table public.rent_payments add column if not exists proof_image text;
alter table public.rent_payments add column if not exists source text default 'Office';
alter table public.rent_payments add column if not exists verified boolean default true;

alter table public.settings add column if not exists property_sender_name text;
alter table public.settings add column if not exists pay_bank_name text;
alter table public.settings add column if not exists pay_account_title text;
alter table public.settings add column if not exists pay_account_no text;
alter table public.settings add column if not exists pay_iban text;
alter table public.settings add column if not exists pay_raast_id text;
alter table public.settings add column if not exists pay_wallet text;
alter table public.settings add column if not exists rent_reminder_days int default 3;

alter table public.clients add column if not exists portal_name text;
alter table public.clients add column if not exists portal_url text;
alter table public.clients add column if not exists vendor_number text;
alter table public.clients add column if not exists vendor_status text;
alter table public.quotations add column if not exists submitted_via text;
alter table public.quotations add column if not exists portal_ref text;

-- The tenant's own page: only the one agreement that matches the secret link, nothing else.
create or replace function public.tenant_portal(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  a public.rental_agreements;
  r jsonb;
begin
  if p_token is null or length(p_token) < 12 then return null; end if;
  select * into a from public.rental_agreements where portal_token = p_token;
  if not found or a.status = 'Closed' then return null; end if;
  select jsonb_build_object(
    'agreement', to_jsonb(a) - 'company_id' - 'notes' - 'tenant_id_number' - 'portal_token',
    'property', (select name from public.properties p where p.id = a.property_id),
    'payments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'agreement_id', x.agreement_id, 'amount_received', x.amount_received, 'date', x.date, 'month', x.month, 'method', x.method, 'reference', x.reference, 'source', x.source, 'verified', x.verified) order by x.date)
                          from public.rent_payments x where x.agreement_id = a.id), '[]'::jsonb),
    'company', (select jsonb_build_object('company_name', s.company_name, 'sender', coalesce(nullif(s.property_sender_name, ''), s.owner_name),
                  'pay_bank_name', s.pay_bank_name, 'pay_account_title', s.pay_account_title, 'pay_account_no', s.pay_account_no,
                  'pay_iban', s.pay_iban, 'pay_raast_id', s.pay_raast_id, 'pay_wallet', s.pay_wallet)
                from public.settings s where s.company_id = a.company_id)
  ) into r;
  return r;
end $$;

-- The tenant sends a payment (screenshot and/or transaction id). It counts in the khata at once, marked "to confirm".
create or replace function public.tenant_submit_payment(p_token text, p_amount numeric, p_date date, p_method text, p_reference text, p_note text, p_image text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  a public.rental_agreements;
  new_id uuid;
begin
  if p_token is null or length(p_token) < 12 then raise exception 'Invalid link'; end if;
  select * into a from public.rental_agreements where portal_token = p_token;
  if not found or a.status = 'Closed' then raise exception 'Invalid link'; end if;
  if p_amount is null or p_amount <= 0 or p_amount > 100000000 then raise exception 'Please enter the amount you paid'; end if;
  if p_image is null and coalesce(trim(p_reference), '') = '' then raise exception 'Add the receipt picture or the transaction ID'; end if;
  if p_image is not null and (length(p_image) > 2500000 or p_image not like 'data:image/%') then raise exception 'The picture is too large'; end if;
  if (select count(*) from public.rent_payments where agreement_id = a.id and verified = false and created_at > now() - interval '1 day') >= 10 then
    raise exception 'Too many receipts today. Please contact the owner.';
  end if;
  insert into public.rent_payments (company_id, agreement_id, month, amount_received, date, method, reference, notes, proof_image, source, verified, status)
  values (a.company_id, a.id, to_char(coalesce(p_date, current_date), 'YYYY-MM'), round(p_amount, 2), least(coalesce(p_date, current_date), current_date),
          left(p_method, 40), left(p_reference, 80), left(p_note, 300), p_image, 'Tenant (online)', false, 'To confirm')
  returning id into new_id;
  return new_id;
end $$;

revoke all on function public.tenant_portal(text) from public;
revoke all on function public.tenant_submit_payment(text, numeric, date, text, text, text, text) from public;
grant execute on function public.tenant_portal(text) to anon, authenticated;
grant execute on function public.tenant_submit_payment(text, numeric, date, text, text, text, text) to anon, authenticated;

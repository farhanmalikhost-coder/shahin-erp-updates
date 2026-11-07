-- Tender / RFQ tracking: every procurement notice found anywhere in Saudi Arabia is kept as an Opportunity with its source.
alter table public.opportunities add column if not exists source text;
alter table public.opportunities add column if not exists source_link text;
alter table public.opportunities add column if not exists tender_no text;
alter table public.opportunities add column if not exists entity_type text;
alter table public.opportunities add column if not exists city text;

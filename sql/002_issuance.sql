-- =============================================================================
-- 002_issuance.sql — Etapa 4: colunas de emissão em lote (Supabase / PostgreSQL 15+)
-- Execute no SQL Editor DEPOIS de 001_schema.sql. O script é idempotente.
-- =============================================================================

begin;

alter table public.certificates
    add column if not exists recipient_doc      text,
    add column if not exists role               text not null default 'Participante',
    add column if not exists event_date_label   text,
    add column if not exists signer_fingerprint text,
    add column if not exists signer_serial      text;

comment on column public.certificates.recipient_doc is
    'Documento do titular já MASCARADO para exibição (ex.: ***.456.789-**). Nunca grave CPF em claro.';
comment on column public.certificates.signer_fingerprint is
    'SHA-256 (hex com ":" maiúsculo) do certificado X.509 que assinou o PDF.';

do $$
begin
    if not exists (select 1 from pg_constraint
                   where conname = 'certificates_recipient_doc_len'
                     and conrelid = 'public.certificates'::regclass) then
        alter table public.certificates add constraint certificates_recipient_doc_len
            check (recipient_doc is null or char_length(recipient_doc) <= 40);
    end if;

    if not exists (select 1 from pg_constraint
                   where conname = 'certificates_role_len'
                     and conrelid = 'public.certificates'::regclass) then
        alter table public.certificates add constraint certificates_role_len
            check (char_length(btrim(role)) between 1 and 80);
    end if;

    if not exists (select 1 from pg_constraint
                   where conname = 'certificates_event_date_label_len'
                     and conrelid = 'public.certificates'::regclass) then
        alter table public.certificates add constraint certificates_event_date_label_len
            check (event_date_label is null or char_length(event_date_label) <= 100);
    end if;

    if not exists (select 1 from pg_constraint
                   where conname = 'certificates_signer_fingerprint_fmt'
                     and conrelid = 'public.certificates'::regclass) then
        alter table public.certificates add constraint certificates_signer_fingerprint_fmt
            check (signer_fingerprint is null
                   or signer_fingerprint ~ '^([0-9A-F]{2}:){31}[0-9A-F]{2}$');
    end if;

    if not exists (select 1 from pg_constraint
                   where conname = 'certificates_signer_serial_len'
                     and conrelid = 'public.certificates'::regclass) then
        alter table public.certificates add constraint certificates_signer_serial_len
            check (signer_serial is null or char_length(signer_serial) <= 64);
    end if;
end
$$;

create index if not exists certificates_signer_fingerprint_idx
    on public.certificates (signer_fingerprint)
    where signer_fingerprint is not null;

-- O certificado assinante passa a fazer parte dos campos imutáveis após a emissão.
create or replace function public.certificates_protect_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    if new.id is distinct from old.id
       or new.batch_id is distinct from old.batch_id
       or new.pdf_sha256 is distinct from old.pdf_sha256
       or new.storage_bucket is distinct from old.storage_bucket
       or new.storage_key is distinct from old.storage_key
       or new.signed_at is distinct from old.signed_at
       or new.created_at is distinct from old.created_at
       or new.signer_fingerprint is distinct from old.signer_fingerprint
       or new.signer_serial is distinct from old.signer_serial then
        raise exception 'Campos de identidade/assinatura do certificado são imutáveis'
            using errcode = '23514';
    end if;
    return new;
end;
$$;

commit;

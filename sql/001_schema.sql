-- =============================================================================
-- 001_schema.sql — Plataforma de certificados (Supabase / PostgreSQL 15+)
-- Execute no SQL Editor do Supabase. O script é idempotente.
-- =============================================================================

begin;

-- -----------------------------------------------------------------------------
-- Tipos
-- -----------------------------------------------------------------------------
do $$
begin
    if not exists (
        select 1 from pg_type t
        join pg_namespace n on n.oid = t.typnamespace
        where t.typname = 'certificate_status' and n.nspname = 'public'
    ) then
        create type public.certificate_status as enum ('valid', 'revoked');
    end if;
end
$$;

-- -----------------------------------------------------------------------------
-- Tabela principal: certificados emitidos
-- -----------------------------------------------------------------------------
create table if not exists public.certificates (
    id                 uuid primary key,
    batch_id           uuid not null,
    participant_name   text not null
        check (char_length(btrim(participant_name)) between 1 and 300),
    participant_email  text
        check (participant_email is null or char_length(participant_email) <= 320),
    event_name         text not null
        check (char_length(btrim(event_name)) between 1 and 300),
    workload_hours     numeric(6, 2)
        check (workload_hours is null or workload_hours >= 0),
    issued_at          timestamptz not null default now(),
    metadata           jsonb not null default '{}'::jsonb
        check (jsonb_typeof(metadata) = 'object'),
    pdf_sha256         text not null
        check (pdf_sha256 ~ '^[0-9a-f]{64}$'),
    storage_bucket     text not null,
    storage_key        text not null,
    signed_at          timestamptz not null default now(),
    status             public.certificate_status not null default 'valid',
    revoked_at         timestamptz,
    revoked_reason     text,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),

    -- O id gerado pela aplicação deve ser um UUID v4 (nibble de versão = 4).
    constraint certificates_id_is_uuid_v4
        check (substr(id::text, 15, 1) = '4'),
    -- Um mesmo PDF assinado (hash) só pode existir uma vez: base da validação por arquivo.
    constraint certificates_pdf_sha256_key unique (pdf_sha256),
    constraint certificates_storage_object_key unique (storage_bucket, storage_key),
    constraint certificates_revocation_consistency
        check ((status = 'revoked') = (revoked_at is not null))
);

comment on table public.certificates is
    'Metadados dos certificados emitidos e assinados (PAdES). O PDF fica no object storage.';
comment on column public.certificates.pdf_sha256 is
    'SHA-256 (hex minúsculo) do PDF já assinado, usado na validação por upload.';

-- -----------------------------------------------------------------------------
-- Índices
-- -----------------------------------------------------------------------------
-- A busca por hash já é coberta pelo índice único certificates_pdf_sha256_key.
create index if not exists certificates_batch_id_idx
    on public.certificates (batch_id);

create index if not exists certificates_participant_email_idx
    on public.certificates (lower(participant_email))
    where participant_email is not null;

create index if not exists certificates_issued_at_idx
    on public.certificates (issued_at desc);

create index if not exists certificates_metadata_gin_idx
    on public.certificates using gin (metadata jsonb_path_ops);

create index if not exists certificates_not_valid_idx
    on public.certificates (revoked_at desc)
    where status <> 'valid';

-- -----------------------------------------------------------------------------
-- Tabela de auditoria (append-only)
-- -----------------------------------------------------------------------------
create table if not exists public.certificate_audit_log (
    id              bigint generated always as identity primary key,
    certificate_id  uuid references public.certificates (id) on delete restrict,
    action          text not null
        check (action in (
            'issued', 'validate_code', 'validate_file', 'presigned_url', 'revoked'
        )),
    outcome         text not null
        check (outcome in ('success', 'not_found', 'invalid', 'error')),
    client_ip_hash  text,
    user_agent      text
        check (user_agent is null or char_length(user_agent) <= 512),
    details         jsonb not null default '{}'::jsonb
        check (jsonb_typeof(details) = 'object'),
    created_at      timestamptz not null default now()
);

comment on table public.certificate_audit_log is
    'Trilha de auditoria imutável. certificate_id é nulo quando o arquivo validado não corresponde a nenhum certificado.';
comment on column public.certificate_audit_log.client_ip_hash is
    'Hash (com salt da aplicação) do IP do cliente; nunca armazene o IP em claro (LGPD).';

create index if not exists certificate_audit_log_cert_idx
    on public.certificate_audit_log (certificate_id, created_at desc);

create index if not exists certificate_audit_log_created_at_idx
    on public.certificate_audit_log (created_at desc);

-- -----------------------------------------------------------------------------
-- Funções e gatilhos
-- -----------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

drop trigger if exists certificates_set_updated_at on public.certificates;
create trigger certificates_set_updated_at
    before update on public.certificates
    for each row execute function public.set_updated_at();

-- Campos que identificam o PDF assinado não podem mudar após a emissão.
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
       or new.created_at is distinct from old.created_at then
        raise exception 'Campos de identidade/assinatura do certificado são imutáveis'
            using errcode = '23514';
    end if;
    return new;
end;
$$;

drop trigger if exists certificates_protect_immutable on public.certificates;
create trigger certificates_protect_immutable
    before update on public.certificates
    for each row execute function public.certificates_protect_immutable();

-- A auditoria só aceita INSERT.
create or replace function public.prevent_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    raise exception 'certificate_audit_log é append-only' using errcode = '42501';
end;
$$;

drop trigger if exists certificate_audit_log_no_update_delete on public.certificate_audit_log;
create trigger certificate_audit_log_no_update_delete
    before update or delete on public.certificate_audit_log
    for each row execute function public.prevent_audit_mutation();

drop trigger if exists certificate_audit_log_no_truncate on public.certificate_audit_log;
create trigger certificate_audit_log_no_truncate
    before truncate on public.certificate_audit_log
    for each statement execute function public.prevent_audit_mutation();

-- -----------------------------------------------------------------------------
-- Row Level Security
-- -----------------------------------------------------------------------------
-- O schema public é exposto pelo PostgREST do Supabase. Para que a chave anon
-- (pública) nunca leia estas tabelas diretamente, ativamos RLS, não criamos
-- nenhuma policy para anon/authenticated (negação por padrão) e revogamos os
-- privilégios. Todo acesso passa pela API FastAPI (conexão direta ou service_role).
alter table public.certificates enable row level security;
alter table public.certificate_audit_log enable row level security;

revoke all on table public.certificates from anon, authenticated;
revoke all on table public.certificate_audit_log from anon, authenticated;
revoke all on sequence public.certificate_audit_log_id_seq from anon, authenticated;

grant select, insert, update on table public.certificates to service_role;
grant select, insert on table public.certificate_audit_log to service_role;
grant usage on sequence public.certificate_audit_log_id_seq to service_role;

drop policy if exists certificates_service_role_all on public.certificates;
create policy certificates_service_role_all
    on public.certificates
    for all
    to service_role
    using (true)
    with check (true);

drop policy if exists certificate_audit_log_service_role_select on public.certificate_audit_log;
create policy certificate_audit_log_service_role_select
    on public.certificate_audit_log
    for select
    to service_role
    using (true);

drop policy if exists certificate_audit_log_service_role_insert on public.certificate_audit_log;
create policy certificate_audit_log_service_role_insert
    on public.certificate_audit_log
    for insert
    to service_role
    with check (true);

commit;

-- Blinky schema. GENERATED - do not edit by hand.
--
-- Regenerate with:
--     dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql
--
-- PostgreSQL runs this only against an empty data directory, so changing
-- the schema means `docker compose down -v` or a hand-written ALTER.

create table cardholders (
        id uuid not null,
       display_name varchar(255) not null,
       upn varchar(255),
       object_sid varchar(255),
       distinguished_name varchar(255),
       directory_source text not null,
       state text not null,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table tokens (
        id uuid not null,
       serial int8 not null unique,
       firmware_version varchar(255),
       form_factor varchar(255),
       attestation_thumbprint varchar(255),
       state text not null,
       cardholder_id uuid,
       management_key_algorithm varchar(255),
       management_key_version int4 not null,
       management_key_state text not null,
       pin_state text not null,
       puk_state text not null,
       biometric_state text not null,
       pin_retries_left int2,
       puk_retries_left int2,
       biometric_attempts_left int2,
       last_seen_at timestamptz,
       last_seen_agent_id uuid,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table slots (
        id uuid not null,
       token_id uuid not null,
       slot_id varchar(255) not null,
       state text not null,
       credential_id uuid,
       key_algorithm varchar(255),
       pin_policy varchar(255),
       touch_policy varchar(255),
       public_key_sha256 bytea,
       updated_at timestamptz not null,
       primary key (id)
    );

create table credentials (
        id uuid not null,
       token_id uuid not null,
       slot_id varchar(255) not null,
       profile_id uuid,
       ca_instance_id uuid,
       serial_number varchar(255),
       issuer_dn varchar(255),
       subject_dn varchar(255),
       not_before timestamptz,
       not_after timestamptz,
       public_key_sha256 bytea,
       attestation_id uuid,
       state text not null,
       supersedes_id uuid,
       revocation_reason varchar(255),
       revoked_at timestamptz,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table ca_instances (
        id uuid not null,
       name varchar(255) not null unique,
       backend text not null,
       topology text not null,
       configuration jsonb not null,
       certificate_chain_pem varchar(255),
       crl_url varchar(255),
       ocsp_url varchar(255),
       is_enabled boolean not null,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table certificate_profiles (
        id uuid not null,
       name varchar(255) not null unique,
       ca_instance_id uuid not null,
       slot_id varchar(255) not null,
       key_algorithm varchar(255) not null,
       required_pin_policy varchar(255),
       required_touch_policy varchar(255),
       validity_days int4 not null,
       subject_template varchar(255),
       san_template varchar(255),
       extended_key_usages jsonb not null,
       adcs_template_name varchar(255),
       is_enabled boolean not null,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table issuance_policies (
        id uuid not null,
       name varchar(255) not null unique,
       directory_group varchar(255),
       profile_names jsonb not null,
       allow_unrecoverable_tokens boolean not null,
       is_enabled boolean not null,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table agents (
        id uuid not null,
       hostname varchar(255) not null,
       domain varchar(255) not null,
       version varchar(255),
       client_certificate_thumbprint varchar(255),
       state text not null,
       last_heartbeat_at timestamptz,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table jobs (
        id uuid not null,
       type text not null,
       state text not null,
       token_serial int8,
       agent_id uuid,
       cardholder_id uuid,
       attempt int4 not null,
       idempotency_key varchar(255) not null unique,
       payload jsonb not null,
       result jsonb,
       lease_expires_at timestamptz,
       deadline_at timestamptz not null,
       created_at timestamptz not null,
       updated_at timestamptz not null,
       primary key (id)
    );

create table secret_envelopes (
        id uuid not null,
       token_id uuid not null,
       kind text not null,
       key_version int4 not null,
       ciphertext bytea not null,
       nonce bytea not null,
       tag bytea not null,
       associated_data varchar(255) not null,
       created_at timestamptz not null,
       primary key (id)
    );

create table audit_events (
        id uuid not null,
       occurred_at timestamptz not null,
       event_type varchar(255) not null,
       actor varchar(255),
       subject_type varchar(255),
       subject_id uuid,
       token_serial int8,
       detail jsonb not null,
       is_exempt_from_retention boolean not null,
       primary key (id)
    );

alter table tokens 
        add constraint FK_899BCD5E 
        foreign key (cardholder_id) 
        references cardholders;

alter table slots 
        add constraint FK_35E8A474 
        foreign key (token_id) 
        references tokens;

alter table slots 
        add constraint FK_D04B0BAD 
        foreign key (credential_id) 
        references credentials;

alter table credentials 
        add constraint FK_FBDEE7FE 
        foreign key (token_id) 
        references tokens;

alter table credentials 
        add constraint FK_8EC4DCF6 
        foreign key (profile_id) 
        references certificate_profiles;

alter table credentials 
        add constraint FK_A101DCE5 
        foreign key (ca_instance_id) 
        references ca_instances;

alter table credentials 
        add constraint FK_5DB8FEF0 
        foreign key (supersedes_id) 
        references credentials;

alter table certificate_profiles 
        add constraint FK_62B5CCF5 
        foreign key (ca_instance_id) 
        references ca_instances;

alter table secret_envelopes 
        add constraint FK_B6AC9663 
        foreign key (token_id) 
        references tokens;


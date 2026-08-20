using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace Blinky.Infrastructure.Mappings;

public sealed class CardholderMapping : ClassMapping<Cardholder>
{
    public CardholderMapping()
    {
        Table("cardholders");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.DisplayName, m => { m.Column("display_name"); m.NotNullable(true); });
        Property(x => x.Upn, m => m.Column("upn"));
        Property(x => x.ObjectSid, m => m.Column("object_sid"));
        Property(x => x.DistinguishedName, m => m.Column("distinguished_name"));
        Property(x => x.DirectorySource,
            m => Conventions.AsEnumString<DirectorySource>(m, "directory_source"));
        Property(x => x.State, m => Conventions.AsEnumString<CardholderState>(m, "state"));
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class TokenMapping : ClassMapping<Token>
{
    public TokenMapping()
    {
        Table("tokens");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Serial, m => { m.Column("serial"); m.NotNullable(true); m.Unique(true); });
        Property(x => x.FirmwareVersion, m => m.Column("firmware_version"));
        Property(x => x.FormFactor, m => m.Column("form_factor"));
        Property(x => x.AttestationThumbprint, m => m.Column("attestation_thumbprint"));
        Property(x => x.State, m => Conventions.AsEnumString<TokenState>(m, "state"));
        ManyToOne(x => x.Cardholder, m =>
        {
            m.Column("cardholder_id");
            m.Cascade(Cascade.None);
        });
        Property(x => x.ManagementKeyAlgorithm, m => m.Column("management_key_algorithm"));
        Property(x => x.ManagementKeyVersion,
            m => { m.Column("management_key_version"); m.NotNullable(true); });
        Property(x => x.ManagementKeyState,
            m => Conventions.AsEnumString<ManagementKeyState>(m, "management_key_state"));
        Property(x => x.PinState, m => Conventions.AsEnumString<CredentialSecretState>(m, "pin_state"));
        Property(x => x.PukState, m => Conventions.AsEnumString<CredentialSecretState>(m, "puk_state"));
        Property(x => x.BiometricState,
            m => Conventions.AsEnumString<BiometricState>(m, "biometric_state"));
        Property(x => x.PinRetriesLeft, m => m.Column("pin_retries_left"));
        Property(x => x.PukRetriesLeft, m => m.Column("puk_retries_left"));
        Property(x => x.BiometricAttemptsLeft, m => m.Column("biometric_attempts_left"));
        Property(x => x.LastSeenAt, m => Conventions.AsTimestamp(m, "last_seen_at", notNull: false));
        Property(x => x.LastSeenAgentId, m => m.Column("last_seen_agent_id"));
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class SlotMapping : ClassMapping<Slot>
{
    public SlotMapping()
    {
        Table("slots");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        ManyToOne(x => x.Token, m => { m.Column("token_id"); m.NotNullable(true); });
        Property(x => x.SlotId, m => { m.Column("slot_id"); m.NotNullable(true); });
        Property(x => x.State, m => Conventions.AsEnumString<SlotState>(m, "state"));
        ManyToOne(x => x.Credential, m => m.Column("credential_id"));
        Property(x => x.KeyAlgorithm, m => m.Column("key_algorithm"));
        Property(x => x.PinPolicy, m => m.Column("pin_policy"));
        Property(x => x.TouchPolicy, m => m.Column("touch_policy"));
        Property(x => x.PublicKeySha256, m => m.Column("public_key_sha256"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class CredentialMapping : ClassMapping<Credential>
{
    public CredentialMapping()
    {
        Table("credentials");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        ManyToOne(x => x.Token, m => { m.Column("token_id"); m.NotNullable(true); });
        Property(x => x.SlotId, m => { m.Column("slot_id"); m.NotNullable(true); });
        ManyToOne(x => x.Profile, m => m.Column("profile_id"));
        ManyToOne(x => x.CaInstance, m => m.Column("ca_instance_id"));
        Property(x => x.SerialNumber, m => m.Column("serial_number"));
        Property(x => x.IssuerDn, m => m.Column("issuer_dn"));
        Property(x => x.SubjectDn, m => m.Column("subject_dn"));
        Property(x => x.NotBefore, m => Conventions.AsTimestamp(m, "not_before", notNull: false));
        Property(x => x.NotAfter, m => Conventions.AsTimestamp(m, "not_after", notNull: false));
        Property(x => x.PublicKeySha256, m => m.Column("public_key_sha256"));
        Property(x => x.AttestationId, m => m.Column("attestation_id"));
        Property(x => x.State, m => Conventions.AsEnumString<CredentialState>(m, "state"));
        ManyToOne(x => x.Supersedes, m => m.Column("supersedes_id"));
        Property(x => x.RevocationReason, m => m.Column("revocation_reason"));
        Property(x => x.RevokedAt, m => Conventions.AsTimestamp(m, "revoked_at", notNull: false));
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class CaInstanceMapping : ClassMapping<CaInstance>
{
    public CaInstanceMapping()
    {
        Table("ca_instances");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Name, m => { m.Column("name"); m.NotNullable(true); m.Unique(true); });
        Property(x => x.Backend, m => Conventions.AsEnumString<CaBackend>(m, "backend"));
        Property(x => x.Topology, m => Conventions.AsEnumString<CaTopology>(m, "topology"));
        Property(x => x.Configuration, m => Conventions.AsJson(m, "configuration"));
        Property(x => x.CertificateChainPem, m => m.Column("certificate_chain_pem"));
        Property(x => x.CrlUrl, m => m.Column("crl_url"));
        Property(x => x.OcspUrl, m => m.Column("ocsp_url"));
        Property(x => x.IsEnabled, m => { m.Column("is_enabled"); m.NotNullable(true); });
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class CertificateProfileMapping : ClassMapping<CertificateProfile>
{
    public CertificateProfileMapping()
    {
        Table("certificate_profiles");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Name, m => { m.Column("name"); m.NotNullable(true); m.Unique(true); });
        ManyToOne(x => x.CaInstance, m => { m.Column("ca_instance_id"); m.NotNullable(true); });
        Property(x => x.SlotId, m => { m.Column("slot_id"); m.NotNullable(true); });
        Property(x => x.KeyAlgorithm, m => { m.Column("key_algorithm"); m.NotNullable(true); });
        Property(x => x.RequiredPinPolicy, m => m.Column("required_pin_policy"));
        Property(x => x.RequiredTouchPolicy, m => m.Column("required_touch_policy"));
        Property(x => x.ValidityDays, m => { m.Column("validity_days"); m.NotNullable(true); });
        Property(x => x.SubjectTemplate, m => m.Column("subject_template"));
        Property(x => x.SanTemplate, m => m.Column("san_template"));
        Property(x => x.ExtendedKeyUsages, m => Conventions.AsJson(m, "extended_key_usages"));
        Property(x => x.AdcsTemplateName, m => m.Column("adcs_template_name"));
        Property(x => x.IsEnabled, m => { m.Column("is_enabled"); m.NotNullable(true); });
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class IssuancePolicyMapping : ClassMapping<IssuancePolicy>
{
    public IssuancePolicyMapping()
    {
        Table("issuance_policies");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Name, m => { m.Column("name"); m.NotNullable(true); m.Unique(true); });
        Property(x => x.DirectoryGroup, m => m.Column("directory_group"));
        Property(x => x.ProfileNames, m => Conventions.AsJson(m, "profile_names"));
        Property(x => x.AllowUnrecoverableTokens,
            m => { m.Column("allow_unrecoverable_tokens"); m.NotNullable(true); });
        Property(x => x.IsEnabled, m => { m.Column("is_enabled"); m.NotNullable(true); });
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class AgentMapping : ClassMapping<Agent>
{
    public AgentMapping()
    {
        Table("agents");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Hostname, m => { m.Column("hostname"); m.NotNullable(true); });
        Property(x => x.Domain, m => { m.Column("domain"); m.NotNullable(true); });
        Property(x => x.Version, m => m.Column("version"));
        Property(x => x.ClientCertificateThumbprint,
            m => m.Column("client_certificate_thumbprint"));
        Property(x => x.State, m => Conventions.AsEnumString<AgentState>(m, "state"));
        Property(x => x.LastHeartbeatAt,
            m => Conventions.AsTimestamp(m, "last_heartbeat_at", notNull: false));
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class JobMapping : ClassMapping<Job>
{
    public JobMapping()
    {
        Table("jobs");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.Type, m => Conventions.AsEnumString<JobType>(m, "type"));
        Property(x => x.State, m => Conventions.AsEnumString<JobState>(m, "state"));
        Property(x => x.TokenSerial, m => m.Column("token_serial"));
        Property(x => x.AgentId, m => m.Column("agent_id"));
        Property(x => x.CardholderId, m => m.Column("cardholder_id"));
        Property(x => x.Attempt, m => { m.Column("attempt"); m.NotNullable(true); });
        Property(x => x.IdempotencyKey, m =>
        {
            m.Column("idempotency_key");
            m.NotNullable(true);
            m.Unique(true);
        });
        Property(x => x.Payload, m => Conventions.AsJson(m, "payload"));
        Property(x => x.Result, m => Conventions.AsJson(m, "result", notNull: false));
        Property(x => x.LeaseExpiresAt,
            m => Conventions.AsTimestamp(m, "lease_expires_at", notNull: false));
        Property(x => x.DeadlineAt, m => Conventions.AsTimestamp(m, "deadline_at"));
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
        Property(x => x.UpdatedAt, m => Conventions.AsTimestamp(m, "updated_at"));
    }
}

public sealed class SecretEnvelopeMapping : ClassMapping<SecretEnvelope>
{
    public SecretEnvelopeMapping()
    {
        Table("secret_envelopes");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        ManyToOne(x => x.Token, m => { m.Column("token_id"); m.NotNullable(true); });
        Property(x => x.Kind, m => Conventions.AsEnumString<SecretKind>(m, "kind"));
        Property(x => x.KeyVersion, m => { m.Column("key_version"); m.NotNullable(true); });
        Property(x => x.Ciphertext, m => { m.Column("ciphertext"); m.NotNullable(true); });
        Property(x => x.Nonce, m => { m.Column("nonce"); m.NotNullable(true); });
        Property(x => x.Tag, m => { m.Column("tag"); m.NotNullable(true); });
        Property(x => x.AssociatedData,
            m => { m.Column("associated_data"); m.NotNullable(true); });
        Property(x => x.CreatedAt, m => Conventions.AsTimestamp(m, "created_at"));
    }
}

public sealed class AuditEventMapping : ClassMapping<AuditEvent>
{
    public AuditEventMapping()
    {
        Table("audit_events");
        Id(x => x.Id, m => { m.Column("id"); m.Generator(Generators.GuidComb); });
        Property(x => x.OccurredAt, m => Conventions.AsTimestamp(m, "occurred_at"));
        Property(x => x.EventType, m => { m.Column("event_type"); m.NotNullable(true); });
        Property(x => x.Actor, m => m.Column("actor"));
        Property(x => x.SubjectType, m => m.Column("subject_type"));
        Property(x => x.SubjectId, m => m.Column("subject_id"));
        Property(x => x.TokenSerial, m => m.Column("token_serial"));
        Property(x => x.Detail, m => Conventions.AsJson(m, "detail"));
        Property(x => x.IsExemptFromRetention,
            m => { m.Column("is_exempt_from_retention"); m.NotNullable(true); });
    }
}

using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;

/// <summary>
/// Writes and reads back one row of each type that NHibernate and Npgsql can
/// disagree about: jsonb, timestamptz, bytea and an enum stored as text.
/// Schema validation compares shapes and never inserts, so it cannot see any of
/// this.
/// </summary>
internal static class RoundTrip
{
    public static int Run(string connectionString)
    {
        // Shapes first: an insert that works into a column of the wrong shape
        // proves nothing about what the services will say at start.
        var validation = SchemaValidator.Validate(BlinkySessionFactory.BuildConfiguration(connectionString));
        Console.WriteLine($"  validation  {validation.Summary}");

        if (!validation.IsValid)
        {
            return 1;
        }

        using var factory = BlinkySessionFactory.Build(connectionString);
        var now = DateTime.UtcNow;
        var serial = 900000000 + (now.Ticks % 1000);

        Guid tokenId;
        Guid jobId;
        Guid passkeyId;

        using (var session = factory.OpenSession())
        using (var transaction = session.BeginTransaction())
        {
            var token = new Token
            {
                Serial = serial,
                FirmwareVersion = "5.7.1",
                State = TokenState.Registered,
                ManagementKeyState = ManagementKeyState.Default,
                PinState = CredentialSecretState.Default,
                PukState = CredentialSecretState.NotApplicable,
                BiometricState = BiometricState.Enrolled,
                CreatedAt = now,
                UpdatedAt = now,
            };
            session.Save(token);

            var job = new Job
            {
                Type = JobType.Inventory,
                State = JobState.Pending,
                TokenSerial = serial,
                IdempotencyKey = $"roundtrip:{serial}",
                Payload = """{"schemaVersion":1,"steps":[{"op":"RequireToken"}]}""",
                DeadlineAt = now.AddMinutes(5),
                CreatedAt = now,
                UpdatedAt = now,
            };
            session.Save(job);

            var envelope = new SecretEnvelope
            {
                Token = token,
                Kind = SecretKind.Puk,
                KeyVersion = 1,
                Ciphertext = [0x01, 0x02, 0x03],
                Nonce = [0x04, 0x05],
                Tag = [0x06],
                AssociatedData = $"puk|{serial}",
                CreatedAt = now,
            };
            session.Save(envelope);

            // bytea, a unique uuid, a state that only moves through MoveTo, and
            // a boolean that is the only PIN-shaped column the table has.
            var passkey = new PasskeyCredential
            {
                Directory = "roundtrip",
                ProviderUserId = "user-1",
                ProviderLogin = "roundtrip@blinky.lab",
                TokenSerial = serial,
                JobId = job.Id,
                CeremonyId = Guid.NewGuid(),
                Challenge = "cdsZ1V10E0BGE4GcG3IK",
                AttestationObject = [0xA3, 0x63, 0x66, 0x6D, 0x74],
                PinSetByAgent = true,
                CreatedAt = now,
                UpdatedAt = now,
            };
            passkey.MoveTo(PasskeyCredentialState.KeyReady, now);
            passkey.MoveTo(PasskeyCredentialState.Failed, now,
                "A provider's error message, which is longer than anybody expects it to be. ".PadRight(400, '.'));
            session.Save(passkey);

            transaction.Commit();
            tokenId = token.Id;
            jobId = job.Id;
            passkeyId = passkey.Id;
        }

        using (var session = factory.OpenSession())
        {
            var token = session.Get<Token>(tokenId);
            var job = session.Get<Job>(jobId);

            Console.WriteLine($"  token       {token.Serial} {token.State} "
                              + $"puk={token.PukState} bio={token.BiometricState}");
            Console.WriteLine($"  created_at  {token.CreatedAt:O} kind={token.CreatedAt.Kind}");
            Console.WriteLine($"  job payload {job.Payload}");
            Console.WriteLine($"  unrecoverable {token.IsUnrecoverable}");

            var passkey = session.Get<PasskeyCredential>(passkeyId);
            Console.WriteLine($"  passkey     {passkey.State} pinSet={passkey.PinSetByAgent} "
                              + $"attestation={passkey.AttestationObject?.Length} reason={passkey.FailureReason?.Length}");

            if (passkey.State != PasskeyCredentialState.Failed || passkey.AttestationObject?.Length != 5
                || passkey.FailureReason?.Length != 400)
            {
                Console.Error.WriteLine("passkey round trip did not return what was written");
                return 1;
            }

            if (token.PukState != CredentialSecretState.NotApplicable
                || !job.Payload.Contains("RequireToken", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("round trip did not return what was written");
                return 1;
            }
        }

        // Leave nothing behind: this runs against a developer's stack.
        using (var session = factory.OpenSession())
        using (var transaction = session.BeginTransaction())
        {
            session.CreateSQLQuery("delete from passkey_credentials where id = :id")
                .SetGuid("id", passkeyId).ExecuteUpdate();
            session.CreateSQLQuery("delete from secret_envelopes where token_id = :id")
                .SetGuid("id", tokenId).ExecuteUpdate();
            session.CreateSQLQuery("delete from jobs where id = :id")
                .SetGuid("id", jobId).ExecuteUpdate();
            session.CreateSQLQuery("delete from tokens where id = :id")
                .SetGuid("id", tokenId).ExecuteUpdate();
            transaction.Commit();
        }

        Console.WriteLine("round trip ok");
        return 0;
    }
}

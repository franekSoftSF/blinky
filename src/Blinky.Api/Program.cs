using Blinky.Api.Agents;
using Blinky.Api.Persistence;
using Blinky.Api.Credentials;
using Blinky.Api.Secrets;
using Blinky.Api.Jobs;
using Blinky.Api.Security;
using Blinky.Api.Tokens;
using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var connectionString = builder.Configuration.GetConnectionString("Blinky") ?? string.Empty;
builder.Services.AddSingleton(new Database(connectionString));

builder.Services.AddSingleton(_ => AgentCertificateAuthority.Load(
    builder.Configuration["Blinky:AgentCa:CertificatePath"] ?? "/etc/blinky/certs/agent-ca.crt",
    builder.Configuration["Blinky:AgentCa:KeyPath"] ?? "/etc/blinky/certs/agent-ca.key",
    TimeSpan.FromDays(builder.Configuration.GetValue("Blinky:AgentCa:LifetimeDays", 90))));

builder.Services.AddSingleton<TokenInventoryService>();
builder.Services.AddSingleton<JobService>();

// The certificate authority, loaded from what scripts/new-ca.sh produced. CA
// instances and profiles in the database are the open half of patch 0022.
builder.Services.AddSingleton<Blinky.Pki.ICertificateAuthority>(_ =>
    Blinky.Pki.BuiltIn.BuiltInCaFactory.LoadFromDirectory(
        builder.Configuration["Blinky:Ca:Directory"] ?? "/etc/blinky/ca",
        builder.Configuration["Blinky:Ca:Password"],
        builder.Configuration.GetValue("Blinky:Ca:AllowFileKeys", false),

        // How long an issued list claims to be good for. Short is safer -
        // a revocation reaches relying parties sooner - but only as far as
        // publication is reliable, because an expired CRL does not fail open:
        // it breaks every chain built under it. Whatever this is, the copy
        // Samba holds in the directory has to be refreshed inside it, which is
        // what scripts/publish-crl-to-directory.sh is for.
        TimeSpan.FromHours(
            builder.Configuration.GetValue("Blinky:Ca:CrlValidityHours", 8)),
        // The address relying parties are told to fetch revocation from, and
        // it has to be one they can reach: not localhost, not the container
        // name, and over HTTP rather than HTTPS - see CaPublication. Left
        // unset, certificates are issued with neither extension, which is
        // what they were until 21 August 2026 and why the first smart-card
        // logon reported CERT_TRUST_REVOCATION_STATUS_UNKNOWN.
        Blinky.Pki.BuiltIn.CaPublication.FromBaseUrl(
            builder.Configuration["Blinky:Ca:PublicUrl"])));

// The directory, or an honest absence of one. Registered either way so the
// endpoints exist and answer "there is no directory here" rather than failing
// to resolve a service - a deployment without one is a normal deployment, with
// cardholders entered by hand.
builder.Services.AddSingleton<Blinky.Directory.IDirectory>(_ =>
{
    var directoryHost = builder.Configuration["Blinky:Directory:Host"];

    if (string.IsNullOrWhiteSpace(directoryHost))
    {
        return new Blinky.Directory.NoDirectory();
    }

    return new Blinky.Directory.LdapDirectory(new Blinky.Directory.LdapDirectoryOptions(
        directoryHost,
        builder.Configuration.GetValue("Blinky:Directory:Port", 389),
        builder.Configuration["Blinky:Directory:BaseDn"]
            ?? throw new InvalidOperationException(
                "Blinky:Directory:BaseDn is required when a directory host is configured. "
                + "A search with no base searches nothing."),
        Enum.TryParse<Blinky.Domain.DirectorySource>(
            builder.Configuration["Blinky:Directory:Source"], true, out var directorySource)
            ? directorySource
            : Blinky.Domain.DirectorySource.ActiveDirectory,
        builder.Configuration["Blinky:Directory:BindDn"],
        builder.Configuration["Blinky:Directory:BindPassword"],
        builder.Configuration.GetValue("Blinky:Directory:UseTls", true)));
});

builder.Services.AddSingleton<CredentialIssuanceService>();


// The key that protects every escrowed PUK. Refused rather than generated when
// absent: a KEK invented at startup would encrypt this run's PUKs with a value
// that dies with the process, and the tokens would be unrecoverable without
// anything having looked wrong.
builder.Services.AddSingleton(services => new PukEscrow(
    services.GetRequiredService<Database>(),
    PukKek(builder.Configuration),
    services.GetRequiredService<ILogger<PukEscrow>>()));

builder.Services.AddSingleton(services => new AgentEnrolmentService(
    services.GetRequiredService<Database>(),
    services.GetRequiredService<AgentCertificateAuthority>(),
    builder.Configuration["Blinky:Enrolment:BootstrapToken"] ?? string.Empty,
    services.GetRequiredService<ILogger<AgentEnrolmentService>>()));

var app = builder.Build();

// Compare the mappings against the live schema once, at start. This logs and
// continues on purpose: a missing column should produce one readable line while
// the container comes up, not a restart loop with no explanation. See
// docs/02-data-model.md.
var schema = string.IsNullOrWhiteSpace(connectionString)
    ? new SchemaValidationResult(false, "no connection string configured")
    : SchemaValidator.Validate(BlinkySessionFactory.BuildConfiguration(connectionString));

if (schema.IsValid)
{
    app.Logger.LogInformation("Schema validation: {Summary}", schema.Summary);
}
else
{
    app.Logger.LogError("Schema validation FAILED: {Summary}", schema.Summary);
}

app.UseSerilogRequestLogging();
app.UseMiddleware<AgentAuthenticationMiddleware>();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "Blinky.Api",
    protocol = Blinky.Contracts.Protocol.SchemaVersion,
    schema = new { valid = schema.IsValid, detail = schema.Summary },
}));

// The only unauthenticated endpoint in the API: an agent cannot present a
// certificate it has not been issued yet. See docs/05-agent-protocol.md.
app.MapPost(AgentAuthenticationMiddleware.EnrolmentPath,
    (EnrolmentRequest request, AgentEnrolmentService enrolment) =>
    {
        var result = enrolment.Enrol(request);

        return result.Outcome switch
        {
            EnrolmentOutcome.Issued => Results.Ok(result.Response),
            EnrolmentOutcome.InvalidToken =>
                Results.Json(new { error = result.Message }, statusCode: 401),
            EnrolmentOutcome.InvalidRequest =>
                Results.Json(new { error = result.Message }, statusCode: 400),
            _ => Results.Json(new { error = result.Message }, statusCode: 403),
        };
    });

// Who the edge says is calling, and which agent row that certificate belongs
// to. Useful on its own, and the first thing to check when an agent is
// mysteriously collecting 401s.
app.MapGet("/api/agents/whoami", (HttpContext context) =>
{
    var certificate = ClientCertificate.From(context.Request)!;
    var agent = (Agent)context.Items["agent"]!;

    return Results.Ok(new
    {
        agentId = agent.Id,
        agent.Hostname,
        agent.Domain,
        state = agent.State.ToString(),
        subject = certificate.Subject,
        issuer = certificate.Issuer,
        thumbprint = certificate.Thumbprint,
        notAfter = certificate.NotAfter,
    });
});

// What an agent found in a reader. Facts in, judgement here - see
// TokenInventoryService.
app.MapPost("/api/tokens/inventory",
    (TokenInventoryReport report, TokenInventoryService inventory) =>
    {
        if (!Protocol.IsSupported(report.SchemaVersion))
        {
            return Results.Json(new
            {
                error = $"schema version {report.SchemaVersion} is not supported",
                supported = new
                {
                    minimum = Protocol.MinimumSupportedVersion,
                    maximum = Protocol.MaximumSupportedVersion,
                },
            }, statusCode: 400);
        }

        return Results.Ok(inventory.Accept(report));
    });

// An agent asking for work. Returns 204 when there is none, which is the
// normal answer most of the time.
app.MapGet("/api/jobs/next", (HttpContext context, JobService jobs) =>
{
    var agent = (Agent)context.Items["agent"]!;
    var claim = jobs.Claim(agent.Id);

    return claim is null ? Results.NoContent() : Results.Ok(claim);
});

app.MapPost("/api/jobs/{id:guid}/progress",
    (Guid id, JobProgress progress, HttpContext context, JobService jobs) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        return jobs.Report(agent.Id, progress with { JobId = id })
            ? Results.NoContent()
            : Results.Json(new { error = "this job is not yours to report on" },
                statusCode: 403);
    });

app.MapPost("/api/jobs/{id:guid}/result",
    (Guid id, JobResult result, HttpContext context, JobService jobs) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        return jobs.Complete(agent.Id, result with { JobId = id })
            ? Results.NoContent()
            : Results.Json(new { error = "this job is not yours to finish" }, statusCode: 403);
    });

// Creating work belongs to an operator, never to an agent: the API creates
// jobs on request and never decides on its own that work exists.
//
// Until RBAC arrives in 0053 the operator proves themselves with a shared
// token. That is a stop-gap and is named as one - but an unauthenticated write
// endpoint would not have been the smaller compromise.
var operatorToken = builder.Configuration["Blinky:Operator:Token"] ?? string.Empty;

app.MapPost("/api/jobs/inventory",
    (InventoryJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var key = $"inventory:{request.AgentId}:{request.Reason ?? "manual"}";

        var (job, created) = jobs.Create(JobType.Inventory, key,
            id => JobEnvelope.Inventory(id, key, DateTimeOffset.UtcNow.AddHours(1)),
            request.AgentId);

        return Results.Ok(new { job.Id, created, state = job.State.ToString() });
    });

app.MapPost("/api/jobs/enrol",
    (EnrolmentJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // The slot is part of the key: two credentials on one token are two
        // jobs, and re-posting the same one is not a second key on the card.
        //
        // The reason is part of it too, and deliberately the operator's to
        // supply. A job that failed on a mistyped PIN is finished as far as the
        // row is concerned, and without a way to say "this is a new attempt"
        // the same request would keep returning the dead one.
        var key = $"enrol:{request.TokenSerial}:{request.SlotId}:{request.ProfileName}"
                  + $":{request.Reason ?? "initial"}";

        var (job, created) = jobs.Create(JobType.Enroll, key,
            id => JobEnvelope.Enrolment(id, key, DateTimeOffset.UtcNow.AddHours(1),
                request.TokenSerial, request.SlotId, request.ProfileName, request.DisplayName,
                request.Upn, request.ObjectSid),
            request.AgentId);

        return Results.Ok(new { job.Id, created, state = job.State.ToString() });
    });

// Taking a credential back off a token. The agent refuses to do this on its
// own - deleting something Blinky issued would leave this server holding a
// credential it believes is installed - so the order comes from here, and the
// record is corrected when the job reports back.
app.MapPost("/api/jobs/recycle",
    (RecycleJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var key = $"recycle:{request.TokenSerial}:{request.SlotId}:{request.Reason ?? "manual"}";

        var (job, created) = jobs.Create(JobType.Revoke, key,
            id => JobEnvelope.Recycle(id, key, DateTimeOffset.UtcNow.AddHours(1),
                request.TokenSerial, request.SlotId),
            request.AgentId);

        return Results.Ok(new { job.Id, created, state = job.State.ToString() });
    });

// An agent asking for a certificate. The attestation is verified here, against
// this server's pinned root - see docs/06-security.md.
app.MapPost("/api/credentials/issue",
    async (IssueCredentialRequest request, CredentialIssuanceService credentials,
        CancellationToken ct) =>
    {
        if (!Protocol.IsSupported(request.SchemaVersion))
        {
            return Results.Json(new { error = "unsupported schema version" }, statusCode: 400);
        }

        try
        {
            return Results.Ok(await credentials.IssueAsync(request, ct));
        }
        catch (Blinky.Pki.IssuancePolicyException ex)
        {
            // A refusal, not a fault: somebody asked for something they may not
            // have, and the reason belongs in the response.
            return Results.Json(new { error = ex.Message }, statusCode: 422);
        }
    });

// Unblocking, in the only shape PIV allows. The card takes a PUK and nothing
// else - there is no challenge-response unblock APDU to build on - so the value
// stops being a secret people know and becomes one only this server holds:
// random per token, released for the seconds an unblock takes, replaced
// immediately. See docs/10-agent-ui.md.
// Taking a token out of service, from the console, about a card nobody can
// necessarily reach - which is the situation that makes it necessary. A card
// reported lost is not going to be presented for a recycle job.
// ---------------------------------------------------------- the directory
//
// Gap 5 of doc 11. A smartcard-logon certificate is refused without a resolved
// objectSid, and that refusal is right: since KB5014754 a domain controller
// ignores a certificate mapped by name alone. So the SID is read from the
// directory that will later be asked to honour it, rather than typed by an
// operator who can only produce a plausible one.

app.MapGet("/api/directory/users",
    async (string? q, HttpContext context, Blinky.Directory.IDirectory directory,
        CancellationToken ct) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        if (directory is Blinky.Directory.NoDirectory)
        {
            // Said plainly rather than as an empty list. "Nobody matched" and
            // "there is nowhere to look" are different answers, and a console
            // should be able to tell an operator which one it got.
            return Results.Json(new
            {
                error = "no directory is configured",
                detail = "Set Blinky:Directory:Host and BaseDn, or add cardholders by hand.",
            }, statusCode: 501);
        }

        if (string.IsNullOrWhiteSpace(q) || q.Trim().Length < 2)
        {
            return Results.Json(new { error = "give at least two characters to search for" },
                statusCode: 400);
        }

        var found = await directory.SearchAsync(q.Trim(), 20, ct);

        return Results.Ok(new
        {
            source = directory.Source.ToString(),
            users = found.Select(u => new
            {
                u.DisplayName,
                u.SamAccountName,
                u.Upn,
                u.ObjectSid,
                u.DistinguishedName,
                u.Enabled,

                // Whether this person can be given a logon credential at all,
                // answered here so the console greys the choice out rather than
                // posting a job the issuance service will refuse.
                issuable = u.Enabled && !string.IsNullOrEmpty(u.Upn)
                           && !string.IsNullOrEmpty(u.ObjectSid),
            }),
        });
    });

// ------------------------------------------------------------ cardholders
//
// Gap 2. The entity has existed all along and nothing exposed it, so
// Job.CardholderId was never set and no credential could be traced to a person
// afterwards.

app.MapGet("/api/cardholders",
    (string? q, HttpContext context, Database database) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        using var session = database.OpenSession();

        var people = session.Query<Cardholder>().ToList();

        if (!string.IsNullOrWhiteSpace(q))
        {
            var needle = q.Trim();

            people = people.Where(c =>
                c.DisplayName.Contains(needle, StringComparison.OrdinalIgnoreCase)
                || (c.Upn ?? string.Empty).Contains(needle, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        return Results.Ok(people.Take(50).Select(c => new
        {
            c.Id,
            c.DisplayName,
            c.Upn,
            c.ObjectSid,
            c.DistinguishedName,
            source = c.DirectorySource.ToString(),
            state = c.State.ToString(),
            issuable = c.State == Blinky.Domain.CardholderState.Active
                       && !string.IsNullOrEmpty(c.Upn)
                       && !string.IsNullOrEmpty(c.ObjectSid),
        }));
    });

app.MapPost("/api/cardholders",
    async (CardholderRequest request, HttpContext context, Database database,
        Blinky.Directory.IDirectory directory, CancellationToken ct) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var displayName = request.DisplayName;
        var upn = request.Upn;
        var sid = request.ObjectSid;
        var dn = request.DistinguishedName;
        var source = Blinky.Domain.DirectorySource.Local;

        // Named in the directory rather than typed out, which is the point.
        // When an account name is given everything else comes from there, and
        // anything the caller also sent is ignored rather than merged: half a
        // person from each source is the worst of both.
        if (!string.IsNullOrWhiteSpace(request.DirectoryAccount))
        {
            var person = await directory.FindAsync(request.DirectoryAccount.Trim(), ct);

            if (person is null)
            {
                return Results.Json(new
                {
                    error = "that account matched no one, or matched more than one person",
                    account = request.DirectoryAccount,
                }, statusCode: 404);
            }

            displayName = person.DisplayName;
            upn = person.Upn;
            sid = person.ObjectSid;
            dn = person.DistinguishedName;
            source = directory.Source;
        }

        if (string.IsNullOrWhiteSpace(displayName))
        {
            return Results.Json(new { error = "a cardholder needs a display name" },
                statusCode: 400);
        }

        // Checked at the boundary. A malformed SID stored here fails at a logon
        // three weeks later, which is the worst possible moment to find out,
        // and the message then is about trust rather than about this field.
        if (!string.IsNullOrEmpty(sid)
            && !Blinky.Directory.SecurityIdentifier.LooksValid(sid))
        {
            return Results.Json(new
            {
                error = "that is not a security identifier",
                detail = "Expected the S-1-5-21 form. Read it from the directory rather than "
                         + "typing it: a plausible SID produces a certificate that asserts an "
                         + "identity nobody issued.",
            }, statusCode: 400);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        // One person, once. A second row for the same UPN is a second identity
        // as far as everything downstream is concerned.
        if (!string.IsNullOrEmpty(upn)
            && session.Query<Cardholder>().ToList().Any(c =>
                string.Equals(c.Upn, upn, StringComparison.OrdinalIgnoreCase)))
        {
            return Results.Json(new { error = "that UPN is already a cardholder", upn },
                statusCode: 409);
        }

        var createdAt = DateTime.UtcNow;

        var cardholder = new Cardholder
        {
            DisplayName = displayName,
            Upn = upn,
            ObjectSid = sid,
            DistinguishedName = dn,
            DirectorySource = source,
            State = Blinky.Domain.CardholderState.Active,
            CreatedAt = createdAt,
            UpdatedAt = createdAt,
        };

        session.Save(cardholder);
        transaction.Commit();

        return Results.Ok(new
        {
            cardholder.Id,
            cardholder.DisplayName,
            cardholder.Upn,
            cardholder.ObjectSid,
            source = source.ToString(),
            issuable = !string.IsNullOrEmpty(upn) && !string.IsNullOrEmpty(sid),
        });
    });

// Everything a help desk needs about one token, in one call: who holds it,
// what state it is in, and what is on it - a person on a telephone should not
// be assembling that from four requests while somebody waits.
//
// Shaped after what a commercial CMS puts on that screen, because the shape is
// not the interesting part and getting it wrong costs the console a rewrite.
app.MapGet("/api/tokens/{serial:long}/helpdesk",
    (long serial, HttpContext context, Database database) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        using var session = database.OpenSession();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);
        if (token is null)
        {
            return Results.NotFound(new { error = $"no token with serial {serial}" });
        }

        var slots = session.Query<Slot>()
            .Where(s => s.Token.Serial == serial)
            .ToList();

        var credentials = session.Query<Credential>()
            .Where(c => c.Token.Serial == serial)
            .ToList()
            .OrderBy(c => c.SlotId)
            .ThenByDescending(c => c.CreatedAt)
            .ToList();

        var holder = token.Cardholder;

        return Results.Ok(new
        {
            // Who it belongs to. Null until somebody is enrolled onto it, and
            // said as null rather than as an empty person.
            cardholder = holder is null ? null : new
            {
                holder.Id,
                holder.DisplayName,
                holder.Upn,
                holder.ObjectSid,
                holder.DistinguishedName,
                source = holder.DirectorySource.ToString(),
                state = holder.State.ToString(),
            },

            device = new
            {
                token.Serial,
                state = token.State.ToString(),
                token.FirmwareVersion,
                formFactor = token.FormFactor,
                token.AttestationThumbprint,
                token.LastSeenAt,

                // What can and cannot be done to it, and why - so the console
                // greys out an action rather than offering one that fails.
                managementKeyState = token.ManagementKeyState.ToString(),
                manageable = token.ManagementKeyState is not Blinky.Domain.ManagementKeyState.Lost,
            },

            // The card's own applications, in the order a person reads them.
            // The PIN is one, exactly as it is on a card: a thing with a policy
            // and a retry count rather than a property of the device.
            pin = new
            {
                state = token.PinState.ToString(),
                retriesLeft = token.PinRetriesLeft,
                policy = PinComplexityPolicy.Default,
            },

            puk = new
            {
                state = token.PukState.ToString(),
                retriesLeft = token.PukRetriesLeft,

                // Whether an unblock is even possible. A PUK that is itself
                // blocked, deleted, or never existed is not a route back, and
                // offering the action is worse than saying so - the console
                // should grey it out rather than fail at the card.
                unblockable = token.PukState
                    is Blinky.Domain.CredentialSecretState.Default
                    or Blinky.Domain.CredentialSecretState.Set,
            },

            biometric = new
            {
                state = token.BiometricState.ToString(),
                attemptsLeft = token.BiometricAttemptsLeft,
            },

            slots = slots.Select(s => new
            {
                s.SlotId,
                state = s.State.ToString(),
                s.KeyAlgorithm,
                s.PinPolicy,
                s.TouchPolicy,
                credentialId = s.Credential?.Id,
            }),

            credentials = credentials.Select(c => new
            {
                c.Id,
                c.SlotId,
                state = c.State.ToString(),
                c.SerialNumber,
                c.SubjectDn,
                c.IssuerDn,
                c.NotBefore,
                c.NotAfter,
                c.RevokedAt,
                c.RevocationReason,

                // Said here rather than worked out in the browser from two
                // dates and a clock nobody trusts.
                expired = c.NotAfter is { } until && until <= DateTime.UtcNow,
                supersedes = c.Supersedes?.Id,
            }),
        });
    });

// One credential put on hold, and taken off it. Distinct from revoking the
// whole token: a card with two credentials on it can have one suspended while
// the other keeps working, which is what "suspend this application" means on a
// help-desk screen.
app.MapPost("/api/credentials/{id:guid}/suspend",
    async (Guid id, HttpContext context, CredentialIssuanceService credentials,
        CancellationToken ct) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // Hold, and only hold. It is the one revocation reason X.509 allows to
        // be taken back, which is what makes this reversible and everything
        // else on this screen permanent.
        var suspended = await credentials.RevokeAsync(id,
            Blinky.Pki.X509RevocationReason.CertificateHold, "suspended by an operator", ct);

        return suspended
            ? Results.Ok(new { id, state = "Revoked", reason = "CertificateHold", reversible = true })
            : Results.Json(new { error = "no such credential, or it is already revoked" },
                statusCode: 404);
    });

app.MapPost("/api/tokens/{serial:long}/block",
    async (long serial, BlockTokenRequest request, HttpContext context,
        CredentialIssuanceService credentials, CancellationToken ct) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        if (!Enum.TryParse<Blinky.Domain.TokenState>(request.State, true, out var state))
        {
            return Results.Json(new
            {
                error = $"'{request.State}' is not a state",
                states = new[] { "Suspended", "Lost", "Stolen", "Terminated", "Retired" },
            }, statusCode: 400);
        }

        try
        {
            var revoked = await credentials.BlockAsync(serial, state, request.Comment, ct);

            return revoked is { } count
                ? Results.Ok(new
                {
                    serial,
                    state = state.ToString(),
                    credentialsRevoked = count,

                    // Said in the answer rather than left to be discovered. A
                    // suspension is the only one that can be lifted; the rest
                    // revoke on key compromise or cessation, and those do not
                    // come back.
                    reversible = state is Blinky.Domain.TokenState.Suspended,
                })
                : Results.NotFound(new { error = $"no token with serial {serial}" });
        }
        catch (ArgumentException ex)
        {
            return Results.Json(new { error = ex.Message }, statusCode: 400);
        }
    });

// And back. Only from a suspension - see CredentialIssuanceService.Unblock for
// why the others do not come back.
app.MapPost("/api/tokens/{serial:long}/unblock",
    (long serial, HttpContext context, CredentialIssuanceService credentials) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        return credentials.Unblock(serial)
            ? Results.Ok(new { serial, state = "Registered" })
            : Results.Json(new
            {
                error = "no such token, or it is not suspended",
                detail = "Only a suspension is lifted here. A token revoked as lost, stolen, "
                         + "terminated or retired stays that way, and the route back is a new "
                         + "credential rather than an undo.",
            }, statusCode: 409);
    });

app.MapPost("/api/tokens/{serial:long}/puk/checkout",
    (long serial, HttpContext context, PukEscrow escrow) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        try
        {
            var checkout = escrow.Checkout(serial, $"agent:{agent.Hostname}");

            return checkout is null
                ? Results.NotFound(new { error = "no such token" })
                : Results.Ok(new PukMaterial(checkout.CheckoutId, checkout.CurrentPuk,
                    checkout.NextPuk));
        }
        catch (PukUnavailableException ex)
        {
            // A refusal, not a fault: a Bio has no PUK by design and a token
            // somebody else personalised has one this server never held.
            return Results.Json(new { error = ex.Message }, statusCode: 422);
        }
    });

app.MapPost("/api/tokens/{serial:long}/puk/rotated",
    (long serial, PukRotated confirmation, PukEscrow escrow) =>
        escrow.Commit(serial, confirmation.CheckoutId)
            ? Results.NoContent()
            : Results.NotFound(new { error = "no such checkout" }));

// The helpdesk's side of a telephone call. The workstation is offline; whoever
// is answering the phone is not. Operator-authorised, because this reads a PUK
// out loud to somebody whose identity nothing here can check - that is a
// process control rather than a technical one, and pretending otherwise would
// be worse than saying it plainly.
app.MapPost("/api/tokens/offline-unblock",
    (OfflineUnblockRequest request, HttpContext context, PukEscrow escrow) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        try
        {
            var answer = escrow.AnswerOffline(request.Challenge, "operator");

            return answer is null
                ? Results.NotFound(new { error = "no such token" })
                : Results.Ok(answer);
        }
        catch (PukUnavailableException ex)
        {
            return Results.Json(new { error = ex.Message }, statusCode: 422);
        }
    });

// "The code you read me was refused." Somebody has to be able to say that, or
// the next code read out is refused as well: the rotation happened here and
// never reached the card.
app.MapPost("/api/tokens/puk/refused",
    (PukRefused refused, HttpContext context, PukEscrow escrow) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        return escrow.Refused(refused.TokenSerial)
            ? Results.NoContent()
            : Results.NotFound(new { error = "nothing to roll back" });
    });

// What the backend believes is on a token, so an agent can compare it with
// what the card actually holds. The disagreement is the point: a credential the
// server thinks is installed and the card does not have is the leak that
// docs/02-data-model.md separates Issued from Installed to make visible.
app.MapGet("/api/tokens/{serial:long}/credentials",
    (long serial, HttpContext context, Database database) =>
    {
        // An agent speaks for the machine it is on, and any agent may be
        // holding any token: this says nothing a person with the token in their
        // hand cannot read off the card itself.
        _ = (Agent)context.Items["agent"]!;

        using var session = database.OpenSession();

        // Materialised before projecting: the hex conversion and the null
        // handling below are C#, not SQL, and NHibernate would try to translate
        // them.
        var credentials = session.Query<Credential>()
            .Where(c => c.Token.Serial == serial)
            .ToList()
            .Select(c => new KnownCredential(
                c.SlotId,
                c.SerialNumber,
                c.PublicKeySha256 is { } hash ? Convert.ToHexString(hash) : null,
                c.State.ToString(),
                c.SubjectDn,
                c.NotAfter))
            .ToList();

        return Results.Ok(credentials);
    });

// Withdrawing a credential without the card. The ordinary route is a recycle
// job, which needs the card, an agent that can reach it and a management key
// Blinky still holds; this is for when one of those is gone and the
// certificate is out of reach while still being perfectly valid to everybody
// who checks it.
app.MapPost("/api/credentials/{id:guid}/revoke",
    async (Guid id, RevokeCredentialRequest request, HttpContext context,
        CredentialIssuanceService credentials, CancellationToken ct) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // Named by the operator rather than defaulted quietly. A revocation
        // reason travels into the CRL and is the only thing a relying party
        // ever learns about why, so "unspecified" should be a choice somebody
        // made.
        if (!Enum.TryParse<Blinky.Pki.X509RevocationReason>(request.Reason, true, out var reason))
        {
            return Results.Json(new
            {
                error = $"'{request.Reason}' is not a revocation reason",
                reasons = Enum.GetNames<Blinky.Pki.X509RevocationReason>(),
            }, statusCode: 400);
        }

        var revoked = await credentials.RevokeAsync(id, reason, request.Comment, ct);

        return revoked
            ? Results.Ok(new { id, state = "Revoked", reason = reason.ToString() })
            : Results.Json(new { error = "no such credential, or it was already revoked" },
                statusCode: 404);
    });

app.MapPost("/api/credentials/{id:guid}/installed",
    (Guid id, CredentialInstalled confirmation, CredentialIssuanceService credentials) =>
        credentials.MarkInstalled(confirmation with { CredentialId = id })
            ? Results.NoContent()
            : Results.NotFound(new { error = "no such credential" }));

// An agent replacing its own certificate before it expires, proving itself
// with the one it still holds. The bootstrap token joins a machine to the
// fleet once; needing it again every ninety days is what would make it hard to
// keep short-lived and rate-limited.
app.MapPost("/api/agents/{id:guid}/renew-certificate",
    (Guid id, RenewalRequest request, HttpContext context,
        AgentEnrolmentService enrolment) =>
    {
        var caller = (Agent)context.Items["agent"]!;

        if (caller.Id != id)
        {
            // An agent speaks only for itself, whatever id it puts in the URL.
            return Results.Json(new { error = "the certificate belongs to a different agent" },
                statusCode: 403);
        }

        var result = enrolment.Renew(id, request);

        return result.Outcome switch
        {
            EnrolmentOutcome.Issued => Results.Ok(result.Response),
            EnrolmentOutcome.InvalidRequest =>
                Results.Json(new { error = result.Message }, statusCode: 400),
            _ => Results.Json(new { error = result.Message }, statusCode: 403),
        };
    });

// One coherent, read-only snapshot for the browser. Keeping the first console
// endpoint coarse-grained avoids four races between counters and tables, and
// keeps the Angular bundle on the same-origin /api contract used behind nginx.
// ---------------------------------------------------------------- pki
//
// Plain HTTP, unauthenticated, and both are deliberate. These are the
// addresses written into every certificate this CA issues - the CRL
// distribution point and the authority information access - and whoever
// fetches them is in the middle of deciding whether they can trust anything at
// all. A relying party that has to validate a certificate in order to fetch
// the thing that tells it whether the certificate is valid has a problem it
// cannot get out of, and a CA certificate is public by construction.
//
// The CRL is signed. That is what protects it, not the transport.

app.MapGet("/pki/issuing.crt", (Blinky.Pki.ICertificateAuthority ca) =>
{
    if (ca is not Blinky.Pki.BuiltIn.BuiltInCertificateAuthority built)
    {
        return Results.NotFound();
    }

    // DER rather than PEM: this is what an authority information access
    // fetch expects, and Windows will not read a PEM here.
    return Results.File(built.Issuer.RawData, "application/pkix-cert", "issuing.crt");
});

app.MapGet("/pki/root.crt", (Blinky.Pki.ICertificateAuthority ca) =>
{
    if (ca is not Blinky.Pki.BuiltIn.BuiltInCertificateAuthority built)
    {
        return Results.NotFound();
    }

    return Results.File(built.TrustAnchor.RawData, "application/pkix-cert", "root.crt");
});

app.MapGet("/pki/chain.pem", (Blinky.Pki.ICertificateAuthority ca) =>
{
    if (ca is not Blinky.Pki.BuiltIn.BuiltInCertificateAuthority built)
    {
        return Results.NotFound();
    }

    // For the things that want the lot in one file - PKINIT anchors, an
    // openssl verify, a Linux client being set up by hand.
    var chain = built.TrustAnchor.Thumbprint == built.Issuer.Thumbprint
        ? built.TrustAnchor.ExportCertificatePem()
        : built.Issuer.ExportCertificatePem() + "\n" + built.TrustAnchor.ExportCertificatePem();

    return Results.Text(chain, "application/x-pem-file");
});

// The root's own list, which says whether the issuing CA was revoked. Served
// from the file scripts/resign-issuing-ca.sh writes, because signing it needs
// the root key and the root key is not something this process holds - that is
// the whole point of a two-tier CA.
//
// A year of validity is right for it: a root that has issued one intermediate
// has nothing to say that changes, and every refresh means taking the root key
// out. Short-lived lists belong to the CA that issues daily.
//
// This endpoint exists because the issuing CA's certificate names it. A URL
// written into a certificate that nobody answers is worse than no URL at all:
// the relying party tries it, waits, and fails a check it would otherwise have
// skipped.
app.MapGet("/pki/root.crl", (IConfiguration configuration) =>
{
    var directory = configuration["Blinky:Ca:Directory"] ?? "/etc/blinky/ca";
    var path = Path.Combine(directory, "root.crl");

    if (!File.Exists(path))
    {
        // 404 rather than an empty list. An empty CRL is a statement - "I have
        // revoked nothing, and here is my signature on that" - and this
        // process cannot make it, because it does not hold the root key. Better
        // to be plainly absent than to look like an answer.
        return Results.NotFound();
    }

    return Results.File(File.ReadAllBytes(path), "application/pkix-crl", "root.crl");
});

// Served from the file, not built here. The worker produces it, on a schedule,
// as a job - and it has to be one list rather than two, because the store
// behind GetCrlAsync is per-process: an API that built its own would publish a
// list holding whatever this replica happened to have been told about, which
// on a fresh container is nothing at all.
app.MapGet("/pki/issuing.crl", (IConfiguration configuration) =>
{
    var path = configuration["Blinky:Ca:CrlFile"] ?? "/var/lib/blinky/pki/issuing.crl";

    if (!File.Exists(path))
    {
        // Before the worker's first pass, or with no worker at all. A 404 says
        // that plainly; an empty list would be a signed claim that nothing has
        // been revoked, which is a different thing and might not be true.
        return Results.NotFound();
    }

    return Results.File(File.ReadAllBytes(path), "application/pkix-crl", "issuing.crl");
});

app.MapGet("/api/console/overview", (HttpContext context, Database database) =>
{
    if (!IsOperator(context, operatorToken))
    {
        return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
    }

    using var session = database.OpenSession();
    var agents = session.Query<Agent>().ToList().Select(a => new
    {
        a.Id, a.Hostname, a.Domain, a.Version, state = a.State.ToString(), a.LastHeartbeatAt,
    }).ToList();
    var tokens = session.Query<Token>().ToList().Select(t => new
    {
        t.Id, t.Serial, t.FirmwareVersion, t.FormFactor, state = t.State.ToString(),
        pinState = t.PinState.ToString(), pukState = t.PukState.ToString(), t.LastSeenAt,
    }).ToList();
    var credentials = session.Query<Credential>().ToList().Select(c => new
    {
        c.Id, tokenSerial = c.Token.Serial, c.SlotId, c.SubjectDn,
        state = c.State.ToString(), c.NotAfter,
    }).ToList();
    var jobs = session.Query<Job>().OrderByDescending(j => j.CreatedAt).Take(100).ToList().Select(j => new
    {
        j.Id, type = j.Type.ToString(), state = j.State.ToString(), j.TokenSerial,
        j.Attempt, j.CreatedAt, j.Result, j.UpdatedAt,
    }).ToList();

    // What is actually in the slots, which is not the same question as what
    // credentials exist. A credential row survives being revoked and survives
    // the card being reset; the slot is the thing that says whether anything
    // is on the token now.
    //
    // Without this the console can only reason from the credential list, and a
    // revoked credential looks exactly like a live one apart from a word. On
    // 21 August 2026 a token was reset with ykman, every slot correctly went to
    // Empty, both credentials correctly went to Revoked - and the console went
    // on showing a certificate on the token, because nothing had ever told it
    // what a slot was.
    var slots = session.Query<Slot>().ToList().Select(s => new
    {
        tokenSerial = s.Token.Serial, s.SlotId, state = s.State.ToString(),
        credentialId = s.Credential?.Id, s.KeyAlgorithm, s.PinPolicy, s.TouchPolicy,
        s.UpdatedAt,
    }).ToList();

    return Results.Ok(new { agents, tokens, slots, credentials, jobs });
});

app.MapPost("/api/agents/{id:guid}/heartbeat",
    (Guid id, HeartbeatRequest request, HttpContext context, Database database) =>
    {
        var caller = (Agent)context.Items["agent"]!;
        if (caller.Id != id)
        {
            // An agent speaks only for itself, whatever id it puts in the URL.
            return Results.Json(new { error = "the certificate belongs to a different agent" },
                statusCode: 403);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        foreach (var card in request.Unsupported ?? [])
        {
            // Not stored: the identity model is the token's serial, and a card
            // that answers no Yubico instruction has none. Visible in the log
            // and in the heartbeat is what stops it looking like a dead agent.
            app.Logger.LogInformation(
                "Agent {AgentId} has an unmanageable card in {Reader}: {Reason}",
                id, card.ReaderName, card.Reason);
        }

        var agent = session.Get<Agent>(id);
        agent.Version = request.Version;
        agent.LastHeartbeatAt = DateTime.UtcNow;
        agent.UpdatedAt = DateTime.UtcNow;
        session.Update(agent);

        transaction.Commit();

        return Results.Ok(new
        {
            protocol = Blinky.Contracts.Protocol.SchemaVersion,
            supported = new
            {
                minimum = Blinky.Contracts.Protocol.MinimumSupportedVersion,
                maximum = Blinky.Contracts.Protocol.MaximumSupportedVersion,
            },
            pollIntervalSeconds = 60,
        });
    });

app.Run();

/// <summary>
/// Constant-time comparison of the stand-in operator token. Returning early on
/// the first wrong byte would leak the prefix to anything that can time a
/// request.
/// </summary>
/// <summary>
/// Thirty-two bytes of base64 from configuration, and nothing else will do.
/// </summary>
/// <remarks>
/// Deliberately not optional and deliberately not generated. Escrow that
/// silently starts working with a throwaway key looks identical to escrow that
/// works, right up to the first unblock after a restart.
/// </remarks>
static byte[] PukKek(IConfiguration configuration)
{
    var configured = configuration["Blinky:Puk:Kek"];

    if (string.IsNullOrWhiteSpace(configured))
    {
        throw new InvalidOperationException(
            "Blinky:Puk:Kek is not set. PUK escrow needs a 32-byte key, base64 encoded; "
            + "generate one with: openssl rand -base64 32");
    }

    var kek = Convert.FromBase64String(configured);

    return kek.Length == 32
        ? kek
        : throw new InvalidOperationException(
            $"Blinky:Puk:Kek decodes to {kek.Length} bytes; AES-256 needs 32.");
}

static bool IsOperator(HttpContext context, string expected)
{
    if (string.IsNullOrEmpty(expected))
    {
        return false;
    }

    var presented = context.Request.Headers["X-Blinky-Operator"].ToString();

    return !string.IsNullOrEmpty(presented)
           && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
               System.Text.Encoding.UTF8.GetBytes(presented),
               System.Text.Encoding.UTF8.GetBytes(expected));
}

/// <summary>What an agent reports when it checks in.</summary>
/// <summary>Asks for one token inventory pass on one agent.</summary>
internal sealed record InventoryJobRequest(Guid AgentId, string? Reason);

/// <summary>One credential the backend holds, as an agent needs to see it.</summary>
/// <summary>An offline code that the card would not take.</summary>
internal sealed record PukRefused(long TokenSerial);

/// <summary>An operator taking a credential back off a token.</summary>
/// <summary>
/// A person to issue to. Either named in the directory, which is the point, or
/// spelled out for a deployment that has none.
/// </summary>
internal sealed record CardholderRequest(
    string? DirectoryAccount = null,
    string? DisplayName = null,
    string? Upn = null,
    string? ObjectSid = null,
    string? DistinguishedName = null);

/// <summary>An operator taking a token out of service.</summary>
internal sealed record BlockTokenRequest(string State, string? Comment = null);

/// <summary>An operator withdrawing a credential the card cannot be asked about.</summary>
internal sealed record RevokeCredentialRequest(string Reason, string? Comment = null);

internal sealed record RecycleJobRequest(
    Guid? AgentId,
    long TokenSerial,
    string SlotId,
    string? Reason = null);

internal sealed record KnownCredential(
    string SlotId,
    string? SerialNumber,
    string? PublicKeySha256,
    string State,
    string? SubjectDn,
    DateTime? NotAfter);

/// <remarks>
/// <c>ProfileName</c> rather than <c>Profile</c>, and that is not a style
/// choice. CRS rule 930120 tests argument <b>names</b> against
/// <c>lfi-os-files.data</c>, which contains the Unix dotfile <c>.profile</c>;
/// a field called <c>profile</c> arrives as <c>ARGS_NAMES:json.profile</c> and
/// the edge answers 403 before the API sees it. The alternative was an
/// exclusion that turns off an LFI rule for a whole endpoint. See
/// docs/06-security.md.
/// </remarks>
internal sealed record EnrolmentJobRequest(
    Guid? AgentId,
    long TokenSerial,
    string SlotId,
    string ProfileName,
    string DisplayName,
    string? Upn,
    string? ObjectSid,
    string? Reason = null);

internal sealed record HeartbeatRequest(
    string? Version,
    string[]? Readers,
    UnsupportedCardReport[]? Unsupported);

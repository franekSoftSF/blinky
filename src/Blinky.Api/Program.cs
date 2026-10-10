using Blinky.Api.Agents;
using Blinky.Api.Persistence;
using Blinky.Api.Credentials;
using Blinky.Api.Secrets;
using Blinky.Api.Jobs;
using Blinky.Api.Security;
using Blinky.Api.Tokens;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using Blinky.Secrets;
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

// Passkey providers, when there are any: rows in the database, configured in the
// console (0107), never variables in .env. The only part of this stack that
// reaches a cloud, and only from this container - see docs/12 §4.6.
builder.Services.AddSingleton<Blinky.Api.Passkeys.IPasskeyProviderStore, Blinky.Api.Passkeys.PasskeyProviderStore>();
builder.Services.AddSingleton<Blinky.Api.Passkeys.PasskeyProviders>();
builder.Services.AddSingleton(services =>
    services.GetRequiredService<Blinky.Api.Passkeys.PasskeyProviders>().Directories);
builder.Services.AddSingleton<Blinky.Api.Passkeys.IPasskeyStore, Blinky.Api.Passkeys.PasskeyStore>();
builder.Services.AddSingleton<Blinky.Api.Passkeys.PasskeyProvisioningService>();
builder.Services.AddSingleton<Blinky.Api.Passkeys.PasskeyJobs>();
builder.Services.AddSingleton<Blinky.Api.Passkeys.PasskeyRequests>();

// The certificate authorities: rows, built on demand and rebuilt when the console
// changes one (0108). Until then one value in .env chose one CA for the life of the
// process, and the first issuance through MS-CONN01 sat on a setting only somebody
// with a shell could change. What .env still says about the CA is imported into the
// table once, at the first start after the upgrade - see CaSeed - and then ignored.
//
// The connector's queue exists whether or not a polling connector is configured:
// it costs nothing, and a CA switched to ConnectorPolls from the console has to find
// it there without a restart.
builder.Services.AddSingleton<Blinky.Pki.Adcs.ConnectorQueue>();
builder.Services.AddSingleton<Blinky.Api.Authorities.CertificateAuthorities>();
builder.Services.AddSingleton<Blinky.Api.Authorities.CaAdministration>();
builder.Services.AddSingleton<Blinky.Pki.ICertificateAuthority, Blinky.Api.Authorities.DefaultCertificateAuthority>();

// Which certificates are connectors is a table, not a setting: a connector is
// registered by the enrolment that issued its certificate and withdrawn from
// the console (0102). Registered unconditionally, because the routes that ask
// are only reachable when a connector transport is configured anyway.
builder.Services.AddSingleton(services =>
    new Blinky.Api.Security.ConnectorIdentities(services.GetRequiredService<Database>()));

// The directory, or an honest absence of one. Registered either way so the
// endpoints exist and answer "there is no directory here" rather than failing
// to resolve a service - a deployment without one is a normal deployment, with
// cardholders entered by hand.
// What the console offers for download: the connector and agent MSIs and the scripts
// that install them, with a manifest the install scripts check against (0105).
builder.Services.AddSingleton(new Blinky.Api.Distribution.Downloads(
    builder.Configuration["Blinky:Downloads:Path"] ?? "/var/lib/blinky/downloads"));

// Via=Connector reads Active Directory through the ADCS connector, as the domain account
// it runs as, so this host keeps no bind password for the domain (0104). The connector
// is looked up at each read: since 0108 the CA in front of it is a row that can change
// while this runs, and a read with no Microsoft CA enabled says so in words.
var directoryViaConnector = string.Equals(
    builder.Configuration["Blinky:Directory:Via"], "Connector", StringComparison.OrdinalIgnoreCase);

builder.Services.AddSingleton<Blinky.Directory.IDirectory>(services =>
{
    if (directoryViaConnector)
    {
        var authorities = services.GetRequiredService<Blinky.Api.Authorities.CertificateAuthorities>();

        return new Blinky.Api.Credentials.ConnectorDirectory(
            () => authorities.Adcs?.Connector, builder.Configuration["Blinky:Directory:NetBiosDomain"]);
    }

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
        builder.Configuration.GetValue("Blinky:Directory:UseTls", true),

        // Read from the domain's crossRef when unset. Set it where the bind account
        // may not read the Configuration partition.
        builder.Configuration["Blinky:Directory:NetBiosDomain"]));
});

// A Microsoft CA issues on somebody's behalf only for DOMAIN\user, read from the
// directory at issuance; the built-in CA takes the subject it is given and needs none.
// Whether it is needed is decided per issuance, by the CA the profile names (0108).
builder.Services.AddSingleton(services => new Blinky.Api.Credentials.LogonNames(
    services.GetRequiredService<Blinky.Directory.IDirectory>(),
    required: false));

builder.Services.AddSingleton<CredentialIssuanceService>();


// Where the two master secrets live. Built once, at start, so that an
// unreachable device or a wrong PIN stops the deployment coming up instead of
// surfacing as somebody's failed enrolment an hour later. Everything above this
// line takes an IKeyProvider and cannot tell a configuration value from a
// token - see docs/06-security.md and src/Blinky.Secrets.
var secrets = KeyProviders.Read(builder.Configuration);

builder.Services.AddSingleton(secrets);

builder.Services.AddSingleton(services => KeyProviders.Build(builder.Configuration, secrets,
    services.GetRequiredService<ILoggerFactory>()));

// The key that protects every escrowed PUK. Refused rather than generated when
// absent: a KEK invented at startup would encrypt this run's PUKs with a value
// that dies with the process, and the tokens would be unrecoverable without
// anything having looked wrong.
builder.Services.AddSingleton(services => new ManagementKeyDerivation(
    services.GetRequiredService<IKeyProvider>(), secrets.ManagementKeyVersion));

builder.Services.AddSingleton(services => new PukEscrow(
    services.GetRequiredService<Database>(),
    services.GetRequiredService<IKeyProvider>(),
    secrets.PukKekVersion,
    secrets.LegacyPukKek,
    services.GetRequiredService<ILogger<PukEscrow>>()));

// Passkey provider credentials are sealed under the PUK KEK's root, in a domain
// of their own - see ProviderSecrets.
builder.Services.AddSingleton(services => new Blinky.Api.Passkeys.ProviderSecrets(
    services.GetRequiredService<IKeyProvider>(), secrets.PukKekVersion));

builder.Services.AddSingleton(services => new EnrolmentTokens(
    services.GetRequiredService<Database>(),
    () => DateTime.UtcNow,
    services.GetRequiredService<ILogger<EnrolmentTokens>>()));

builder.Services.AddSingleton(services => new AgentEnrolmentService(
    services.GetRequiredService<Database>(),
    services.GetRequiredService<AgentCertificateAuthority>(),
    services.GetRequiredService<EnrolmentTokens>(),
    services.GetRequiredService<ILogger<AgentEnrolmentService>>()));

var app = builder.Build();

// Open the key provider now rather than at the first enrolment. A module that
// is missing, a token that was never provisioned and a PIN that is wrong are
// all deployment faults, and a deployment fault belongs in the first ten lines
// of a container log rather than in a job that failed at somebody's desk.
//
// Unlike the schema check below this does not continue: a PIN attempt is
// spent when it is wrong, and a service that keeps starting and keeps trying
// locks the token.
var keys = app.Services.GetRequiredService<IKeyProvider>();

app.Logger.LogInformation(
    "Master secrets: {Provider} - {Custody}. Keys present: {Keys}",
    keys.Name,
    keys.Custody.Description,
    keys.Keys.Count == 0 ? "none" : string.Join(", ", keys.Keys.Select(k => k.Label)));

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

// The first way in, created once and only when there is nobody at all.
//
// The CA and the profiles .env described, imported into their tables the first time
// this build starts against a database that has none (0108). Before the console can
// be used, so the first page an administrator opens shows what is actually issuing.
if (schema.IsValid)
{
    Blinky.Api.Authorities.CaSeed.Import(
        app.Services.GetRequiredService<Database>(), app.Configuration, app.Logger);
}

// A deployment that has no accounts has no way to make one, which is the
// bootstrap problem 0053d names: a smart card cannot be required to sign into
// the system that issues smart cards before it has issued any. So the installer
// generates a password into a file only root can read, and it buys exactly one
// sign-in during which a real one is set.
//
// Seeded here rather than by a migration because it has to be conditional on
// the table being empty, and "empty" is a question about the database at start
// rather than about the schema.
if (schema.IsValid)
{
    var bootstrapPassword = builder.Configuration["Blinky:Bootstrap:Password"] ?? string.Empty;
    var bootstrapUsername = builder.Configuration["Blinky:Bootstrap:Username"] ?? "superadmin";

    if (string.IsNullOrWhiteSpace(bootstrapPassword))
    {
        app.Logger.LogWarning(
            "No bootstrap password configured, so no administrator exists and nobody can "
            + "sign in. Set BOOTSTRAP_ADMIN_PASSWORD and restart.");
    }
    else
    {
        using var seeding = new Database(connectionString).OpenSession();
        using var transaction = seeding.BeginTransaction();

        if (!seeding.Query<OperatorAccount>().Any())
        {
            var now = DateTime.UtcNow;

            seeding.Save(new OperatorAccount
            {
                Username = bootstrapUsername.Trim().ToLowerInvariant(),
                DisplayName = "Bootstrap administrator",
                PasswordHash = PasswordHash.Create(bootstrapPassword),
                Role = Blinky.Domain.OperatorRole.Administrator,
                State = Blinky.Domain.OperatorAccountState.Active,

                // Both true at once on purpose. The generated password is in a
                // file, a terminal history and a support bundle, and an account
                // with no second factor is an account with one.
                MustChangePassword = true,
                CreatedAt = now,
                UpdatedAt = now,
            });

            transaction.Commit();

            app.Logger.LogWarning(
                "Created the bootstrap administrator {Username}. It must change its password "
                + "and enrol a second factor before it can do anything.", bootstrapUsername);
        }
    }
}

app.UseSerilogRequestLogging();
// Explicitly, and before the middleware below, because that middleware asks
// which route was matched. Without this call routing runs at the end of the
// pipeline, GetEndpoint() returns null on the way in, and every parameterised
// operator route falls through to the certificate check.
app.UseRouting();

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
        // An ADCS connector joins through the same door, because it is the same
        // problem: a machine with no certificate asking for one. Which row it
        // becomes is decided by the token it holds, not by this field (0102).
        if (string.Equals(request.Purpose, "connector", StringComparison.OrdinalIgnoreCase))
        {
            var connector = enrolment.EnrolConnector(request);

            return connector.Outcome switch
            {
                EnrolmentOutcome.Issued => Results.Ok(connector.Response),
                EnrolmentOutcome.InvalidToken =>
                    Results.Json(new { error = connector.Message }, statusCode: 401),
                EnrolmentOutcome.InvalidRequest =>
                    Results.Json(new { error = connector.Message }, statusCode: 400),
                _ => Results.Json(new { error = connector.Message }, statusCode: 403),
            };
        }

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

// The ADCS connector asking for calls to make against its CA, when it is the one that
// dials - docs/15. Long-polled: a quiet API holds the request open for up to
// AdcsQueue.MaximumWaitSeconds and then answers 204, so a call is collected within a
// round trip instead of a polling interval. Who may reach these is decided in
// AgentAuthenticationMiddleware, by fingerprint.
if (app.Services.GetService<Blinky.Pki.Adcs.ConnectorQueue>() is not null)
{
    app.MapGet(AdcsQueue.NextPath,
        async (int? wait, Blinky.Pki.Adcs.ConnectorQueue queue, CancellationToken ct) =>
        {
            var seconds = Math.Clamp(wait ?? AdcsQueue.MaximumWaitSeconds, 1, AdcsQueue.MaximumWaitSeconds);
            var item = await queue.NextAsync(TimeSpan.FromSeconds(seconds), ct);

            return item is null ? Results.NoContent() : Results.Ok(item);
        });

    app.MapPost(AdcsQueue.ResultPath,
        (AdcsWorkResult result, Blinky.Pki.Adcs.ConnectorQueue queue, ILogger<Program> logger) =>
        {
            if (queue.Complete(result))
            {
                return Results.NoContent();
            }

            // Gone rather than not found: the call existed and its caller stopped
            // waiting. For a submission that means a certificate the CA may hold and
            // Blinky does not, so the connector logs it where somebody will look.
            logger.LogWarning("A connector answered call {Id}, which nobody was waiting for any more", result.Id);

            return Results.Json(
                new AdcsProblem("Nobody is waiting for this call any more; it timed out on the API's side."),
                statusCode: StatusCodes.Status410Gone);
        });
}

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
    async (Guid id, JobResult result, HttpContext context, JobService jobs,
        Blinky.Api.Passkeys.PasskeyProvisioningService passkeys, CancellationToken ct) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        if (!jobs.Complete(agent.Id, result with { JobId = id }))
        {
            return Results.Json(new { error = "this job is not yours to finish" }, statusCode: 403);
        }

        // A FIDO2 job that ended with its ceremony still open leaves a pending
        // registration at the provider. Cleaned up here, where the ending is
        // learned, rather than by a sweep that finds it later.
        await passkeys.JobEndedAsync(id, result with { JobId = id }, ct);

        return Results.NoContent();
    });

// FIDO2, the agent's half. The key is ready: the provider is asked for a
// challenge now and not earlier, because its lifetime starts when it is asked.
app.MapPost("/api/jobs/{id:guid}/fido2/ready",
    (Guid id, Fido2Ready ready, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProvisioningService passkeys, CancellationToken ct) =>
        Passkey(async () => Results.Ok(await passkeys.ReadyAsync(
            ((Agent)context.Items["agent"]!).Id, id, ready with { JobId = id }, ct))));

app.MapPost("/api/jobs/{id:guid}/fido2/result",
    (Guid id, Fido2CeremonyResult result, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProvisioningService passkeys, CancellationToken ct) =>
        Passkey(async () => Results.Ok(await passkeys.ResultAsync(
            ((Agent)context.Items["agent"]!).Id, id, result with { JobId = id }, ct))));

// Creating work belongs to an operator, never to an agent: the API creates
// jobs on request and never decides on its own that work exists.
//
// Who the operator is comes from a session - see the /api/auth routes below
// and patch 0053b. There is no second way in.

var signIn = new OperatorSignIn(() => DateTime.UtcNow);
var sessions = new OperatorSessions(() => DateTime.UtcNow);

// ---------------------------------------------------------------------------
// Signing in. Patches 0086 and 0053b.
//
// Every step re-presents the password rather than carrying a half-finished
// sign-in around on a ticket. A pending credential is a credential: it can be
// stolen, it has to expire, and it needs its own storage and its own rules.
// Asking for the password again costs a page that already has it nothing, and
// leaves exactly one kind of token in this system.
// ---------------------------------------------------------------------------

OperatorAccount? FindOperator(NHibernate.ISession session, string? username) =>
    string.IsNullOrWhiteSpace(username)
        ? null
        : session.Query<OperatorAccount>()
            .FirstOrDefault(a => a.Username == username.Trim().ToLowerInvariant());

// The second factor's secret, handed out while it is still unconfirmed.
//
// Generated once and kept, so reloading the page during enrolment shows the
// same QR code rather than silently invalidating the one already scanned. It
// stops being available the moment a code proves somebody has it.
app.MapPost("/api/auth/totp/enrol",
    (SignInRequest request, Database database) =>
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var account = FindOperator(session, request.Username);
        var outcome = signIn.WithPassword(account, request.Password ?? string.Empty);

        session.Flush();
        transaction.Commit();

        if (outcome.Outcome is not (SignInOutcome.TotpEnrolmentRequired
            or SignInOutcome.PasswordChangeRequired))
        {
            return Results.Json(new { error = "that is not where this account is" },
                statusCode: 409);
        }

        if (account!.TotpConfirmedAt is not null)
        {
            return Results.Json(new { error = "this account already has a second factor" },
                statusCode: 409);
        }

        using var writing = database.OpenSession();
        using var write = writing.BeginTransaction();

        var fresh = FindOperator(writing, request.Username)!;
        fresh.TotpSecret ??= Totp.NewSecret();
        fresh.UpdatedAt = DateTime.UtcNow;
        writing.Update(fresh);
        write.Commit();

        return Results.Ok(new
        {
            secret = fresh.TotpSecret,
            uri = Totp.ProvisioningUri("Blinky", fresh.Username, fresh.TotpSecret!),
        });
    });

// The whole sign-in, in one request when the account is settled and two while
// it is not. The reply says what is missing rather than only that it failed.
app.MapPost("/api/auth/sign-in",
    (SignInRequest request, HttpContext context, Database database) =>
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var account = FindOperator(session, request.Username);
        var first = signIn.WithPassword(account, request.Password ?? string.Empty);

        // Persisted whatever happened: a failed attempt that is not written
        // down is an attempt that never counted towards the lockout.
        if (account is not null)
        {
            session.Update(account);
        }

        transaction.Commit();

        switch (first.Outcome)
        {
            case SignInOutcome.Refused:
                return Results.Json(new { error = "that did not work" }, statusCode: 401);

            case SignInOutcome.LockedOut:
                return Results.Json(new
                {
                    error = "too many attempts",
                    until = first.LockedUntil,
                }, statusCode: 423);

            case SignInOutcome.PasswordChangeRequired:
                return Results.Ok(new { outcome = "password-change-required" });

            case SignInOutcome.TotpEnrolmentRequired
                when string.IsNullOrWhiteSpace(request.TotpCode)
                     || string.IsNullOrEmpty(account!.TotpSecret):

                // Only when there is nothing to check yet. An account that has
                // been given a secret and is now presenting a code is finishing
                // its enrolment, and falling through to the same verification
                // is the whole of what "confirmed by use" means. Returning here
                // regardless was a dead end: the secret could be handed out and
                // never confirmed, so the account could never finish signing in
                // at all. Every unit test passed, because the state machine was
                // right and this branch was not.
                return Results.Ok(new { outcome = "totp-enrolment-required" });
        }

        if (string.IsNullOrWhiteSpace(request.TotpCode))
        {
            return Results.Ok(new { outcome = "totp-required" });
        }

        using var second = database.OpenSession();
        using var finishing = second.BeginTransaction();

        var confirming = FindOperator(second, request.Username)!;
        var result = signIn.WithTotp(confirming, request.TotpCode);
        second.Update(confirming);

        if (result.Outcome != SignInOutcome.SignedIn)
        {
            finishing.Commit();

            return result.Outcome == SignInOutcome.LockedOut
                ? Results.Json(new { error = "too many attempts", until = result.LockedUntil },
                    statusCode: 423)
                : Results.Json(new { error = "that code did not work" }, statusCode: 401);
        }

        var (issued, token) = sessions.Issue(confirming.Id,
            context.Connection.RemoteIpAddress?.ToString());

        second.Save(issued);
        finishing.Commit();

        // The token leaves this process once, into a cookie no script can
        // read, and is never in the body (0101). What the console gets back is
        // who it is - enough to draw the shell, useless to anybody who steals it.
        SessionCookie.Issue(
            context.Response,
            token,
            SessionCookie.NewCsrfToken(),
            issued.AbsoluteExpiresAt);

        return Results.Ok(new
        {
            outcome = "signed-in",
            expires = issued.AbsoluteExpiresAt,
            operatorName = confirming.DisplayName,
            role = confirming.Role.ToString(),
        });
    });

// Changing the password, which is how the bootstrap closes.
app.MapPost("/api/auth/password",
    (PasswordChangeRequest request, Database database) =>
    {
        if (string.IsNullOrWhiteSpace(request.NewPassword) || request.NewPassword.Length < 12)
        {
            return Results.Json(new
            {
                error = "a password for this console is at least twelve characters",
                detail = "Length is the only rule here on purpose: composition rules push "
                         + "people towards one capital, one digit and one exclamation mark at "
                         + "the end, which is a smaller space than a longer phrase.",
            }, statusCode: 400);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var account = FindOperator(session, request.Username);
        var outcome = signIn.WithPassword(account, request.CurrentPassword ?? string.Empty);

        if (outcome.Outcome is SignInOutcome.Refused or SignInOutcome.LockedOut)
        {
            if (account is not null)
            {
                session.Update(account);
            }

            transaction.Commit();

            return Results.Json(new { error = "that did not work" }, statusCode: 401);
        }

        signIn.SetPassword(account!, request.NewPassword);
        session.Update(account!);

        // Every session that existed under the old password ends here. A
        // password is changed either because it should be, or because somebody
        // believes it is known - and the second case is worthless if whatever
        // was signed in with it keeps working.
        var live = session.Query<OperatorSession>()
            .Where(s => s.OperatorAccountId == account!.Id && s.RevokedAt == null)
            .ToList();

        var ended = sessions.RevokeAll(live, "password changed");

        foreach (var one in live)
        {
            session.Update(one);
        }

        transaction.Commit();

        return Results.Ok(new { outcome = "password-changed", sessionsEnded = ended });
    });

// Who the caller is, and what is still outstanding for them.
app.MapGet("/api/auth/me",
    (HttpContext context, Database database) =>
    {
        var caller = SignedInOperator(context, database, sessions);

        return caller is null
            ? Results.Json(new { error = "not signed in" }, statusCode: 401)
            : Results.Ok(new
            {
                caller.Username,
                caller.DisplayName,
                role = caller.Role.ToString(),
            });
    });

// Ending this one, and ending all of them.
app.MapPost("/api/auth/sign-out",
    (HttpContext context, Database database) =>
    {
        var presented = SessionTokenFrom(context);

        if (presented is null)
        {
            return Results.Json(new { error = "not signed in" }, statusCode: 401);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var fingerprint = SessionTokens.Fingerprint(presented);
        var row = session.Query<OperatorSession>().FirstOrDefault(s => s.TokenHash == fingerprint);

        if (row is not null)
        {
            sessions.Revoke(row, "signed out");
            session.Update(row);
        }

        transaction.Commit();

        // Revoked in the database and gone from the browser. Leaving the cookie
        // behind would mean every later request carried a session the server
        // has already refused, and the console would read that as an outage.
        SessionCookie.Clear(context.Response);

        return Results.Ok(new { outcome = "signed-out" });
    });

app.MapGet("/api/auth/sessions",
    (HttpContext context, Database database) =>
    {
        var caller = SignedInOperator(context, database, sessions);

        if (caller is null)
        {
            return Results.Json(new { error = "not signed in" }, statusCode: 401);
        }

        using var session = database.OpenSession();

        var rows = session.Query<OperatorSession>()
            .Where(s => s.OperatorAccountId == caller.Id).ToList();

        return Results.Ok(sessions.Live(rows).Select(s => new
        {
            s.Id,
            s.CreatedFrom,
            s.CreatedAt,
            s.LastSeenAt,
            s.AbsoluteExpiresAt,
        }));
    });

app.MapPost("/api/auth/sessions/revoke-all",
    (HttpContext context, Database database) =>
    {
        var caller = SignedInOperator(context, database, sessions);

        if (caller is null)
        {
            return Results.Json(new { error = "not signed in" }, statusCode: 401);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var rows = session.Query<OperatorSession>()
            .Where(s => s.OperatorAccountId == caller.Id && s.RevokedAt == null).ToList();

        var ended = sessions.RevokeAll(rows, "signed out everywhere");

        foreach (var row in rows)
        {
            session.Update(row);
        }

        transaction.Commit();

        // Including the one that asked. "Everywhere" that quietly means
        // "everywhere else" is the wrong answer when somebody believes their
        // session has been taken - so this browser loses its cookies too.
        SessionCookie.Clear(context.Response);

        return Results.Ok(new { outcome = "signed-out-everywhere", sessionsEnded = ended });
    });

app.MapPost("/api/jobs/inventory",
    (InventoryJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context))
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
    (EnrolmentJobRequest request, HttpContext context, JobService jobs,
        Database database, Blinky.Api.Authorities.CaAdministration administration) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // A person, named once, instead of three strings that have to agree.
        //
        // The row wins over anything the caller also sent, the same way
        // POST /api/cardholders resolves an account: half an identity from each
        // source is the worst of both, and this is the identity the certificate
        // will assert.
        //
        // It is also the only way Job.CardholderId is ever set, which is what
        // makes a credential traceable to a person after the job is a row in a
        // table.
        var displayName = request.DisplayName;
        var upn = request.Upn;
        var objectSid = request.ObjectSid;
        Guid? cardholderId = null;

        if (request.CardholderId is { } personId)
        {
            using var people = database.OpenSession();
            var person = people.Get<Cardholder>(personId);

            if (person is null)
            {
                return Results.Json(new { error = "there is no cardholder with that id" },
                    statusCode: 404);
            }

            if (person.State != Blinky.Domain.CardholderState.Active)
            {
                return Results.Json(new
                {
                    error = "that cardholder is not active",
                    state = person.State.ToString(),
                }, statusCode: 409);
            }

            displayName = person.DisplayName;
            upn = person.Upn;
            objectSid = person.ObjectSid;
            cardholderId = person.Id;
        }

        // Refused here rather than at issuance, because a job created now fails
        // a minute later on an agent, and by then nobody is looking at the
        // thing that created it. The refusal itself is not new - the issuance
        // service has always made it - only its timing and its audience.
        var profile = administration.Find(request.ProfileName);

        if (profile is null)
        {
            return Results.Json(new
            {
                error = $"there is no enabled profile called {request.ProfileName}",
                known = administration.Profiles(enabledOnly: true).Select(p => p.Name),
            }, statusCode: 400);
        }

        // The profile decides the key and, unless the operator chose a slot, where it
        // goes (0108). The algorithm used to travel separately from the console, so one
        // card could be given RSA or ECC whatever the CA's template allowed.
        var slotId = string.IsNullOrWhiteSpace(request.SlotId) ? profile.SlotId : request.SlotId;
        var keyAlgorithm = profile.KeyAlgorithm;

        if (profile.IncludeSidExtension && string.IsNullOrWhiteSpace(objectSid))
        {
            return Results.Json(new
            {
                error = $"{profile.Name} needs a resolved objectSid and this one has none",
                detail = "Since KB5014754 a domain controller ignores a certificate mapped by "
                         + "name alone, so a logon certificate without the SID extension is one "
                         + "that will be rejected at the only moment it matters.",
            }, statusCode: 422);
        }

        if (profile.IncludeUpnSan && string.IsNullOrWhiteSpace(upn))
        {
            return Results.Json(new
            {
                error = $"{profile.Name} puts a UPN in the certificate and this one has none",
            }, statusCode: 422);
        }

        // The slot is part of the key: two credentials on one token are two
        // jobs, and re-posting the same one is not a second key on the card.
        //
        // The reason is part of it too, and deliberately the operator's to
        // supply. A job that failed on a mistyped PIN is finished as far as the
        // row is concerned, and without a way to say "this is a new attempt"
        // the same request would keep returning the dead one.
        var key = $"enrol:{request.TokenSerial}:{slotId}:{request.ProfileName}"
                  + $":{keyAlgorithm}"
                  + $":{request.Reason ?? "initial"}";

        // Whether the agent may generate over a key that is already in the
        // slot. Decided here, from this server's own record, and never from
        // the request - an operator asking for an enrolment is not thereby
        // asking to destroy a key nobody has accounted for.
        //
        // KeyPresent means Blinky put a key there and the credential is gone:
        // recycling deletes the certificate, and on some firmware the key does
        // not go with it. Without this the slot is finished - every later
        // enrolment stops on a key the operator already asked to have removed.
        //
        // Foreign is the case the refusal exists for and stays refused. So
        // does a slot this server believes is empty: if it is not, its record
        // is wrong, and acting on a wrong record by destroying a key is the
        // worst available response.
        var replaceKey = false;

        using (var session = database.OpenSession())
        {
            var slot = session.Query<Slot>()
                .FirstOrDefault(s => s.Token.Serial == request.TokenSerial
                                     && s.SlotId == slotId);

            replaceKey = slot?.State == Blinky.Domain.SlotState.KeyPresent;
        }

        var (job, created) = jobs.Create(JobType.Enroll, key,
            id => JobEnvelope.Enrolment(id, key, DateTimeOffset.UtcNow.AddHours(1),
                request.TokenSerial, slotId, request.ProfileName, displayName,
                upn, objectSid, keyAlgorithm, replaceKey,

                // For the window at the workstation (0084a): who this is for
                // and which operator asked, so a PIN prompt there is not a
                // request from nobody.
                new JobContext(JobContext.EnrolCard, displayName, upn, ActorFor(context),
                    request.ProfileName)),
            request.AgentId, cardholderId: cardholderId);

        return Results.Ok(new { job.Id, created, state = job.State.ToString() });
    });

// Taking a credential back off a token. The agent refuses to do this on its
// own - deleting something Blinky issued would leave this server holding a
// credential it believes is installed - so the order comes from here, and the
// record is corrected when the job reports back.
app.MapPost("/api/jobs/recycle",
    (RecycleJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context))
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

// A passkey for somebody, on a key that will be plugged into an agent. The user
// is resolved at the provider first: a login that does not exist is refused
// here, before anybody goes to find a key. See docs/12 and patch 0077.
app.MapPost("/api/jobs/fido2",
    (Blinky.Api.Passkeys.PasskeyJobRequest request, HttpContext context,
        Blinky.Api.Passkeys.PasskeyJobs passkeyJobs, CancellationToken ct) =>
        Passkey(async () =>
        {
            if (!IsOperator(context))
            {
                return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
            }

            var made = await passkeyJobs.CreateAsync(request, ActorFor(context), ct);

            return Results.Ok(new
            {
                made.Job.Id,
                created = made.Created,
                state = made.Job.State.ToString(),
                passkey = made.Passkey.Id,
                user = new { made.User.Id, made.User.Login, made.User.DisplayName },
            });
        }));

app.MapGet("/api/passkeys/directories",
    (HttpContext context, Blinky.Api.Passkeys.PasskeyDirectories directories) =>
        !IsOperator(context)
            ? Results.Json(new { error = "an operator token is required" }, statusCode: 401)
            : Results.Ok(new
            {
                directories = directories.All.Select(d => new { d.Name, d.Capabilities }),
                analysisOnly = Blinky.Api.Passkeys.AnalysisOnlyDirectory.All,
            }));

// The providers themselves (0107). Reading is any operator's; changing one is an
// administrator's, because it decides where a credential is registered and holds
// the secret that lets Blinky do it.
app.MapGet("/api/passkeys/providers",
    (HttpContext context, Blinky.Api.Passkeys.PasskeyProviders providers) =>
        !IsOperator(context)
            ? Results.Json(new { error = "an operator token is required" }, statusCode: 401)
            : Results.Ok(providers.List()));

app.MapPost("/api/passkeys/providers",
    (Blinky.Api.Passkeys.PasskeyProviderRequest request, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProviders providers) =>
        Passkey(() => Task.FromResult(!IsAdministrator(context)
            ? Results.Json(new { error = "an administrator is required" }, statusCode: 403)
            : Results.Ok(providers.Create(request, ActorFor(context))))));

app.MapPut("/api/passkeys/providers/{id:guid}",
    (Guid id, Blinky.Api.Passkeys.PasskeyProviderRequest request, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProviders providers) =>
        Passkey(() => Task.FromResult(!IsAdministrator(context)
            ? Results.Json(new { error = "an administrator is required" }, statusCode: 403)
            : Results.Ok(providers.Update(id, request, ActorFor(context))))));

app.MapDelete("/api/passkeys/providers/{id:guid}",
    (Guid id, HttpContext context, Blinky.Api.Passkeys.PasskeyProviders providers) =>
        Passkey(() =>
        {
            if (!IsAdministrator(context))
            {
                return Task.FromResult(Results.Json(new { error = "an administrator is required" }, statusCode: 403));
            }

            providers.Delete(id, ActorFor(context));
            return Task.FromResult(Results.NoContent());
        }));

// Blinky makes the key and keeps it; the answer carries the public half only.
app.MapPost("/api/passkeys/providers/{id:guid}/generate-credential",
    (Guid id, HttpContext context, Blinky.Api.Passkeys.PasskeyProviders providers) =>
        Passkey(() => Task.FromResult(!IsAdministrator(context)
            ? Results.Json(new { error = "an administrator is required" }, statusCode: 403)
            : Results.Ok(providers.GenerateCredential(id, ActorFor(context))))));

// A credential the administrator brought: sealed on arrival, never sent back.
app.MapPost("/api/passkeys/providers/{id:guid}/credential",
    (Guid id, Blinky.Api.Passkeys.PasskeyCredentialImport import, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProviders providers) =>
        Passkey(() => Task.FromResult(!IsAdministrator(context)
            ? Results.Json(new { error = "an administrator is required" }, statusCode: 403)
            : Results.Ok(providers.ImportCredential(id, import, ActorFor(context))))));

app.MapPost("/api/passkeys/providers/{id:guid}/test",
    (Guid id, HttpContext context, Blinky.Api.Passkeys.PasskeyProviders providers, CancellationToken ct) =>
        Passkey(async () => !IsAdministrator(context)
            ? Results.Json(new { error = "an administrator is required" }, statusCode: 403)
            : Results.Ok(new { message = await providers.TestAsync(id, ct) })));

// One passkey, for the console following a ceremony. The row's state is the step.
app.MapGet("/api/passkeys/{id:guid}",
    (Guid id, HttpContext context, Blinky.Api.Passkeys.PasskeyProvisioningService passkeys) =>
        Passkey(() => Task.FromResult(!IsOperator(context)
            ? Results.Json(new { error = "an operator token is required" }, statusCode: 401)
            : Results.Ok(passkeys.Status(id)))));

// The database and the provider side by side. Disagreement is shown, not fixed:
// a method somebody deleted at the provider, or a key the user enrolled alone,
// is something an operator should see rather than something Blinky decides.
app.MapGet("/api/passkeys",
    (string directory, string user, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProvisioningService passkeys, CancellationToken ct) =>
        Passkey(async () =>
        {
            if (!IsOperator(context))
            {
                return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
            }

            var resolved = await passkeys.ResolveAsync(directory, user, ct);
            return Results.Ok(new { user = resolved, passkeys = await passkeys.ListAsync(directory, resolved, ct) });
        }));

// Deleted at the provider first, marked here second. Never the other way round:
// a row reading Revoked over a credential that still signs somebody in is the
// one failure this ordering exists to prevent.
app.MapPost("/api/passkeys/{id:guid}/revoke",
    (Guid id, PasskeyRevokeRequest request, HttpContext context,
        Blinky.Api.Passkeys.PasskeyProvisioningService passkeys, CancellationToken ct) =>
        Passkey(async () =>
        {
            if (!IsOperator(context))
            {
                return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
            }

            if (string.IsNullOrWhiteSpace(request.Reason))
            {
                return Results.Json(new { error = "a revocation needs a reason" }, statusCode: 400);
            }

            var revoked = await passkeys.RevokeAsync(id, request.Reason, ActorFor(context), ct);
            return Results.Ok(new { id, state = revoked.State.ToString(), revoked.RevokedAt });
        }));

// A workstation asking for a passkey on the key in its reader (0109). Asking, not
// doing: the row waits for an operator, and only an operator's approval makes a
// job. Any agent may ask about any token, as with /credentials above - holding
// the key is what it takes to ask, and the console sees which machine did.
app.MapPost("/api/tokens/{serial:long}/passkey-request",
    (long serial, HttpContext context, Blinky.Api.Passkeys.PasskeyRequests requests) =>
        Passkey(() => Task.FromResult(Results.Ok(
            requests.Ask(((Agent)context.Items["agent"]!).Id, serial)))));

app.MapGet("/api/tokens/{serial:long}/passkey-request",
    (long serial, HttpContext context, Blinky.Api.Passkeys.PasskeyRequests requests) =>
    {
        _ = (Agent)context.Items["agent"]!;

        return requests.Latest(serial) is { } latest ? Results.Ok(latest) : Results.NoContent();
    });

app.MapGet("/api/passkeys/requests",
    (string? state, HttpContext context, Blinky.Api.Passkeys.PasskeyRequests requests) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
        }

        if (state is not null && !Enum.TryParse<Blinky.Domain.PasskeyRequestState>(state, true, out _))
        {
            return Results.Json(new { error = "state is Pending, Approved or Rejected" }, statusCode: 400);
        }

        return Results.Ok(requests.List(state is null
            ? null
            : Enum.Parse<Blinky.Domain.PasskeyRequestState>(state, true)));
    });

app.MapPost("/api/passkeys/requests/{id:guid}/approve",
    (Guid id, Blinky.Api.Passkeys.PasskeyRequestApproval approval, HttpContext context,
        Blinky.Api.Passkeys.PasskeyRequests requests, CancellationToken ct) =>
        Passkey(async () =>
        {
            if (!IsOperator(context))
            {
                return Results.Json(new { error = "an operator token is required" }, statusCode: 401);
            }

            var made = await requests.ApproveAsync(id, approval, ActorFor(context), ct);

            return Results.Ok(new
            {
                id,
                job = made.Job.Id,
                made.Created,
                passkey = made.Passkey.Id,
                user = new { made.User.Id, made.User.Login, made.User.DisplayName },
            });
        }));

app.MapPost("/api/passkeys/requests/{id:guid}/reject",
    (Guid id, PasskeyRevokeRequest request, HttpContext context,
        Blinky.Api.Passkeys.PasskeyRequests requests) =>
        Passkey(() =>
        {
            if (!IsOperator(context))
            {
                return Task.FromResult(Results.Json(new { error = "an operator token is required" }, statusCode: 401));
            }

            requests.Reject(id, request.Reason, ActorFor(context));
            return Task.FromResult(Results.Ok(new { id, state = "Rejected" }));
        }));

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
        catch (Blinky.Pki.CertificateAuthorityException ex)
        {
            // The CA, or the connector in front of it, could not do it. Said as a
            // 502 with the CA's own sentence, because the agent copies this body
            // into the job's result and that is what the console shows: unhandled,
            // the first enrolment through MS-CONN01 failed as "Issuance refused:
            // 500" while the log said exactly which setting was missing.
            return Results.Json(new { error = ex.Message }, statusCode: 502);
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
// ------------------------------------------------------------- deployment
//
// One view of what this installation is made of, for the console's status
// page: which CA, where its key lives, whether the revocation list is current,
// whether there is a directory, and whether the worker has been heard from.
//
// Assembled here rather than left to the console to infer from five calls,
// because "is this deployment healthy" is one question and answering it from
// pieces is how a console ends up saying yes while one piece says no.
// What is wrong with the configured Microsoft CA before anybody enrols - 0033.
//
// A separate call from the status page, because it is expensive in a way the
// status page must not be: it asks the CA, reads every mapped template out of the
// directory, and opens the enrolment agent on the connector. The console asks it
// when an operator opens the CA page, not every few seconds.
//
// "Registration" is what the roadmap calls this, and there is no registration
// flow yet - CA instances are not rows until 0022's open half lands. So this is
// the check that flow will run, available now against the one CA the
// configuration names.
app.MapGet("/api/system/ca/checks",
    async (HttpContext context, Blinky.Api.Authorities.CertificateAuthorities authorities,
        CancellationToken ct) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // The CA itself rather than the container's ICertificateAuthority, which since
        // 0108 is a proxy and would never be the Microsoft CA this asks about.
        var ca = authorities.Default;

        if (ca is not Blinky.Pki.Adcs.AdcsCertificateAuthority adcs)
        {
            // Not an empty list: an empty list reads as "checked and fine", and
            // nothing here was checked.
            return Results.Ok(new
            {
                name = ca.Name,
                backend = CaBackend.BuiltIn.ToString(),
                checkedHere = false,
                outcome = (string?)null,
                findings = Array.Empty<object>(),
            });
        }

        var report = await adcs.CheckRegistrationAsync(ct);

        return Results.Ok(new
        {
            name = report.CaName,
            backend = CaBackend.Adcs.ToString(),
            checkedHere = true,
            outcome = report.Outcome.ToString(),
            findings = report.Findings.Select(finding => new
            {
                finding.Code,
                severity = finding.Severity.ToString(),
                finding.Message,
            }),
        });
    });

app.MapGet("/api/system/status",
    async (HttpContext context, Blinky.Api.Authorities.CertificateAuthorities authorities,
        Blinky.Directory.IDirectory directory, IConfiguration configuration,
        Database database, IKeyProvider keyProvider,
        KeyProviders.SecretsOptions secretsOptions, CancellationToken ct) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var ca = authorities.Default;

        // A built-in CA answers from this process and cannot fail here. A
        // Microsoft CA answers through a connector on another machine, and a
        // status page that returned 500 because that machine was rebooting
        // would hide the one fact worth showing - so an unreachable CA is part
        // of the status rather than a failure of it.
        Blinky.Pki.CaCapabilities? capabilities = null;
        string? caProblem = null;

        try
        {
            capabilities = await ca.DescribeAsync(ct);
        }
        catch (Blinky.Pki.CertificateAuthorityException ex)
        {
            caProblem = ex.Message;
        }

        var built = ca as Blinky.Pki.BuiltIn.BuiltInCertificateAuthority;
        var adcs = ca as Blinky.Pki.Adcs.AdcsCertificateAuthority;

        // The CRL is read from the file the worker writes rather than built
        // here: one producer, so the status reports what is actually published
        // rather than what this process would publish if asked.
        var crlPath = configuration["Blinky:Ca:CrlFile"] ?? "/var/lib/blinky/pki/issuing.crl";

        DateTimeOffset? crlThisUpdate = null;
        DateTimeOffset? crlNextUpdate = null;
        var crlPublished = File.Exists(crlPath);

        if (crlPublished)
        {
            // From the file's timestamp and the configured validity rather than
            // by parsing the list. The worker writes the file at the moment it
            // builds the CRL, so the two agree - and a parse that has to reach
            // into an ASN.1 structure for one field is a thing that breaks
            // quietly on a runtime upgrade.
            crlThisUpdate = File.GetLastWriteTimeUtc(crlPath);

            crlNextUpdate = crlThisUpdate.Value.AddHours(
                configuration.GetValue("Blinky:Ca:CrlValidityHours", 8));
        }

        using var session = database.OpenSession();

        var agents = session.Query<Agent>().ToList();
        var lastHeartbeat = agents.Count == 0
            ? (DateTime?)null
            : agents.Max(a => a.LastHeartbeatAt);

        return Results.Ok(new
        {
            certificateAuthority = new
            {
                name = ca.Name,
                backend = (capabilities?.Backend ?? (adcs is null ? CaBackend.BuiltIn : CaBackend.Adcs))
                    .ToString(),

                // Additive: false with a reason when a connector did not answer.
                reachable = caProblem is null,
                problem = caProblem,
                transport = adcs?.TransportDescription,
                enrolmentAgent = adcs?.AgentDescription,

                topology = built?.Topology.ToString(),
                issuer = built?.Issuer.Subject,
                anchor = built?.TrustAnchor.Subject,
                anchorNotAfter = built?.TrustAnchor.NotAfter,

                // Whether this configuration can produce a certificate a domain
                // controller will accept for logon. False is not a defect - it
                // means the configuration cannot, and says so before anybody
                // enrols.
                canIssueLogonCredentials = capabilities?.CanIssueSmartCardLogon ?? false,
                supportsRevocation = capabilities?.SupportsRevocation ?? false,
                publishesCrl = capabilities?.PublishesCrl ?? false,
            },

            // Where the signing key lives. Present now, with one tier
            // implemented, so the shape does not change when SoftHSM and a
            // device arrive - see docs/04-pki-backends.md.
            keyCustody = built is null ? null : new
            {
                tier = built.Custody.Tier.ToString(),
                built.Custody.Description,
                built.Custody.ProductionReady,
                built.Custody.Detail,

                // What this deployment could move to. Listed rather than
                // hardcoded in the console, so the console does not have to
                // know which tiers exist.
                available = new[]
                {
                    new { tier = "File", implemented = true,
                          detail = "An encrypted PKCS#12 on a volume." },
                    new { tier = "SoftHsm", implemented = false,
                          detail = "PKCS#11 against SoftHSM: the interface of a device, on a "
                                   + "disk. A rehearsal for the real thing rather than a "
                                   + "protection against somebody with root here." },
                    new { tier = "Hsm", implemented = false,
                          detail = "A PKCS#11 device that will not export the key at all." },
                },
            },

            // Where the two master secrets live, which provider answered, and
            // what has been asked of it since this process started. Named
            // separately from keyCustody above because they are two questions:
            // a deployment can hold the CA key in a device while its
            // management-key master is still a configuration value, and a
            // console that reported one number for both would hide that.
            //
            // No PIN, no module configuration beyond the path, and no key
            // material. The labels are not secret - they are derived from the
            // purpose and the version, and an operator has to be able to match
            // them against what the token holds.
            secrets = new
            {
                provider = keyProvider.Name,

                custody = new
                {
                    keyProvider.Custody.Tier,
                    keyProvider.Custody.Description,
                    keyProvider.Custody.ProductionReady,
                    keyProvider.Custody.Detail,
                },

                // What this deployment writes with now. An older generation
                // stays readable; these are the ones new material is created
                // under.
                writingWith = new
                {
                    managementKey = secretsOptions.ManagementKeyVersion,
                    pukKek = secretsOptions.PukKekVersion,
                },

                // Every generation the provider actually found, which is not
                // the same list: a rotation that was configured but never
                // provisioned looks exactly like one that worked, until an
                // enrolment.
                keys = keyProvider.Keys
                    .OrderBy(k => k.Key.Purpose)
                    .ThenBy(k => k.Key.Version)
                    .Select(k => new
                    {
                        purpose = k.Key.Purpose.ToString(),
                        version = k.Key.Version,
                        k.Label,
                        k.NonExportable,
                        usage = Usage(keyProvider, k.Key),
                    }),

                // The state docs/06-security.md calls supported rather than
                // broken: no master means every card keeps its factory
                // management key.
                managementKeyMasterConfigured = keyProvider.Has(
                    new KeyRef(KeyPurpose.ManagementKeyMaster,
                        secretsOptions.ManagementKeyVersion)),

                // Whether anything can still open the PUKs escrowed before the
                // provider existed. Worth saying out loud, because the answer
                // becomes no the moment somebody tidies the old value out of
                // the environment.
                legacyPukEnvelopesReadable = secretsOptions.LegacyPukKek.Length > 0,
            },

            revocationList = new
            {
                published = crlPublished,
                path = crlPath,
                thisUpdate = crlThisUpdate,
                nextUpdate = crlNextUpdate,

                // The one that matters. An expired CRL does not fail open: it
                // breaks every chain built under it, and the client reports
                // that as a problem with trust.
                expired = crlNextUpdate is { } until && until <= DateTimeOffset.UtcNow,
                url = configuration["Blinky:Ca:PublicUrl"] is { Length: > 0 } published
                    ? $"{published.TrimEnd('/')}/pki/issuing.crl"
                    : null,
            },

            directory = new
            {
                configured = directory is not Blinky.Directory.NoDirectory,
                source = directory.Source.ToString(),
                via = directory is Blinky.Api.Credentials.ConnectorDirectory ? "connector" : "ldap",
                host = directory is Blinky.Api.Credentials.ConnectorDirectory viaConnector
                    ? viaConnector.Host
                    : configuration["Blinky:Directory:Host"],
                baseDn = directory is Blinky.Api.Credentials.ConnectorDirectory throughConnector
                    ? throughConnector.BaseDn
                    : configuration["Blinky:Directory:BaseDn"],
                boundAs = directory is Blinky.Api.Credentials.ConnectorDirectory
                    ? "the ADCS connector's service account, with Kerberos"
                    : configuration["Blinky:Directory:BindDn"] is { Length: > 0 } bind
                        ? bind
                        : "the container's own Kerberos credentials",

                // Never the password, not even masked. It is not sent here and
                // must not look as though it could be.
                writesAnything = false,
            },

            agents = new
            {
                total = agents.Count,
                enrolled = agents.Count(a => a.State == Blinky.Domain.AgentState.Enrolled),
                lastHeartbeatAt = lastHeartbeat,
            },
        });
    });

// ---------------------------------------------------------- the directory
//
// Gap 5 of doc 11. A smartcard-logon certificate is refused without a resolved
// objectSid, and that refusal is right: since KB5014754 a domain controller
// ignores a certificate mapped by name alone. So the SID is read from the
// directory that will later be asked to honour it, rather than typed by an
// operator who can only produce a plausible one.

// The button in the settings page. "It does not work" is not a useful answer to
// somebody who has just filled in six fields, so this says which of them was
// wrong - the host was unreachable, the bind was refused, the base was not
// there - and how long it took.
app.MapPost("/api/directory/test",
    async (HttpContext context, Blinky.Directory.IDirectory directory, CancellationToken ct) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var probe = await directory.TestAsync(ct);

        return Results.Ok(new
        {
            probe.Succeeded,
            probe.Reachable,
            probe.BaseDnFound,
            probe.BoundAs,
            probe.Encrypted,
            probe.Milliseconds,
            probe.Detail,
            source = directory.Source.ToString(),
        });
    });

// The test that matters more than the connection: take the people who would
// actually be issued to, and say which of them can be. A directory that binds
// perfectly and holds nobody with a UPN is a working connection and a failed
// rollout, and finding that out one enrolment at a time is the slow way.
app.MapPost("/api/directory/test-resolve",
    async (ResolveTestRequest request, HttpContext context,
        Blinky.Directory.IDirectory directory, CancellationToken ct) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var people = new List<Blinky.Directory.DirectoryUser>();
        var missing = new List<string>();

        if (!string.IsNullOrWhiteSpace(request.Group))
        {
            people.AddRange(await directory.MembersOfAsync(request.Group.Trim(), 200, ct));
        }

        foreach (var account in request.Accounts ?? [])
        {
            if (string.IsNullOrWhiteSpace(account))
            {
                continue;
            }

            // Named separately from "found but not issuable". An account that
            // does not exist and one that exists without a UPN are different
            // problems with different fixes.
            if (await directory.FindAsync(account.Trim(), ct) is { } person)
            {
                people.Add(person);
            }
            else
            {
                missing.Add(account.Trim());
            }
        }

        var resolved = people.Select(u => new
        {
            u.DisplayName,
            u.SamAccountName,
            u.Upn,
            u.ObjectSid,
            u.Enabled,
            issuable = u.Enabled && !string.IsNullOrEmpty(u.Upn)
                       && !string.IsNullOrEmpty(u.ObjectSid),

            // Why not, in the words somebody can act on. A smartcard-logon
            // certificate is refused without a SID, and that refusal arrives
            // at issuance unless it is said here first.
            blockedBy = !u.Enabled ? "the account is disabled"
                : string.IsNullOrEmpty(u.Upn) ? "no userPrincipalName"
                : string.IsNullOrEmpty(u.ObjectSid) ? "no objectSid could be read"
                : null,
        }).ToList();

        return Results.Ok(new
        {
            source = directory.Source.ToString(),
            found = resolved.Count,
            issuable = resolved.Count(r => r.issuable),
            notFound = missing,
            users = resolved,
        });
    });

// Whether the account this binds as could do more than read. Asked of the
// directory, never attempted: writing something to a real person's account to
// see whether it sticks is a change nobody asked for, made in order to find
// something out.
app.MapPost("/api/directory/test-write-access",
    async (WriteAccessTestRequest request, HttpContext context,
        Blinky.Directory.IDirectory directory, CancellationToken ct) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var subject = request.DistinguishedName;

        // Permissions in a directory are per object, so an account name is
        // resolved to somebody first rather than the question being asked in
        // general - there is no answer in general.
        if (string.IsNullOrWhiteSpace(subject) && !string.IsNullOrWhiteSpace(request.Account))
        {
            var person = await directory.FindAsync(request.Account.Trim(), ct);

            if (person?.DistinguishedName is null)
            {
                return Results.Json(new
                {
                    error = "that account could not be resolved, so there is nobody to ask about",
                    account = request.Account,
                }, statusCode: 404);
            }

            subject = person.DistinguishedName;
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            return Results.Json(new
            {
                error = "give an account or a distinguished name to ask about",
                detail = "Permissions are per object; there is no answer in general.",
            }, statusCode: 400);
        }

        var access = await directory.CanWriteAsync(subject, ct);

        return Results.Ok(new
        {
            subject,
            access.Determined,
            access.UserCertificate,
            access.AltSecurityIdentities,
            access.AnythingExtra,
            access.Detail,

            // What it would unlock, said here so the console does not have to
            // know the patch numbers. Nothing writes today - see 0035 - and
            // this answers whether it could, not whether it does.
            wouldEnable = access.AnythingExtra
                ? "Publishing issued certificates, and explicit certificate mappings (0035). "
                  + "Neither is implemented yet; this only says the account would be allowed."
                : "Nothing beyond reading, which is all Blinky needs today.",
        });
    });

app.MapGet("/api/directory/users",
    async (string? q, HttpContext context, Blinky.Directory.IDirectory directory,
        CancellationToken ct) =>
    {
        if (!IsOperator(context))
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

// What can be issued, and what each of them demands of the person it is issued
// to. Without this a console dropdown is a hardcoded copy of a list in the
// source, and the copy drifts the first time a profile is added.
//
// requiresObjectSid is the field that matters. smartcard-logon refuses without
// a resolved SID and that refusal is right; a page that offers the profile
// without knowing the rule posts a job that fails a minute later, somewhere the
// operator is no longer looking.
// ---- enrolment tokens (0102) ------------------------------------------------
//
// What a machine presents to join. These used to be one string in
// docker-compose.yml, the same for every agent and for the life of the
// deployment; they are rows now, with a term, a number of uses and a purpose.
//
// Created, listed and withdrawn - not edited and not deleted. A token whose
// limits can be changed after it was handed out is a token whose limits mean
// nothing, and a deleted one takes the record of what enrolled with it along
// with it. That is the same exception AuditEvent and Credential take to the
// CRUD rule, for the same reason.
app.MapPost("/api/enrol-tokens",
    (CreateEnrolTokenRequest request, HttpContext context, Database database, EnrolmentTokens tokens) =>
    {
        if (context.Items["operator"] is not OperatorAccount caller)
        {
            return Results.Json(new { error = "an operator session is required" }, statusCode: 401);
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Results.BadRequest(new { error = "a name is required: somebody has to recognise this later" });
        }

        var purpose = request.Purpose?.Trim().ToLowerInvariant() switch
        {
            null or "" or "agent" => EnrolmentPurpose.Agent,
            "connector" or "adcsconnector" or "adcs-connector" => EnrolmentPurpose.AdcsConnector,
            _ => (EnrolmentPurpose?)null,
        };

        if (purpose is null)
        {
            return Results.BadRequest(new { error = "purpose is 'agent' or 'connector'" });
        }

        try
        {
            var (row, token) = tokens.Create(
                request.Name,
                purpose.Value,
                request.ValidForDays is { } days ? TimeSpan.FromDays(days) : null,
                request.MaxUses,
                request.AllowedDomain,
                caller.Username);

            using var session = database.OpenSession();
            using var transaction = session.BeginTransaction();

            session.Save(new AuditEvent
            {
                OccurredAt = DateTime.UtcNow,
                EventType = "enrolment-token.created",
                Actor = caller.Username,
                SubjectType = nameof(EnrolmentToken),
                SubjectId = row.Id,
                Detail = $$"""{"name":"{{row.Name}}","purpose":"{{row.Purpose}}","expires":"{{row.ExpiresAt?.ToString("u") ?? "never"}}","maxUses":"{{row.MaxUses?.ToString() ?? "unlimited"}}"}""",
            });

            transaction.Commit();

            // The only time the value exists outside the holder's hands.
            return Results.Ok(new
            {
                row.Id,
                row.Name,
                purpose = row.Purpose.ToString(),
                token,
                expires = row.ExpiresAt,
                maxUses = row.MaxUses,
                allowedDomain = row.AllowedDomain,
            });
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

app.MapGet("/api/downloads",
    (HttpContext context, Blinky.Api.Distribution.Downloads downloads) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator session is required" }, statusCode: 401);
        }

        // Empty rather than 404: "nothing has been published here yet" is a state the
        // console should show as such, with the command that publishes.
        return Results.Ok(downloads.Manifest()
                          ?? new Blinky.Api.Distribution.DownloadManifest(null, null, []));
    });

app.MapGet("/api/downloads/{name}",
    (string name, HttpContext context, Blinky.Api.Distribution.Downloads downloads) =>
    {
        // A session, not a public URL: an installer that carries this deployment's
        // address is not something to hand to whoever finds the link.
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator session is required" }, statusCode: 401);
        }

        return downloads.Resolve(name) is { } found
            ? Results.File(found.Path, Blinky.Api.Distribution.Downloads.ContentType(found.Entry.File),
                found.Entry.File, enableRangeProcessing: true)
            : Results.Json(new { error = "no such download" }, statusCode: 404);
    });

// A workstation or a CA's neighbour fetching its own package (0110), on the agents'
// listener: the bootstrap script first, anonymous because it holds nothing but the
// server's name, then the package, by agent certificate or enrolment token. Until this
// an installer reached a machine only through an operator's browser.
app.MapGet("/install/{name}",
    (string name, Blinky.Api.Distribution.Downloads downloads) =>
        downloads.Resolve(name) is { Entry.Kind: "bootstrap" } found
            ? Results.File(found.Path, "text/plain; charset=utf-8")
            : Results.NotFound());

app.MapGet(AgentAuthenticationMiddleware.MachineDownloadsPath + "/{purpose}",
    (string purpose, HttpContext context, Blinky.Api.Distribution.Downloads downloads,
        Blinky.Api.Agents.EnrolmentTokens tokens) =>
        MachineAdmitted(context, purpose, tokens) is not { } set
            ? Results.Json(new { error = "an enrolled agent's certificate or an enrolment token for it is required" },
                statusCode: 401)
            : Results.Ok(new
            {
                manifest = downloads.Manifest() is { } m
                    ? m with { Files = m.Files.Where(f => Blinky.Api.Distribution.Downloads.Belongs(f.File, set)).ToList() }
                    : null,
            }));

app.MapGet(AgentAuthenticationMiddleware.MachineDownloadsPath + "/{purpose}/{name}",
    (string purpose, string name, HttpContext context, Blinky.Api.Distribution.Downloads downloads,
        Blinky.Api.Agents.EnrolmentTokens tokens) =>
        MachineAdmitted(context, purpose, tokens) is not { } set
            ? Results.Json(new { error = "an enrolled agent's certificate or an enrolment token for it is required" },
                statusCode: 401)
            : Blinky.Api.Distribution.Downloads.Belongs(name, set) && downloads.Resolve(name) is { } found
                ? Results.File(found.Path, Blinky.Api.Distribution.Downloads.ContentType(found.Entry.File),
                    found.Entry.File, enableRangeProcessing: true)
                : Results.Json(new { error = "no such download" }, statusCode: 404));

app.MapGet("/api/enrol-tokens",
    (HttpContext context, EnrolmentTokens tokens) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator session is required" }, statusCode: 401);
        }

        var now = DateTime.UtcNow;

        // No hashes and no values: the list says what exists and what it can
        // still do, which is what somebody deciding whether to revoke needs.
        return Results.Ok(tokens.All().Select(t => new
        {
            t.Id,
            t.Name,
            purpose = t.Purpose.ToString(),
            expires = t.ExpiresAt,
            maxUses = t.MaxUses,
            t.Uses,
            allowedDomain = t.AllowedDomain,
            t.CreatedBy,
            t.CreatedAt,
            t.RevokedAt,
            t.RevokedBy,
            usable = t.IsUsable(now),
            spent = t.Spent(now),
        }));
    });

app.MapPost("/api/enrol-tokens/{id:guid}/revoke",
    (Guid id, RevokeEnrolTokenRequest? request, HttpContext context, Database database, EnrolmentTokens tokens) =>
    {
        if (context.Items["operator"] is not OperatorAccount caller)
        {
            return Results.Json(new { error = "an operator session is required" }, statusCode: 401);
        }

        var row = tokens.Revoke(id, caller.Username, request?.Reason);

        if (row is null)
        {
            return Results.NotFound(new { error = "no such token" });
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        session.Save(new AuditEvent
        {
            OccurredAt = DateTime.UtcNow,
            EventType = "enrolment-token.revoked",
            Actor = caller.Username,
            SubjectType = nameof(EnrolmentToken),
            SubjectId = row.Id,
            Detail = $$"""{"name":"{{row.Name}}","reason":"{{request?.Reason ?? "none given"}}"}""",
        });

        transaction.Commit();

        return Results.Ok(new { row.Id, row.Name, row.RevokedAt, row.RevokedBy });
    });

app.MapGet("/api/profiles",
    (HttpContext context, Blinky.Api.Authorities.CaAdministration administration) =>
    {
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // The enabled ones, in the shape the enrolment dialog has read since 0052, from
        // the table since 0108 - with the slot and the CA it would now go to.
        return Results.Ok(administration.Profiles(enabledOnly: true).Select(p => new
        {
            p.Name,
            p.Description,
            requiresUpn = p.IncludeUpnSan,
            requiresObjectSid = p.IncludeSidExtension,
            keyAlgorithm = p.KeyAlgorithm,
            days = p.ValidityDays,
            slotId = p.SlotId,
            ca = p.CaInstanceName,
            backend = p.Backend,
            extendedKeyUsage = p.ExtendedKeyUsages.Select(ExtendedKeyUsageName),
        }));
    });

// Certificate authorities and certificate profiles, from the console (0108). Read by any
// operator, because the enrolment dialog and the status page show them; written by an
// administrator, because a wrong template or CA name stops every enrolment.
app.MapGet("/api/ca-instances",
    (HttpContext context, Blinky.Api.Authorities.CaAdministration administration) =>
        !IsOperator(context)
            ? Results.Json(new { error = "an operator token is required" }, statusCode: 401)
            : Results.Ok(administration.Instances()));

app.MapPost("/api/ca-instances",
    (Blinky.Api.Authorities.CaInstanceRequest request, HttpContext context,
        Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () => Results.Ok(administration.Create(request, ActorFor(context)))));

app.MapPut("/api/ca-instances/{id:guid}",
    (Guid id, Blinky.Api.Authorities.CaInstanceRequest request, HttpContext context,
        Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () => Results.Ok(administration.Update(id, request, ActorFor(context)))));

app.MapDelete("/api/ca-instances/{id:guid}",
    (Guid id, HttpContext context, Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () =>
        {
            administration.DeleteInstance(id, ActorFor(context));
            return Results.NoContent();
        }));

// What the CA says about itself, through the connector for ADCS - the check that would
// have shown MS-CONN01's empty CA name before anybody enrolled a card.
app.MapPost("/api/ca-instances/{id:guid}/test",
    async (Guid id, HttpContext context, Blinky.Api.Authorities.CaAdministration administration,
        CancellationToken ct) =>
    {
        if (!IsAdministrator(context))
        {
            return Results.Json(new { error = "an administrator is required" }, statusCode: 403);
        }

        try
        {
            return Results.Ok(await administration.TestAsync(id, ct));
        }
        catch (Blinky.Pki.CertificateAuthorityException e)
        {
            return Results.Json(new { error = e.Message }, statusCode: 502);
        }
    });

app.MapGet("/api/certificate-profiles",
    (HttpContext context, Blinky.Api.Authorities.CaAdministration administration) =>
        !IsOperator(context)
            ? Results.Json(new { error = "an operator token is required" }, statusCode: 401)
            : Results.Ok(new
            {
                profiles = administration.Profiles(),

                // What the form may offer, from the same lists the server validates
                // against, so the console cannot drift from them.
                choices = new
                {
                    slots = Blinky.Api.Authorities.CaAdministration.Slots,
                    keyAlgorithms = Blinky.Api.Authorities.CaAdministration.KeyAlgorithms,
                    pinPolicies = Blinky.Api.Authorities.CaAdministration.PinPolicies,
                    touchPolicies = Blinky.Api.Authorities.CaAdministration.TouchPolicies,
                },
            }));

app.MapPost("/api/certificate-profiles",
    (Blinky.Api.Authorities.ProfileRequest request, HttpContext context,
        Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () => Results.Ok(administration.CreateProfile(request, ActorFor(context)))));

app.MapPut("/api/certificate-profiles/{id:guid}",
    (Guid id, Blinky.Api.Authorities.ProfileRequest request, HttpContext context,
        Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () => Results.Ok(administration.UpdateProfile(id, request, ActorFor(context)))));

app.MapDelete("/api/certificate-profiles/{id:guid}",
    (Guid id, HttpContext context, Blinky.Api.Authorities.CaAdministration administration) =>
        CaAdmin(context, () =>
        {
            administration.DeleteProfile(id, ActorFor(context));
            return Results.NoContent();
        }));

app.MapGet("/api/cardholders",
    (string? q, HttpContext context, Database database) =>
    {
        if (!IsOperator(context))
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
        if (!IsOperator(context))
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
        if (!IsOperator(context))
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
                token.LastSeenAgentId,

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
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        // Hold, and only hold. It is the one revocation reason X.509 allows to
        // be taken back, which is what makes this reversible and everything
        // else on this screen permanent.
        var suspended = await credentials.RevokeAsync(id,
            Blinky.Pki.X509RevocationReason.CertificateHold, "suspended by an operator", ActorFor(context), ct);

        return suspended
            ? Results.Ok(new { id, state = "Revoked", reason = "CertificateHold", reversible = true })
            : Results.Json(new { error = "no such credential, or it is already revoked" },
                statusCode: 404);
    });

app.MapPost("/api/tokens/{serial:long}/block",
    async (long serial, BlockTokenRequest request, HttpContext context,
        CredentialIssuanceService credentials, CancellationToken ct) =>
    {
        if (!IsOperator(context))
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
            var revoked = await credentials.BlockAsync(serial, state, request.Comment, ActorFor(context), ct);

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
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        return credentials.Unblock(serial, ActorFor(context))
            ? Results.Ok(new { serial, state = "Registered" })
            : Results.Json(new
            {
                error = "no such token, or it is not suspended",
                detail = "Only a suspension is lifted here. A token revoked as lost, stolen, "
                         + "terminated or retired stays that way, and the route back is a new "
                         + "credential rather than an undo.",
            }, statusCode: 409);
    });

// The management key for one token, to the agent holding that token.
//
// Fetched at the moment it is needed rather than carried in the job, because a
// job's payload is written to the database and this must not be. docs/06 says
// a stolen database yields no management key; putting one in an enrolment job
// would make that untrue for every card ever issued.
//
// Any enrolled agent may ask for any token's key, and that is not a gap: an
// agent has to be able to manage whatever card is put into it, and it already
// holds a certificate this server issued. The audit line is what makes the
// asking visible.
app.MapPost("/api/tokens/{serial:long}/management-key",
    (long serial, HttpContext context, ManagementKeyDerivation derivation,
        Database database, ILoggerFactory loggers) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        if (!derivation.IsConfigured)
        {
            // Not an error. A deployment without a master keeps the factory
            // key, and the agent needs to hear that rather than a failure.
            return Results.Json(new { configured = false }, statusCode: 200);
        }

        // Which generation of the master this card was diversified under. The
        // column existed and nothing ever wrote it, so every diversified token
        // read back as Lost - see TokenClassification.ManagementKey.
        //
        // The rule for a token that has no version recorded is not "the current
        // one". A card personalised before versioning existed can only have
        // been done under generation one, and telling it apart from a factory
        // card is what PukState's sibling ManagementKeyState is for: a card
        // still on the factory key has not been diversified under anything, so
        // it gets whatever this deployment writes with now.
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);

        var version = token switch
        {
            null => derivation.Version,
            { ManagementKeyVersion: > 0 } known => known.ManagementKeyVersion,
            { ManagementKeyState: ManagementKeyState.Default or ManagementKeyState.Unknown } =>
                derivation.Version,
            _ => 1,
        };

        if (token is not null && token.ManagementKeyVersion != version)
        {
            token.ManagementKeyVersion = version;
            token.UpdatedAt = DateTime.UtcNow;
            session.Update(token);
        }

        transaction.Commit();

        // Recorded at disclosure rather than on the agent's word that the card
        // took it, and that is safe rather than sloppy: the card's own metadata
        // decides Default from Diversified, so a key that was never written
        // still reads as a factory card. What the version adds is the answer to
        // "diversified under which master", which nothing else can supply.
        loggers.CreateLogger("Blinky.ManagementKey").LogInformation(
            "Agent {Agent} took the management key for token {Serial}, generation {Version}",
            agent.Hostname, serial, version);

        return Results.Ok(new
        {
            configured = true,
            version,
            secret = Convert.ToBase64String(derivation.For(serial, version)),
        });
    });

app.MapPost("/api/tokens/{serial:long}/puk/checkout",
    (long serial, string? reason, HttpContext context, PukEscrow escrow) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        try
        {
            // Why, from the caller, because the two callers are doing different
            // things: rescuing a blocked PIN at a desk, and personalising a card
            // that still has the factory PUK. Recording both as an unblock makes
            // the audit trail lie in the direction of alarm.
            var checkout = escrow.Checkout(serial, $"agent:{agent.Hostname}",
                string.IsNullOrWhiteSpace(reason) ? "unblock" : reason);

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
        if (!IsOperator(context))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        try
        {
            // Named, not "operator". This row is the record that a recovery
            // secret for somebody's card was read out to a person over a
            // telephone, and it is one of the two events retention may never
            // remove. A name is the only thing that makes it an answer.
            var answer = escrow.AnswerOffline(request.Challenge, ActorFor(context));

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
        if (!IsOperator(context))
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
        if (!IsOperator(context))
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

        var revoked = await credentials.RevokeAsync(id, reason, request.Comment, ActorFor(context), ct);

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

app.MapGet("/pki/issuing.crt", (Blinky.Api.Authorities.CertificateAuthorities authorities, IConfiguration configuration) =>
    StackChain.Of(authorities.Default, configuration) is { } chain
        // DER rather than PEM: this is what an authority information access
        // fetch expects, and Windows will not read a PEM here.
        ? Results.File(chain.Issuer.RawData, "application/pkix-cert", "issuing.crt")
        : Results.NotFound());

app.MapGet("/pki/root.crt", (Blinky.Api.Authorities.CertificateAuthorities authorities, IConfiguration configuration) =>
    StackChain.Of(authorities.Default, configuration) is { } chain
        ? Results.File(chain.Anchor.RawData, "application/pkix-cert", "root.crt")
        : Results.NotFound());

app.MapGet("/pki/chain.pem", (Blinky.Api.Authorities.CertificateAuthorities authorities, IConfiguration configuration) =>
{
    if (StackChain.Of(authorities.Default, configuration) is not { } chain)
    {
        return Results.NotFound();
    }

    // For the things that want the lot in one file - PKINIT anchors, an
    // openssl verify, a Linux client being set up by hand.
    var pem = chain.Anchor.Thumbprint == chain.Issuer.Thumbprint
        ? chain.Anchor.ExportCertificatePem()
        : chain.Issuer.ExportCertificatePem() + "\n" + chain.Anchor.ExportCertificatePem();

    return Results.Text(pem, "application/x-pem-file");
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
    if (!IsOperator(context))
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

        // Which agent last saw it, so the console's enrolment dialog asks that one
        // rather than leaving the job to whichever agent polls first (0052).
        t.LastSeenAgentId,
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
/// What has been asked of one key since this process started.
/// </summary>
/// <remarks>
/// Null when nothing has, and null when the provider is not the auditing one -
/// which cannot happen in a running deployment and can in a test, and either
/// way is better reported as absent than as zero.
/// </remarks>
static object? Usage(IKeyProvider provider, KeyRef key) =>
    provider is AuditingKeyProvider audited && audited.Usage.TryGetValue(key, out var usage)
        ? new { usage.Operations, usage.Failures, usage.LastUsedAt }
        : null;

/// <summary>
/// An extended key usage as a person reads it, falling back to the OID.
/// </summary>
/// <remarks>
/// Only the two this build issues are named. An unknown OID comes back as
/// itself rather than as "Unknown": a console showing a dotted number is
/// something an operator can look up, and a console showing "Unknown" is a
/// dead end.
/// </remarks>
static string ExtendedKeyUsageName(string oid) => oid switch
{
    "1.3.6.1.5.5.7.3.2" => "Client Authentication",
    Blinky.Pki.BuiltIn.BuiltInCertificateAuthority.SmartCardLogonOid => "Smart Card Logon",
    _ => oid,
};

/// <summary>
/// Who to record as the actor of an operator action.
/// </summary>
/// <remarks>
/// The signed-in account's username where there is one, and the literal
/// <c>shared-token</c> where the caller presented the shared secret instead.
/// <para>
/// Naming the fallback rather than writing "operator" for both is the whole
/// point. A PUK disclosure recorded as "operator" says an unknown person was
/// given the recovery secret for somebody's card; the same row reading
/// <c>shared-token</c> says the same thing and admits it, which means the
/// remaining hole is countable in the audit view rather than invisible. It
/// disappears when 0053e removes the shared token.
/// </para>
/// </remarks>
static string ActorFor(HttpContext context) =>
    context.Items.TryGetValue("operator", out var signedIn) && signedIn is OperatorAccount account
        ? account.Username
        : "unknown";

/// <summary>
/// The session token this request carries, from the cookie.
/// </summary>
/// <remarks>
/// One place, and one source. Until 0101 this read two headers, which meant
/// the token had to live somewhere a script could reach - and an XSS in an
/// administrative console is then a stolen session rather than a defaced page.
/// A machine client gets its own credential when there is a machine client;
/// two ways in from the first day is two ways to get it wrong.
/// </remarks>
static string? SessionTokenFrom(HttpContext context) =>
    SessionCookie.TokenFrom(context.Request);

/// <summary>
/// The account behind a presented session token, or null.
/// </summary>
/// <remarks>
/// Every call is a lookup, which is the cost 0053b accepts on purpose: it is
/// what makes ending a session take effect on the next request rather than
/// whenever a self-contained token happens to expire.
/// </remarks>
static OperatorAccount? SignedInOperator(HttpContext context, Database database,
    OperatorSessions sessions)
{
    var presented = SessionTokenFrom(context);

    if (presented is null)
    {
        return null;
    }

    using var session = database.OpenSession();
    using var transaction = session.BeginTransaction();

    var fingerprint = SessionTokens.Fingerprint(presented);
    var row = session.Query<OperatorSession>().FirstOrDefault(s => s.TokenHash == fingerprint);
    var check = sessions.Check(row);

    if (!check.Accepted)
    {
        transaction.Commit();
        return null;
    }

    var account = session.Get<OperatorAccount>(check.Session!.OperatorAccountId);

    // An account disabled while signed in stops here rather than at the next
    // expiry, which is the same argument the session itself makes.
    if (account is null || account.State != Blinky.Domain.OperatorAccountState.Active)
    {
        transaction.Commit();
        return null;
    }

    session.Update(check.Session);
    transaction.Commit();

    return account;
}

/// <summary>
/// Whether the caller may act as an operator, by either route.
/// </summary>
/// <remarks>
/// A session first, because that is the one that can say who. The shared token
/// stays because fifteen call sites and every script in <c>scripts/</c> use it,
/// and removing it in the same change that introduces sessions would break the
/// CRL publisher and the lab scripts at the moment there is nothing to replace
/// them with. Patch 0053e is where it goes, after named service credentials
/// exist - and it goes entirely, rather than being left discouraged.
/// </remarks>
/// <summary>
/// Whether the caller is a signed-in operator.
/// </summary>
/// <remarks>
/// One way in, as of patch 0053e. The shared <c>X-Blinky-Operator</c> token is
/// gone: it was one secret for everybody, so the audit trail could say a
/// credential had been revoked and never by whom, nothing expired, and taking
/// access from one person meant taking it from all of them.
/// <para>
/// It could only go once the console could sign in, because until then it was
/// the console's only way in. It could go without a service-credential scheme
/// because nothing automated ever used it: the installer only generated it, and
/// the revocation-list publisher reads <c>/pki/</c>, which is public.
/// </para>
/// </remarks>
// One shape for every refusal in the passkey flow: a status, a code an agent or
// a console can branch on, and a sentence for whoever reads the log.
/// <summary>
/// An administrator's write to a CA or a profile, with the refusal said as the status
/// and the sentence the administration chose for it.
/// </summary>
static IResult CaAdmin(HttpContext context, Func<IResult> handler)
{
    if (!IsAdministrator(context))
    {
        return Results.Json(new { error = "an administrator is required" }, statusCode: 403);
    }

    try
    {
        return handler();
    }
    catch (Blinky.Api.Authorities.CaAdministrationException e)
    {
        return Results.Json(new { error = e.Message }, statusCode: e.Status);
    }
}

static async Task<IResult> Passkey(Func<Task<IResult>> handler)
{
    try
    {
        return await handler();
    }
    catch (Blinky.Api.Passkeys.PasskeyFlowException e)
    {
        return Results.Json(new { error = e.Message, code = e.Code }, statusCode: e.Status);
    }
}

/// <summary>
/// Which package set a machine may fetch: a workstation's by its agent certificate or an
/// agent token, a connector's by a connector token. Null when neither was shown.
/// </summary>
static string? MachineAdmitted(HttpContext context, string purpose, Blinky.Api.Agents.EnrolmentTokens tokens)
{
    var token = context.Request.Headers["X-Blinky-Enrolment-Token"].ToString();

    return purpose switch
    {
        "workstation" when context.Items.ContainsKey("agent")
                           || tokens.Admits(token, Blinky.Domain.Entities.EnrolmentPurpose.Agent) => "workstation",
        "connector" when tokens.Admits(token, Blinky.Domain.Entities.EnrolmentPurpose.AdcsConnector) => "connector",
        _ => null,
    };
}

static bool IsAdministrator(HttpContext context) =>
    context.Items.TryGetValue("operator", out var signedIn)
    && signedIn is OperatorAccount { Role: Blinky.Domain.OperatorRole.Administrator };

static bool IsOperator(HttpContext context) =>
    context.Items.TryGetValue("operator", out var signedIn) && signedIn is OperatorAccount;

/// <summary>What an agent reports when it checks in.</summary>
/// <summary>An operator asking for a new enrolment token.</summary>
/// <param name="Name">What it is for, in words, so it can be recognised on the list.</param>
/// <param name="Purpose">"agent" or "connector". Absent means an agent.</param>
/// <param name="ValidForDays">Days until it stops working. Absent means never, which is a choice.</param>
/// <param name="MaxUses">How many machines may use it. Absent means any number.</param>
/// <param name="AllowedDomain">The domain a machine must report. Absent means any.</param>
internal sealed record CreateEnrolTokenRequest(
    string Name,
    string? Purpose,
    int? ValidForDays,
    int? MaxUses,
    string? AllowedDomain);

/// <summary>Why a token is being withdrawn. Optional, and worth filling in.</summary>
internal sealed record RevokeEnrolTokenRequest(string? Reason);

/// <summary>Asks for one token inventory pass on one agent.</summary>
internal sealed record InventoryJobRequest(Guid AgentId, string? Reason);

internal sealed record PasskeyRevokeRequest(string Reason);

/// <summary>One credential the backend holds, as an agent needs to see it.</summary>
/// <summary>An offline code that the card would not take.</summary>
internal sealed record PukRefused(long TokenSerial);

/// <summary>An operator taking a credential back off a token.</summary>
/// <summary>
/// People a rollout would cover, to be resolved before anybody is issued to.
/// </summary>
internal sealed record ResolveTestRequest(string? Group = null, string[]? Accounts = null);

/// <summary>Somebody to ask the directory about, for the permission probe.</summary>
internal sealed record WriteAccessTestRequest(
    string? Account = null,
    string? DistinguishedName = null);

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

/// <summary>Signing in: a name, a password, and the six digits when they are due.</summary>
/// <remarks>
/// The password travels on every step of the ceremony rather than being
/// exchanged once for a half-finished ticket. A pending credential is a
/// credential - it can be stolen, it has to expire, and it needs its own rules.
/// </remarks>
internal sealed record SignInRequest(string? Username, string? Password, string? TotpCode = null);

/// <summary>Replacing a password, which is also how the bootstrap closes.</summary>
internal sealed record PasswordChangeRequest(
    string? Username, string? CurrentPassword, string? NewPassword);

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
    string? Reason = null,

    /// <summary>
    /// A person already on file, instead of the three strings above.
    /// </summary>
    /// <remarks>
    /// Added rather than substituted: the loose strings are how every script
    /// and the smoke path ask today, and breaking them to make a console nicer
    /// would be the wrong trade. When this is given the three are read from the
    /// row and whatever the caller sent for them is ignored.
    /// </remarks>
    Guid? CardholderId = null,

    /// <summary>
    /// "Rsa2048", "EccP256", and so on. Null leaves the choice to the agent.
    /// </summary>
    /// <remarks>
    /// Worth choosing rather than accepting, because the two are not
    /// interchangeable in front of Windows. The inbox smart-card credential
    /// provider does not enumerate ECC certificates unless
    /// EnumerateECCCerts is set on the workstation, so a perfectly good ECC
    /// credential produces "no valid certificates were found on this smart
    /// card" at the logon screen - a sentence about the card, for a policy
    /// setting.
    /// </remarks>
    string? KeyAlgorithm = null);

internal sealed record HeartbeatRequest(
    string? Version,
    string[]? Readers,
    UnsupportedCardReport[]? Unsupported);

/// <summary>
/// The stack's own CA: the one that signed the edge's certificate, which is what a
/// workstation has to trust before its agent will talk to anything.
/// </summary>
/// <remarks>
/// With the built-in backend it is also the CA that issues cards, and it is read from
/// the loaded authority. With ADCS the cards come from a Microsoft CA, but the edge
/// certificate still comes from this one - and /pki/root.crt answered 404, so
/// install-windows-client.ps1 had no anchor to give the agent, and the first
/// workstation in ad.digitalworkspace.pl could not enrol: its TLS check refused the
/// edge. Read from the files new-ca.sh left in Blinky:Ca:Directory instead; the key is
/// not needed and not touched.
/// </remarks>
internal static class StackChain
{
    public static (System.Security.Cryptography.X509Certificates.X509Certificate2 Issuer,
        System.Security.Cryptography.X509Certificates.X509Certificate2 Anchor)? Of(
        Blinky.Pki.ICertificateAuthority ca, IConfiguration configuration)
    {
        if (ca is Blinky.Pki.BuiltIn.BuiltInCertificateAuthority built)
        {
            return (built.Issuer, built.TrustAnchor);
        }

        var directory = configuration["Blinky:Ca:Directory"] ?? "/etc/blinky/ca";
        var issuer = Path.Combine(directory, "issuing.crt");
        var anchor = Path.Combine(directory, "anchor.crt");

        if (!File.Exists(issuer) || !File.Exists(anchor))
        {
            return null;
        }

        // CreateFromPem, not CreateFromPemFile: the file overload with no key path
        // looks for the private key in the certificate's own file, and these files
        // hold none - every /pki/root.crt under ADCS answered 500 for it.
        return (System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(issuer)),
            System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(anchor)));
    }
}

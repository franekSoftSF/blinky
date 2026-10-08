using Blinky.Passkeys;
using Blinky.Passkeys.Entra;
using Blinky.Passkeys.Okta;

namespace Blinky.Api.Passkeys;

/// <summary>The identity providers this deployment can register passkeys with, by name.</summary>
/// <remarks>
/// Either may be absent, and both usually are: an on-premises PIV deployment has
/// no reason to reach a cloud, and this is the only thing in the stack that does.
/// Absent means the console says so; it never means a provider half-configured.
/// </remarks>
public sealed class PasskeyDirectories
{
    private readonly Dictionary<string, IPasskeyDirectory> byName;

    public PasskeyDirectories(IEnumerable<IPasskeyDirectory> directories) =>
        byName = directories.ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);

    public IReadOnlyCollection<IPasskeyDirectory> All => byName.Values;

    public IPasskeyDirectory? Find(string name) => byName.GetValueOrDefault(name);

    /// <summary>
    /// <c>Blinky:Passkeys:Entra</c> and <c>Blinky:Passkeys:Okta</c>. Secrets are
    /// read from files, like the ADCS client certificate's password: a secret in
    /// an environment variable is in every <c>docker inspect</c> and every crash
    /// dump of the process.
    /// </summary>
    public static PasskeyDirectories FromConfiguration(IConfiguration configuration, ILogger logger)
    {
        var found = new List<IPasskeyDirectory>();
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        var entra = configuration.GetSection("Blinky:Passkeys:Entra");
        if (entra["TenantId"] is { Length: > 0 } tenant && entra["ClientId"] is { Length: > 0 } client)
        {
            found.Add(EntraPasskeyDirectory.Create(new EntraOptions(
                tenant,
                client,
                ClientCertificatePath: Value(entra["ClientCertificatePath"]),
                ClientCertificatePassword: FromFile(entra["ClientCertificatePasswordFile"]),
                ClientSecret: FromFile(entra["ClientSecretFile"]),
                Name: Value(entra["Name"]) ?? "entra",
                ChallengeTimeoutMinutes: entra.GetValue("ChallengeTimeoutMinutes", 10)), http));
        }

        var okta = configuration.GetSection("Blinky:Passkeys:Okta");
        if (okta["OrgUrl"] is { Length: > 0 } org)
        {
            found.Add(OktaPasskeyDirectory.Create(new OktaOptions(
                org,
                AuthMode: okta.GetValue("AuthMode", OktaAuthMode.OAuthPrivateKeyJwt),
                ApiToken: FromFile(okta["ApiTokenFile"]),
                ClientId: Value(okta["ClientId"]),
                PrivateKeyPath: Value(okta["PrivateKeyPath"]),
                KeyId: Value(okta["KeyId"]),
                Name: Value(okta["Name"]) ?? "okta",
                ChallengeMinutes: okta.GetValue("ChallengeMinutes", 5)), http));
        }

        logger.LogInformation("Passkey providers: {Providers}",
            found.Count == 0 ? "none configured" : string.Join(", ", found.Select(d => d.Name)));

        return new PasskeyDirectories(found);
    }

    private static string? Value(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? FromFile(string? path) =>
        Value(path) is { } file ? File.ReadAllText(file).Trim() : null;
}

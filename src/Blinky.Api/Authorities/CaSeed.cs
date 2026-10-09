using System.Text.Json;
using Blinky.Api.Credentials;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Pki.Adcs;

namespace Blinky.Api.Authorities;

/// <summary>
/// The first start after 0108: the CA and the profiles this server was configured
/// with in <c>.env</c> become rows, once.
/// </summary>
/// <remarks>
/// <para>
/// Imported rather than required, so an upgrade keeps issuing: BY-CACMS ran ADCS
/// through MS-CONN01 with the template in <c>ADCS_TEMPLATE_SMARTCARD_LOGON</c>, and
/// the day after the upgrade it has to run the same CA with the same template
/// without anybody retyping either.
/// </para>
/// <para>
/// Only into empty tables. Once a row exists the console owns it, and a value still
/// sitting in <c>.env</c> is ignored - said in the log, because an administrator
/// editing <c>.env</c> afterwards and seeing nothing change deserves to know why.
/// </para>
/// </remarks>
public static class CaSeed
{
    public static void Import(Database database, IConfiguration configuration, ILogger logger)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var now = DateTime.UtcNow;
        var instance = session.Query<CaInstance>().OrderBy(c => c.CreatedAt).FirstOrDefault();

        if (instance is null)
        {
            var backend = AdcsInstance.Backend(configuration["Blinky:Ca:Backend"]);

            instance = new CaInstance
            {
                Backend = backend,
                Topology = CaTopology.TwoTier,
                IsEnabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            };

            if (backend == CaBackend.Adcs)
            {
                var adcs = new AdcsInstanceOptions();
                configuration.GetSection("Blinky:Adcs").Bind(adcs);
                instance.Name = string.IsNullOrWhiteSpace(adcs.Name) ? "adcs" : adcs.Name;
                instance.Configuration = CertificateAuthorities.Serialise(adcs);
            }
            else
            {
                instance.Name = "built-in";
                instance.Configuration = JsonSerializer.Serialize(
                    new BuiltInSettings(configuration["Blinky:Ca:Directory"]), CertificateAuthorities.Json);
            }

            session.Save(instance);
            session.Save(Audit(now, "ca.imported", nameof(CaInstance), instance.Id,
                $$"""{"name":"{{instance.Name}}","backend":"{{backend}}","from":".env"}"""));

            logger.LogWarning(
                "Imported the CA {Name} ({Backend}) from .env into the database. From now on it is changed in "
                + "the console; CA_BACKEND and ADCS_* in .env are no longer read", instance.Name, backend);
        }

        if (!session.Query<CertificateProfile>().Any())
        {
            var adcs = new AdcsInstanceOptions();
            configuration.GetSection("Blinky:Adcs").Bind(adcs);

            // One algorithm configured for the CA was what every card got; with
            // several, or none, the profile's own default stands.
            var algorithm = adcs.KeyAlgorithms.Count == 1 ? adcs.KeyAlgorithms[0] : null;

            foreach (var descriptor in Profiles.All)
            {
                var profile = new CertificateProfile
                {
                    Name = descriptor.Name,
                    CaInstance = instance,
                    SlotId = "9A",
                    // Spelled as the agent and the console's form spell it: .env said
                    // RSA2048 and the descriptor ECCP256, and a select that cannot match
                    // the stored value shows the profile as having no key at all.
                    KeyAlgorithm = Spelled(instance.Backend == CaBackend.Adcs && algorithm is not null
                        ? algorithm
                        : descriptor.KeyAlgorithm),
                    ValidityDays = descriptor.ValidityDays,
                    ExtendedKeyUsages = JsonSerializer.Serialize(descriptor.ExtendedKeyUsages),
                    IncludeUpnSan = descriptor.IncludeUpnSan,
                    IncludeSidExtension = descriptor.IncludeSidExtension,
                    AdcsTemplateName = adcs.Templates.GetValueOrDefault(descriptor.Name),

                    // A Microsoft CA refuses a profile with no template at the first
                    // enrolment; imported disabled, it is refused in the console instead.
                    IsEnabled = instance.Backend != CaBackend.Adcs || adcs.Templates.ContainsKey(descriptor.Name),
                    CreatedAt = now,
                    UpdatedAt = now,
                };

                session.Save(profile);
                session.Save(Audit(now, "profile.imported", nameof(CertificateProfile), profile.Id,
                    $$"""{"name":"{{profile.Name}}","ca":"{{instance.Name}}","template":"{{profile.AdcsTemplateName}}"}"""));
            }

            logger.LogWarning("Imported {Count} certificate profiles into the database", Profiles.All.Count);
        }

        transaction.Commit();
    }

    private static string Spelled(string algorithm)
    {
        try
        {
            return CaAdministration.KeyAlgorithm(algorithm);
        }
        catch (CaAdministrationException)
        {
            return algorithm;
        }
    }

    private static AuditEvent Audit(DateTime now, string type, string subjectType, Guid id, string detail) => new()
    {
        OccurredAt = now,
        EventType = type,
        Actor = "system",
        SubjectType = subjectType,
        SubjectId = id,
        Detail = detail,
    };
}

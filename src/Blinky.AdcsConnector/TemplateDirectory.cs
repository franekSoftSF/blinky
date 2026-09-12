using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Blinky.Contracts;

namespace Blinky.AdcsConnector;

/// <summary>
/// Reads a certificate template out of the forest, as the account this service
/// runs as.
/// </summary>
public interface ITemplateDirectory
{
    AdcsTemplateInfo Find(string name);
}

/// <summary>
/// The template object in the Configuration partition, and the Enroll right on it
/// evaluated for the integration account.
/// </summary>
/// <remarks>
/// <para>
/// Read here rather than in the container because this is the machine that is in
/// the domain and this is the account whose rights are in question. A container
/// reading the same object over LDAP would answer for its own bind account, which
/// is not the account that will ask the CA for anything.
/// </para>
/// <para>
/// <b>Reasoned from the documentation and not yet run against a forest.</b> The
/// attribute names and the Enroll right's GUID are Microsoft's and are in MS-CRTD;
/// whether every one of them is readable by an ordinary account on a real estate
/// is the first thing to watch on the lab server. An attribute that could not be
/// read is reported as null and never as a value.
/// </para>
/// </remarks>
public sealed class ActiveDirectoryTemplates(ILogger<ActiveDirectoryTemplates> logger) : ITemplateDirectory
{
    public AdcsTemplateInfo Find(string name)
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        var configuration = (string?)rootDse.Properties["configurationNamingContext"].Value
            ?? throw new InvalidOperationException(
                "The directory did not name its configuration partition. This machine is not "
                + "reading a domain, or the account cannot bind to one.");

        using var container = new DirectoryEntry(
            $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configuration}");

        using var search = new DirectorySearcher(container)
        {
            Filter = $"(&(objectClass=pKICertificateTemplate)(cn={Escape(name)}))",
            SearchScope = SearchScope.OneLevel,
            SecurityMasks = SecurityMasks.Dacl,
        };

        search.PropertiesToLoad.AddRange(
        [
            "cn", "displayName", "msPKI-Template-Schema-Version", "msPKI-Certificate-Name-Flag",
            "msPKI-RA-Signature", "msPKI-RA-Application-Policies", "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
        ]);

        var found = search.FindOne();
        var account = WindowsIdentity.GetCurrent();

        if (found is null)
        {
            return new AdcsTemplateInfo(name, Found: false, Account: account.Name);
        }

        return new AdcsTemplateInfo(
            name,
            Found: true,
            DisplayName: Text(found, "displayName"),
            SchemaVersion: Number(found, "msPKI-Template-Schema-Version"),
            NameFlags: Number(found, "msPKI-Certificate-Name-Flag"),
            AuthorizedSignatures: Number(found, "msPKI-RA-Signature"),
            SignaturePolicies: Many(found, "msPKI-RA-Application-Policies"),
            ExtendedKeyUsages: Many(found, "pKIExtendedKeyUsage"),
            AccountMayEnroll: MayEnroll(found, account),
            Account: account.Name);
    }

    private bool? MayEnroll(SearchResult found, WindowsIdentity account)
    {
        if (found.Properties["nTSecurityDescriptor"] is not { Count: > 0 } values
            || values[0] is not byte[] descriptor)
        {
            logger.LogWarning(
                "The security descriptor of this template could not be read, so whether {Account} "
                + "may enrol is unknown", account.Name);

            return null;
        }

        var security = new ActiveDirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(descriptor, AccessControlSections.Access);

        return EnrolRight.Evaluate(security, EnrolRight.TokenOf(account));
    }

    private static int? Number(SearchResult found, string attribute) =>
        found.Properties[attribute] is { Count: > 0 } values && values[0] is int value ? value : null;

    private static string? Text(SearchResult found, string attribute) =>
        found.Properties[attribute] is { Count: > 0 } values ? values[0]?.ToString() : null;

    private static IReadOnlyList<string>? Many(SearchResult found, string attribute) =>
        found.Properties[attribute] is { Count: > 0 } values
            ? [.. values.Cast<object>().Select(value => value.ToString() ?? string.Empty)]
            : null;

    /// <summary>RFC 4515. A template name is typed by a person and read into a filter.</summary>
    internal static string Escape(string value) =>
        string.Concat(value.Select(c => c switch
        {
            '\\' => @"\5c",
            '*' => @"\2a",
            '(' => @"\28",
            ')' => @"\29",
            '\0' => @"\00",
            _ => c.ToString(),
        }));
}

/// <summary>
/// Whether a security descriptor grants Enroll to a token.
/// </summary>
/// <remarks>
/// <para>
/// Enroll is an extended right with a fixed GUID. It is also granted by Full
/// Control, and by an extended-rights entry with no object type, which means every
/// extended right - both of which are how templates are commonly over-granted, and
/// both of which a check that only looked for the GUID would miss.
/// </para>
/// <para>
/// A deny that matches wins over any allow, regardless of order. Windows evaluates
/// in canonical order where an explicit deny precedes an allow anyway, and a
/// non-canonical descriptor is not something to reason about generously when the
/// question is whether an account may ask for certificates in other people's names.
/// </para>
/// </remarks>
public static class EnrolRight
{
    public static readonly Guid Enroll = new("0e10c968-78fb-11d2-90d4-00c04f79dc55");

    /// <summary>GENERIC_ALL, before the directory maps it to specific rights.</summary>
    private const int GenericAllBit = 0x10000000;

    public static IReadOnlySet<SecurityIdentifier> TokenOf(WindowsIdentity identity)
    {
        var token = new HashSet<SecurityIdentifier>();

        if (identity.User is { } user)
        {
            token.Add(user);
        }

        foreach (var group in identity.Groups ?? [])
        {
            if (group is SecurityIdentifier sid)
            {
                token.Add(sid);
            }
        }

        return token;
    }

    public static bool Evaluate(ActiveDirectorySecurity security, IReadOnlySet<SecurityIdentifier> token)
    {
        var allowed = false;

        foreach (ActiveDirectoryAccessRule rule in security.GetAccessRules(
                     includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.IdentityReference is not SecurityIdentifier sid || !token.Contains(sid))
            {
                continue;
            }

            // Full Control arrives as the mapped directory rights, which is how the
            // directory stores it. The raw GENERIC_ALL bit is accepted too: a
            // descriptor written by a tool that did not map it is still granting
            // everything, and reading it as nothing would refuse a working template.
            var grants = rule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll)
                || ((int)rule.ActiveDirectoryRights & GenericAllBit) != 0
                || (rule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight)
                    && (rule.ObjectType == Enroll || rule.ObjectType == Guid.Empty));

            if (!grants)
            {
                continue;
            }

            if (rule.AccessControlType == AccessControlType.Deny)
            {
                return false;
            }

            allowed = true;
        }

        return allowed;
    }
}

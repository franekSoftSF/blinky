using Blinky.Api.Credentials;
using Blinky.Directory;
using Blinky.Domain;
using Blinky.Pki;

namespace Blinky.UnitTests;

/// <summary>
/// The <c>DOMAIN\user</c> a Microsoft CA issues for, read from the directory at issuance.
/// </summary>
/// <remarks>
/// The lab CA ignored the subject a request asked for and built the certificate from
/// the account <c>requestername</c> named, so a wrong name here is somebody else's
/// certificate rather than a malformed one.
/// </remarks>
public sealed class LogonNameTests
{
    private const string Sid = "S-1-5-21-3474637876-781497690-2719985338-1132";

    private static readonly DirectoryUser BlinkyUser = new(
        "BlinkyUser", "BlinkyUser", "BlinkyUser@ad.digitalworkspace.pl", Sid,
        "CN=BlinkyUser,OU=Users,OU=DIGITALWORKSPACE,DC=ad,DC=digitalworkspace,DC=pl", true);

    [Fact]
    public async Task The_name_is_the_domains_netbios_name_and_the_account_name()
    {
        var names = new LogonNames(new FakeDirectory(BlinkyUser, "AD"), required: true);

        Assert.Equal(@"AD\BlinkyUser", await names.ResolveAsync(Cardholder(), default));
    }

    [Fact]
    public async Task A_ca_that_takes_the_subject_it_is_given_asks_the_directory_nothing()
    {
        var directory = new FakeDirectory(BlinkyUser, "AD");

        Assert.Null(await new LogonNames(directory, required: false).ResolveAsync(Cardholder(), default));
        Assert.Equal(0, directory.Lookups);
    }

    [Fact]
    public async Task A_upn_that_has_moved_to_another_account_is_refused()
    {
        // Created for one SID, and the UPN now answers with another. Issuing would
        // build the certificate for the account that holds the UPN today.
        var moved = BlinkyUser with { ObjectSid = "S-1-5-21-3474637876-781497690-2719985338-2001" };
        var names = new LogonNames(new FakeDirectory(moved, "AD"), required: true);

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => names.ResolveAsync(Cardholder(), default));

        Assert.Contains(Sid, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nobody_or_two_people_in_the_directory_is_refused()
    {
        var names = new LogonNames(new FakeDirectory(null, "AD"), required: true);

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => names.ResolveAsync(Cardholder(), default));

        Assert.Contains("no single account", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_domain_name_that_cannot_be_read_names_the_setting()
    {
        var names = new LogonNames(new FakeDirectory(BlinkyUser, null), required: true);

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => names.ResolveAsync(Cardholder(), default));

        Assert.Contains("Blinky:Directory:NetBiosDomain", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cardholder_without_a_upn_is_refused_before_the_directory_is_asked()
    {
        var directory = new FakeDirectory(BlinkyUser, "AD");
        var names = new LogonNames(directory, required: true);

        await Assert.ThrowsAsync<IssuancePolicyException>(
            () => names.ResolveAsync(Cardholder() with { Upn = null }, default));

        Assert.Equal(0, directory.Lookups);
    }

    [Theory]
    [InlineData("CN=BlinkyUser,OU=Users,DC=ad,DC=digitalworkspace,DC=pl", "DC=ad,DC=digitalworkspace,DC=pl")]
    [InlineData("CN=x,OU=DC=odd,DC=blinky,DC=lab", "DC=blinky,DC=lab")]
    [InlineData("DC=blinky,DC=lab", "DC=blinky,DC=lab")]
    [InlineData("CN=nobody,O=Example", null)]
    [InlineData("", null)]
    public void The_domain_is_the_dn_from_its_first_domain_component(string dn, string? expected) =>
        Assert.Equal(expected, LdapDirectory.DomainOf(dn));

    private static Blinky.Contracts.CardholderRequest Cardholder() =>
        new("BlinkyUser", "BlinkyUser@ad.digitalworkspace.pl", Sid);

    private sealed class FakeDirectory(DirectoryUser? user, string? netBios) : IDirectory
    {
        public int Lookups { get; private set; }

        public DirectorySource Source => DirectorySource.ActiveDirectory;

        public Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default)
        {
            Lookups++;

            return Task.FromResult(user);
        }

        public Task<string?> NetBiosDomainAsync(string distinguishedName, CancellationToken ct = default) =>
            Task.FromResult(netBios);

        public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20, CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<DirectoryProbe> TestAsync(CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200, CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }
}

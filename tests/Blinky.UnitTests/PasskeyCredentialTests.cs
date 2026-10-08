using System.Reflection;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using NHibernate.Mapping;
using NHibernate.Type;

namespace Blinky.UnitTests;

/// <summary>
/// 0075: the fourth state machine, and the PIN it has nowhere to keep.
/// </summary>
public sealed class PasskeyCredentialTests
{
    private const string AnyConnection = "Host=localhost;Database=blinky;Username=blinky;Password=blinky";
    private static readonly DateTime Now = new(2026, 10, 8, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void No_column_can_hold_a_pin()
    {
        // Enforced by the mapping, not left as a convention: the one PIN-shaped
        // column is a boolean, and anything else with "pin" in its name fails here
        // before it can reach a database, a backup, or a support dump.
        var mapping = BlinkySessionFactory.BuildConfiguration(AnyConnection)
            .GetClassMapping(typeof(PasskeyCredential));

        var pinColumns = mapping.PropertyIterator
            .SelectMany(p => p.ColumnIterator.OfType<Column>().Select(c => (Column: c.Name, p.Type)))
            .Where(x => x.Column.Contains("pin", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var only = Assert.Single(pinColumns);
        Assert.Equal("pin_set_by_agent", only.Column);
        Assert.IsType<BooleanType>(only.Type);
    }

    [Fact]
    public void The_entity_has_no_property_a_pin_would_fit_in()
    {
        var offenders = typeof(PasskeyCredential).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.Name.Contains("Pin", StringComparison.OrdinalIgnoreCase) && p.PropertyType != typeof(bool))
            .Select(p => p.Name)
            .ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void A_passkey_goes_from_requested_to_registered_and_is_revoked_without_being_deleted()
    {
        var passkey = new PasskeyCredential();

        passkey.MoveTo(PasskeyCredentialState.KeyReady, Now);
        passkey.MoveTo(PasskeyCredentialState.ChallengeIssued, Now);
        passkey.MoveTo(PasskeyCredentialState.Provisioned, Now);
        passkey.MoveTo(PasskeyCredentialState.Registered, Now.AddSeconds(5));
        passkey.MoveTo(PasskeyCredentialState.Revoked, Now.AddDays(1), "Key lost");

        Assert.Equal(PasskeyCredentialState.Revoked, passkey.State);
        Assert.Equal(Now.AddSeconds(5), passkey.RegisteredAt);
        Assert.Equal(Now.AddDays(1), passkey.RevokedAt);
        Assert.Equal("Key lost", passkey.RevocationReason);
        Assert.Equal(Now.AddDays(1), passkey.UpdatedAt);
    }

    [Theory]
    // Skipping the provider: a credential on the key nobody accepted, recorded as usable.
    [InlineData(PasskeyCredentialState.Requested, PasskeyCredentialState.Registered)]
    [InlineData(PasskeyCredentialState.ChallengeIssued, PasskeyCredentialState.Registered)]
    // Revoking what was never registered: nothing at the provider to delete.
    [InlineData(PasskeyCredentialState.Provisioned, PasskeyCredentialState.Revoked)]
    // Failing what the provider already accepted would hide a live credential.
    [InlineData(PasskeyCredentialState.Registered, PasskeyCredentialState.Failed)]
    // Back from the dead.
    [InlineData(PasskeyCredentialState.Revoked, PasskeyCredentialState.Registered)]
    [InlineData(PasskeyCredentialState.Failed, PasskeyCredentialState.KeyReady)]
    public void A_move_the_lifecycle_does_not_allow_is_refused(
        PasskeyCredentialState from, PasskeyCredentialState to) =>
        Assert.False(PasskeyCredentialStates.CanMove(from, to));

    [Fact]
    public void A_refused_move_leaves_the_row_as_it_was()
    {
        var passkey = new PasskeyCredential();

        var e = Assert.Throws<InvalidOperationException>(() =>
            passkey.MoveTo(PasskeyCredentialState.Registered, Now));

        Assert.Equal(PasskeyCredentialState.Requested, passkey.State);
        Assert.Null(passkey.RegisteredAt);
        Assert.Contains("KeyReady", e.Message);
    }

    [Fact]
    public void A_retried_job_goes_round_again_on_the_same_row()
    {
        var passkey = new PasskeyCredential();
        passkey.MoveTo(PasskeyCredentialState.KeyReady, Now);
        passkey.MoveTo(PasskeyCredentialState.ChallengeIssued, Now);

        // The lease ran out with the challenge issued; the next attempt reports
        // the key ready again and is given a fresh challenge.
        passkey.MoveTo(PasskeyCredentialState.KeyReady, Now.AddMinutes(11));
        passkey.MoveTo(PasskeyCredentialState.ChallengeIssued, Now.AddMinutes(11));

        Assert.Equal(PasskeyCredentialState.ChallengeIssued, passkey.State);
    }

    [Theory]
    [InlineData(PasskeyCredentialState.Failed)]
    [InlineData(PasskeyCredentialState.Revoked)]
    public void Failing_or_revoking_needs_a_reason(PasskeyCredentialState terminal)
    {
        var passkey = new PasskeyCredential();
        passkey.MoveTo(PasskeyCredentialState.KeyReady, Now);
        passkey.MoveTo(PasskeyCredentialState.ChallengeIssued, Now);
        passkey.MoveTo(PasskeyCredentialState.Provisioned, Now);

        if (terminal is PasskeyCredentialState.Revoked)
        {
            passkey.MoveTo(PasskeyCredentialState.Registered, Now);
        }

        Assert.Throws<ArgumentException>(() => passkey.MoveTo(terminal, Now, " "));
    }

    [Fact]
    public void Every_state_has_somewhere_it_may_go_or_is_known_to_be_final()
    {
        // A state added later and given no row would throw on the first move
        // out of it, in production, on somebody's key.
        foreach (var state in Enum.GetValues<PasskeyCredentialState>())
        {
            var next = PasskeyCredentialStates.From(state);

            Assert.True(next.Count > 0
                || state is PasskeyCredentialState.Failed or PasskeyCredentialState.Revoked, $"{state}");
        }
    }
}

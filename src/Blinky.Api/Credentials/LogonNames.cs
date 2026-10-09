using Blinky.Directory;
using Blinky.Pki;

namespace Blinky.Api.Credentials;

/// <summary>
/// The cardholder's <c>DOMAIN\sAMAccountName</c>, read from the directory at the
/// moment of issuance, for a CA that issues on somebody's behalf only by that name.
/// </summary>
/// <remarks>
/// <para>
/// Only a Microsoft CA needs it. The <c>requestername</c> in its CMC is what the
/// certificate is built for - the lab CA ignored the subject the request asked for
/// and took the subject, the UPN and the SID extension from the account this names.
/// So a wrong name is not a malformed certificate, it is somebody else's.
/// </para>
/// <para>
/// <b>Read at issuance and checked against the SID the enrolment was created for.</b>
/// A UPN can be moved to another account between an operator creating the job and a
/// card arriving at a reader; the SID cannot. Stored instead, the name would have
/// to be a schema change and would go stale the same way.
/// </para>
/// </remarks>
public sealed class LogonNames(IDirectory directory, bool required)
{
    public Task<string?> ResolveAsync(Blinky.Contracts.CardholderRequest cardholder, CancellationToken ct) =>
        ResolveAsync(cardholder, required, ct);

    /// <param name="needed">
    /// Whether the CA this issuance goes to needs the name - decided per profile since
    /// 0108, when one deployment can issue from a Microsoft CA and the built-in one.
    /// </param>
    public async Task<string?> ResolveAsync(Blinky.Contracts.CardholderRequest cardholder, bool needed,
        CancellationToken ct)
    {
        if (!needed)
        {
            return null;
        }

        if (cardholder.Upn is not { Length: > 0 } upn)
        {
            throw new IssuancePolicyException(
                $"{cardholder.DisplayName} has no UPN, and a Microsoft CA issues on somebody's behalf "
                + @"only for an account named DOMAIN\user, which is looked up by UPN.");
        }

        // FindAsync answers null for nobody and for two people alike, and both are
        // a refusal: choosing between two accounts would issue for whichever the
        // server returned first.
        var user = await directory.FindAsync(upn, ct)
                   ?? throw new IssuancePolicyException(
                       $"The directory has no single account for {upn}, so the CA cannot be told "
                       + "whom to issue for. Either nobody holds that UPN, or more than one account "
                       + "answers to it, or no directory is configured (Blinky:Directory:Host, or "
                       + "Blinky:Directory:Via=Connector).");

        if (cardholder.ObjectSid is { Length: > 0 } sid
            && !string.Equals(user.ObjectSid, sid, StringComparison.OrdinalIgnoreCase))
        {
            throw new IssuancePolicyException(
                $"{upn} now belongs to the account with SID {user.ObjectSid ?? "(none)"}, not the "
                + $"{sid} this enrolment was created for. A certificate issued now would be that "
                + "other account's. Create the enrolment again from the directory.");
        }

        if (user.SamAccountName is not { Length: > 0 } account)
        {
            throw new IssuancePolicyException(
                $"The directory returned no sAMAccountName for {upn}.");
        }

        var domain = await directory.NetBiosDomainAsync(user.DistinguishedName ?? string.Empty, ct)
                     ?? throw new IssuancePolicyException(
                         $"The NetBIOS name of the domain {upn} is in could not be read from the "
                         + "directory's Configuration partition. Set Blinky:Directory:NetBiosDomain.");

        return $@"{domain}\{account}";
    }
}

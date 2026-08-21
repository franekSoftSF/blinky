using Blinky.Api.Persistence;
using Blinky.Domain.Entities;
using Blinky.Pki;

namespace Blinky.Api.Credentials;

/// <summary>
/// Keeps the revocation list current, in memory and on disk.
/// </summary>
/// <remarks>
/// <para>
/// A CRL has an expiry, and an expired one does not fail open: it breaks every
/// chain built under it. So it is rebuilt on a schedule rather than when
/// something is revoked, and the schedule is a fraction of its validity so a
/// missed run is not an outage.
/// </para>
/// <para>
/// <b>Rebuilt from the database, not accumulated in memory.</b> The store this
/// fills is in-process and forgets everything when the container restarts — a
/// revocation list that quietly forgets who was revoked is worse than none,
/// because everybody trusts it. The credential rows already carry
/// <c>RevokedAt</c> and a reason, so they are the record and this is a
/// projection of it.
/// </para>
/// <para>
/// <b>And written to a file.</b> Samba publishes the CRL into the directory as
/// bytes, in <c>certificateRevocationList</c> and
/// <c>authorityRevocationList</c>, and those attributes hold DER rather than
/// fetch a URL. PKINIT wants the same thing on disk. So the file is not a
/// convenience: it is how everything that is not a web client gets the list.
/// </para>
/// </remarks>
public sealed class CrlPublisher(
    ICertificateAuthority authority,
    Database database,
    CrlPublicationOptions options,
    ILogger<CrlPublisher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PublishAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Not fatal to the process. The previous file stays where it
                // is and remains valid until its own nextUpdate, which is what
                // the interval leaves room for.
                logger.LogError(ex, "Could not publish the revocation list");
            }

            try
            {
                await Task.Delay(options.Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Replays every revoked credential into the list and writes it out.
    /// </summary>
    public async Task PublishAsync(CancellationToken ct = default)
    {
        int replayed;

        using (var session = database.OpenSession())
        {
            var revoked = session.Query<Credential>()
                .Where(c => c.RevokedAt != null)
                .ToList();

            replayed = 0;

            foreach (var credential in revoked)
            {
                if (string.IsNullOrEmpty(credential.SerialNumber))
                {
                    // Revoked before it was ever issued. There is no serial
                    // number to name and nothing for a relying party to check.
                    continue;
                }

                var reason = Enum.TryParse<X509RevocationReason>(
                    credential.RevocationReason, ignoreCase: true, out var parsed)
                    ? parsed
                    : X509RevocationReason.Unspecified;

                // Idempotent: revoking twice replaces the entry rather than
                // adding a second one, which is what makes replaying the whole
                // table on every pass safe.
                await authority.RevokeAsync(
                    new RevocationRequest(credential.SerialNumber, reason), ct);

                replayed++;
            }
        }

        var crl = await authority.GetCrlAsync(ct);
        if (crl is null)
        {
            logger.LogWarning("This CA publishes no revocation list, so nothing was written");
            return;
        }

        if (options.File is { Length: > 0 } path)
        {
            WriteAtomically(path, crl.Der);
        }

        logger.LogInformation(
            "Revocation list published: {Count} certificate(s), valid until {NextUpdate:u}",
            replayed, crl.NextUpdate);
    }

    /// <summary>
    /// Writes beside the target and renames over it.
    /// </summary>
    /// <remarks>
    /// A reader that opens the file while it is being written gets half a CRL,
    /// and half a CRL does not parse — which a relying party reports as a
    /// revocation check that failed rather than as a file that was busy. The
    /// rename is atomic on any filesystem this runs on.
    /// </remarks>
    private void WriteAtomically(string path, byte[] der)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = path + ".new";
        File.WriteAllBytes(temporary, der);
        File.Move(temporary, path, overwrite: true);

        logger.LogDebug("Revocation list written to {Path} ({Bytes} bytes)", path, der.Length);
    }
}

/// <param name="Interval">
/// How often to rebuild. Wants to be well inside the list's own validity, so
/// that one failed run is a retry rather than an expiry.
/// </param>
/// <param name="File">
/// Where to write the DER, or null to publish over HTTP only. Samba reads this
/// file; so does PKINIT.
/// </param>
public sealed record CrlPublicationOptions(TimeSpan Interval, string? File);

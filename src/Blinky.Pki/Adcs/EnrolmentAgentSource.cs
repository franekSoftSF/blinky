namespace Blinky.Pki.Adcs;

/// <summary>
/// Where an <see cref="AdcsCertificateAuthority"/> gets its enrolment agent from,
/// at the moment it needs one rather than at the moment it is built.
/// </summary>
/// <remarks>
/// <para>
/// Late, for two reasons that each force it. A key on the connector's server is
/// opened by asking the connector, and an API whose start depends on a Windows
/// server in somebody else's change window being up is an API that does not
/// start on the morning that server is patched. And a process that only revokes
/// needs no enrolment agent at all: revocation goes through <c>ICertAdmin2</c>
/// without a signature, so building the CA class must not demand a key it will
/// never use.
/// </para>
/// </remarks>
public interface IEnrolmentAgentSource
{
    /// <summary>What this is, for logs, before it has been opened.</summary>
    string Description { get; }

    Task<IEnrolmentAgentKeyStore> OpenAsync(CancellationToken ct = default);
}

/// <summary>An enrolment agent already opened - a file, or a test's.</summary>
public sealed class OpenedEnrolmentAgentSource(IEnrolmentAgentKeyStore store)
    : IEnrolmentAgentSource, IDisposable
{
    public string Description => store.Description;

    public Task<IEnrolmentAgentKeyStore> OpenAsync(CancellationToken ct = default) =>
        Task.FromResult(store);

    public void Dispose() => store.Dispose();
}

/// <summary>
/// The enrolment agent on the connector's server, opened on first use and kept.
/// </summary>
/// <remarks>
/// <para>
/// A failure is not kept. A connector that was down for the first enrolment of the
/// day is asked again for the second, rather than the API remembering an outage
/// until somebody restarts it.
/// </para>
/// <para>
/// A success is re-checked every time it is handed out, because the certificate
/// the connector reported can expire while this process runs. An expired one is
/// dropped and the connector asked again - by then it may well be holding the
/// renewed certificate, and a cached stale one would refuse every enrolment with
/// a sentence about a date nobody can fix from here.
/// </para>
/// </remarks>
public sealed class ConnectorEnrolmentAgentSource(
    IRemoteEnrolmentAgent remote, string where, TimeProvider? clock = null)
    : IEnrolmentAgentSource, IDisposable
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    private readonly SemaphoreSlim gate = new(1, 1);

    private ConnectorEnrolmentAgentKeyStore? opened;

    public string Description => $"enrolment agent held by the connector at {where}";

    public async Task<IEnrolmentAgentKeyStore> OpenAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (opened is not null && StillValid(opened))
            {
                return opened;
            }

            opened?.Dispose();
            opened = null;

            opened = await ConnectorEnrolmentAgentKeyStore.OpenAsync(remote, where, time.GetUtcNow(), ct);

            return opened;
        }
        finally
        {
            gate.Release();
        }
    }

    private bool StillValid(ConnectorEnrolmentAgentKeyStore store)
    {
        try
        {
            FileEnrolmentAgentKeyStore.RequireAgentCertificate(
                store.Certificate, $"the connector at {where}", time.GetUtcNow());

            return true;
        }
        catch (CertificateAuthorityException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        opened?.Dispose();
        gate.Dispose();
    }
}

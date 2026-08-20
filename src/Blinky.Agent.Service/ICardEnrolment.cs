using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// Puts a credential onto a token that is physically present on this machine.
/// </summary>
/// <remarks>
/// <para>
/// An interface because the only implementation is Windows-only, and the
/// executor has no business knowing that. Suppressing the platform warning at
/// the call site would have been the shorter fix and the wrong one: the
/// executor would still name a type it cannot use, and patch 0017 — the same
/// flow over pcsc-lite — would have had nowhere to attach.
/// </para>
/// <para>
/// Null where no implementation is registered. The executor refuses the step
/// and says why, rather than skipping it. See <see cref="JobExecutor"/>.
/// </para>
/// </remarks>
public interface ICardEnrolment
{
    Task EnrolAsync(JobEnvelope job, JobStep step, BackendClient backend, int attempt,
        CancellationToken ct);
}

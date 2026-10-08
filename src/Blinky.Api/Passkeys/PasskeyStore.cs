using Blinky.Api.Persistence;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Passkeys;

/// <summary>What the passkey flow reads and writes, and nothing else.</summary>
/// <remarks>
/// An interface so the flow can be tested without PostgreSQL - the orchestration
/// is where the ordering rules live (persist before calling the provider, delete
/// at the provider before marking revoked), and those are worth a test each.
/// </remarks>
public interface IPasskeyStore
{
    Job? Job(Guid jobId);

    PasskeyCredential? Get(Guid id);

    PasskeyCredential? ForJob(Guid jobId);

    IReadOnlyList<PasskeyCredential> ForUser(string directory, string providerUserId);

    Cardholder? Cardholder(Guid id);

    /// <summary>Inserts or updates, together with any audit events, in one transaction.</summary>
    void Save(PasskeyCredential passkey, params AuditEvent[] audit);
}

public sealed class PasskeyStore(Database database) : IPasskeyStore
{
    public Job? Job(Guid jobId)
    {
        using var session = database.OpenSession();
        return session.Get<Job>(jobId);
    }

    public PasskeyCredential? Get(Guid id)
    {
        using var session = database.OpenSession();
        return session.Get<PasskeyCredential>(id);
    }

    public PasskeyCredential? ForJob(Guid jobId)
    {
        using var session = database.OpenSession();
        return session.Query<PasskeyCredential>().SingleOrDefault(p => p.JobId == jobId);
    }

    public IReadOnlyList<PasskeyCredential> ForUser(string directory, string providerUserId)
    {
        using var session = database.OpenSession();
        return session.Query<PasskeyCredential>()
            .Where(p => p.Directory == directory && p.ProviderUserId == providerUserId)
            .OrderBy(p => p.CreatedAt)
            .ToList();
    }

    public Cardholder? Cardholder(Guid id)
    {
        using var session = database.OpenSession();
        return session.Get<Cardholder>(id);
    }

    public void Save(PasskeyCredential passkey, params AuditEvent[] audit)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        session.SaveOrUpdate(passkey);

        foreach (var entry in audit)
        {
            // A row saved for the first time has its id only now.
            entry.SubjectId ??= passkey.Id;
            session.Save(entry);
        }

        transaction.Commit();
    }
}

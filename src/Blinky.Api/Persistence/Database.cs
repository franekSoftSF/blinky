using Blinky.Infrastructure;
using ISession = NHibernate.ISession;
using ISessionFactory = NHibernate.ISessionFactory;

namespace Blinky.Api.Persistence;

/// <summary>
/// One session factory for the process, sessions opened per unit of work.
/// </summary>
/// <remarks>
/// Deliberately not a per-request session: the API is mostly small, single
/// statement work, and a session that lives as long as a request quietly
/// becomes a first-level cache nobody asked for.
/// </remarks>
public sealed class Database : IDisposable
{
    private readonly Lazy<ISessionFactory> factory;

    public Database(string connectionString)
    {
        ConnectionString = connectionString;
        factory = new Lazy<ISessionFactory>(() => BlinkySessionFactory.Build(connectionString));
    }

    public string ConnectionString { get; }

    public ISession OpenSession() => factory.Value.OpenSession();

    public void Dispose()
    {
        if (factory.IsValueCreated)
        {
            factory.Value.Dispose();
        }
    }
}

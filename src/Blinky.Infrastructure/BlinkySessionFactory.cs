using System.Reflection;
using NHibernate;
using NHibernate.Cfg;
using NHibernate.Cfg.MappingSchema;
using NHibernate.Dialect;
using NHibernate.Driver;
using NHibernate.Mapping.ByCode;
using Environment = NHibernate.Cfg.Environment;

namespace Blinky.Infrastructure;

/// <summary>Builds the NHibernate configuration and session factory.</summary>
public static class BlinkySessionFactory
{
    /// <summary>
    /// The mapped model, without touching a database. Separated so the schema
    /// can be validated, or a script generated, without a session factory.
    /// </summary>
    public static Configuration BuildConfiguration(string connectionString)
    {
        var mapper = new ModelMapper();
        mapper.AddMappings(Assembly.GetExecutingAssembly().GetExportedTypes());

        HbmMapping mapping = mapper.CompileMappingForAllExplicitlyAddedEntities();

        var configuration = new Configuration();
        configuration.SetProperty(Environment.Dialect, typeof(PostgreSQL83Dialect).AssemblyQualifiedName);
        configuration.SetProperty(Environment.ConnectionDriver, typeof(NpgsqlDriver).AssemblyQualifiedName);
        configuration.SetProperty(Environment.ConnectionString, connectionString);
        configuration.SetProperty(Environment.Hbm2ddlKeyWords, "none");

        configuration.AddMapping(mapping);

        return configuration;
    }

    public static ISessionFactory Build(string connectionString) =>
        BuildConfiguration(connectionString).BuildSessionFactory();
}

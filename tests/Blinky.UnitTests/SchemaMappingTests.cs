using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using Blinky.Infrastructure.Mappings;
using NHibernate.Tool.hbm2ddl;

namespace Blinky.UnitTests;

/// <summary>
/// Runs without a database. The live check is `SchemaValidator` at service
/// start; this is the one that fails in CI when a mapping changes and the
/// committed schema does not.
/// </summary>
public sealed class SchemaMappingTests
{
    private const string AnyConnection =
        "Host=localhost;Database=blinky;Username=blinky;Password=blinky";

    private static List<string> GenerateDdl()
    {
        var statements = new List<string>();
        new SchemaExport(BlinkySessionFactory.BuildConfiguration(AnyConnection))
            .Create(statements.Add, execute: false);

        return statements
            .Select(s => s.Trim())
            .Where(s => s.Length > 0 && !s.StartsWith("drop ", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    [Fact]
    public void The_committed_schema_is_what_the_mappings_generate()
    {
        // Regenerate with:
        //     dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql
        var committed = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "001-schema.sql"));

        foreach (var statement in GenerateDdl())
        {
            Assert.True(committed.Contains(statement, StringComparison.Ordinal),
                $"docker/postgres/001-schema.sql is missing:\n{statement}\n\n"
                + "Regenerate it with tools/SchemaTool.");
        }
    }

    [Fact]
    public void Every_entity_in_the_data_model_is_mapped()
    {
        var configuration = BlinkySessionFactory.BuildConfiguration(AnyConnection);

        var mapped = configuration.ClassMappings.Select(m => m.MappedClass).ToHashSet();

        Assert.Contains(typeof(Cardholder), mapped);
        Assert.Contains(typeof(Token), mapped);
        Assert.Contains(typeof(Slot), mapped);
        Assert.Contains(typeof(Credential), mapped);
        Assert.Contains(typeof(CertificateProfile), mapped);
        Assert.Contains(typeof(IssuancePolicy), mapped);
        Assert.Contains(typeof(CaInstance), mapped);
        Assert.Contains(typeof(Agent), mapped);
        Assert.Contains(typeof(Job), mapped);
        Assert.Contains(typeof(SecretEnvelope), mapped);
        Assert.Contains(typeof(AuditEvent), mapped);
    }

    [Fact]
    public void Json_columns_are_jsonb_and_bound_as_jsonb()
    {
        // Both halves matter and only one of them is visible in the DDL: the
        // column type, and the parameter type NHibernate sends. Getting only
        // the first produces a schema that validates and an insert that fails
        // with "column is of type jsonb but expression is of type text".
        var configuration = BlinkySessionFactory.BuildConfiguration(AnyConnection);

        var jsonProperties = configuration.ClassMappings
            .SelectMany(m => m.PropertyIterator)
            .Where(p => p.ColumnIterator.OfType<NHibernate.Mapping.Column>()
                .Any(c => c.SqlType == "jsonb"))
            .ToList();

        Assert.NotEmpty(jsonProperties);
        Assert.All(jsonProperties, property =>
            Assert.Contains(nameof(JsonbType), property.Type.Name, StringComparison.Ordinal));
    }

    [Fact]
    public void Timestamps_are_timestamptz()
    {
        var configuration = BlinkySessionFactory.BuildConfiguration(AnyConnection);

        var timestamps = configuration.ClassMappings
            .SelectMany(m => m.PropertyIterator)
            .Where(p => p.Type.ReturnedClass == typeof(DateTime))
            .SelectMany(p => p.ColumnIterator.OfType<NHibernate.Mapping.Column>())
            .ToList();

        Assert.NotEmpty(timestamps);
        Assert.All(timestamps, column => Assert.Equal("timestamptz", column.SqlType));
    }

    [Fact]
    public void Enumerations_are_stored_by_name()
    {
        // A number in a column is unreadable in a support session, and
        // renumbering an enum would silently rewrite history.
        var configuration = BlinkySessionFactory.BuildConfiguration(AnyConnection);

        var state = configuration.ClassMappings
            .Single(m => m.MappedClass == typeof(Token))
            .PropertyIterator
            .Single(p => p.Name == nameof(Token.State));

        Assert.Contains("EnumStringType", state.Type.Name, StringComparison.Ordinal);
    }

    [Fact]
    public void A_bio_token_and_a_stripped_token_are_both_unrecoverable_but_not_the_same_state()
    {
        var bio = new Token { PukState = Blinky.Domain.CredentialSecretState.NotApplicable };
        var stripped = new Token { PukState = Blinky.Domain.CredentialSecretState.Disabled };
        var ordinary = new Token { PukState = Blinky.Domain.CredentialSecretState.Default };

        Assert.True(bio.IsUnrecoverable);
        Assert.True(stripped.IsUnrecoverable);
        Assert.False(ordinary.IsUnrecoverable);
        Assert.NotEqual(bio.PukState, stripped.PukState);
    }
}

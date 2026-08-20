using NHibernate.Mapping.ByCode;
using NHibernate.Type;

namespace Blinky.Infrastructure.Mappings;

/// <summary>Shapes shared by every mapping, so they cannot drift apart.</summary>
internal static class Conventions
{
    /// <summary>
    /// PostgreSQL timestamptz. Npgsql insists a value written to one has
    /// DateTimeKind.Utc, so everything that writes a timestamp writes
    /// DateTime.UtcNow - a local time here fails at insert, not at build.
    /// </summary>
    public const string Timestamp = "timestamptz";

    /// <summary>
    /// Payloads whose shape belongs to a protocol version rather than to the
    /// database. Mapped explicitly: without the SQL type NHibernate infers
    /// text, the column is created as text, and comparisons quietly stop
    /// behaving like JSON.
    /// </summary>
    public const string Json = "jsonb";

    /// <summary>
    /// Enumerations are stored as their names. A number in a column is
    /// unreadable in a support session, and renumbering an enum silently
    /// rewrites history.
    /// </summary>
    public static void AsEnumString<T>(IPropertyMapper mapper, string column, bool notNull = true)
        where T : struct
    {
        mapper.Column(c =>
        {
            c.Name(column);
            c.SqlType("text");
            c.NotNullable(notNull);
        });
        mapper.Type<EnumStringType<T>>();
    }

    public static void AsJson(IPropertyMapper mapper, string column, bool notNull = true)
    {
        mapper.Column(c =>
        {
            c.Name(column);
            c.SqlType(Json);
            c.NotNullable(notNull);
        });

        // The column type alone is not enough - see JsonbType.
        mapper.Type<JsonbType>();
    }

    public static void AsTimestamp(IPropertyMapper mapper, string column, bool notNull = true) =>
        mapper.Column(c =>
        {
            c.Name(column);
            c.SqlType(Timestamp);
            c.NotNullable(notNull);
        });
}

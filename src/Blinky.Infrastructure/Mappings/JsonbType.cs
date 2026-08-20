using System.Data;
using System.Data.Common;
using NHibernate;
using NHibernate.Engine;
using NHibernate.SqlTypes;
using NHibernate.UserTypes;
using NpgsqlTypes;

namespace Blinky.Infrastructure.Mappings;

/// <summary>
/// Binds a string to a PostgreSQL <c>jsonb</c> parameter.
/// </summary>
/// <remarks>
/// Declaring the column type in the mapping is not enough, and the failure is
/// invisible until the first insert: NHibernate sends the value as text, and
/// PostgreSQL refuses with <c>42804: column "payload" is of type jsonb but
/// expression is of type text</c> - it will not cast text to jsonb for a
/// parameter. Schema validation never inserts anything, so it cannot catch
/// this; the round trip in tools/SchemaTool exists because of it.
/// </remarks>
public sealed class JsonbType : IUserType
{
    public SqlType[] SqlTypes => [new SqlType(DbType.String)];

    public System.Type ReturnedType => typeof(string);

    public bool IsMutable => false;

    public object? NullSafeGet(DbDataReader rs, string[] names, ISessionImplementor session,
        object owner) =>
        NHibernateUtil.String.NullSafeGet(rs, names[0], session);

    public void NullSafeSet(DbCommand cmd, object? value, int index, ISessionImplementor session)
    {
        var parameter = cmd.Parameters[index];

        // Guarded rather than cast: a different provider would throw here with
        // a message about jsonb, which would send the reader in the wrong
        // direction entirely.
        if (parameter is Npgsql.NpgsqlParameter npgsql)
        {
            npgsql.NpgsqlDbType = NpgsqlDbType.Jsonb;
        }

        parameter.Value = value ?? (object)DBNull.Value;
    }

    public object? DeepCopy(object? value) => value;

    public object? Replace(object? original, object? target, object? owner) => original;

    public object? Assemble(object? cached, object? owner) => cached;

    public object? Disassemble(object? value) => value;

    // string.Equals, explicitly: an unqualified Equals here resolves to this
    // very method and recurses until the stack ends.
    public new bool Equals(object? x, object? y) =>
        string.Equals(x as string, y as string, StringComparison.Ordinal);

    public int GetHashCode(object? x) => x?.GetHashCode() ?? 0;
}

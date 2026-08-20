using NHibernate.Cfg;
using Tool = NHibernate.Tool.hbm2ddl;

namespace Blinky.Infrastructure;

/// <summary>The outcome of comparing the mappings against the live schema.</summary>
public sealed record SchemaValidationResult(bool IsValid, string Summary, string? Detail = null)
{
    public override string ToString() => IsValid ? "schema ok" : $"schema drift: {Summary}";
}

/// <summary>
/// Compares the mapped model against the database at service start.
/// </summary>
/// <remarks>
/// <b>It logs and continues; it does not kill the process.</b> A missing column
/// should produce one readable line while the container comes up, not a restart
/// loop with no explanation - and a service that refuses to start cannot tell
/// anyone why. Carried over from FAG, where the same choice paid for itself.
/// </remarks>
public static class SchemaValidator
{
    public static SchemaValidationResult Validate(Configuration configuration)
    {
        try
        {
            new Tool.SchemaValidator(configuration).Validate();

            return new SchemaValidationResult(true, "mappings match the database");
        }
        catch (Exception ex)
        {
            // The message carries the table and column, which is the only part
            // anybody reading a container log actually needs.
            return new SchemaValidationResult(false, ex.Message.ReplaceLineEndings(" "),
                ex.ToString());
        }
    }
}

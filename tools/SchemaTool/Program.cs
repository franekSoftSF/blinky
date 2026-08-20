// Blinky - schema tool.
//
// Generates docker/postgres/001-schema.sql from the NHibernate mappings, so the
// schema and the mappings cannot drift apart. SchemaValidator checks the same
// two things against each other at service start; regenerating here is how the
// drift gets fixed rather than argued about.
//
//     dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql

using System.Text;
using Blinky.Infrastructure;
using NHibernate.Tool.hbm2ddl;

// --roundtrip writes one row of every awkward type and reads it back. Schema
// validation compares shapes and never inserts anything, so it cannot catch a
// jsonb parameter that NHibernate sends as text - which PostgreSQL rejects.
if (args.Contains("--roundtrip"))
{
    return RoundTrip.Run(Environment.GetEnvironmentVariable("BLINKY_CONNECTION")
        ?? "Host=localhost;Database=blinky;Username=blinky;Password=blinky");
}

var output = args.Length > 0 ? args[0] : null;

// No connection is made; the dialect alone decides the DDL.
var configuration = BlinkySessionFactory.BuildConfiguration(
    "Host=localhost;Database=blinky;Username=blinky;Password=blinky");

var statements = new List<string>();
new SchemaExport(configuration).Create(statements.Add, execute: false);

var sql = new StringBuilder();
sql.AppendLine("-- Blinky schema. GENERATED - do not edit by hand.");
sql.AppendLine("--");
sql.AppendLine("-- Regenerate with:");
sql.AppendLine("--     dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql");
sql.AppendLine("--");
sql.AppendLine("-- PostgreSQL runs this only against an empty data directory, so changing");
sql.AppendLine("-- the schema means `docker compose down -v` or a hand-written ALTER.");
sql.AppendLine();

// SchemaExport emits the drops as well. This file is an init script that runs
// against an empty data directory, and a DROP in it is a loaded gun pointed at
// whichever live database somebody eventually runs it against.
var creates = statements
    .Select(s => s.Trim())
    .Where(s => s.Length > 0)
    .Where(s => !s.StartsWith("drop ", StringComparison.OrdinalIgnoreCase))
    .ToList();

foreach (var statement in creates)
{
    sql.AppendLine(statement.EndsWith(';') ? statement : statement + ";");
    sql.AppendLine();
}

if (output is null)
{
    Console.Write(sql.ToString());
    return 0;
}

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
File.WriteAllText(output, sql.ToString());
Console.WriteLine($"{output}: {creates.Count} statements");
return 0;

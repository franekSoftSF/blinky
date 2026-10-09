using System.Text.Json;

namespace Blinky.Api.Distribution;

/// <summary>
/// The installers and scripts an operator downloads from the console, listed by
/// <c>downloads.json</c> beside them (0105).
/// </summary>
/// <remarks>
/// <para>
/// The pattern WSODeployer settled on: a build drops the files and a manifest with
/// each one's SHA-256 into a folder the API reads; the console lists them to a
/// signed-in operator; the install script checks the hash against the same manifest.
/// Before this the connector reached the CA server by <c>scp</c> from a developer's
/// checkout, and an agent MSI by whatever copy somebody had.
/// </para>
/// <para>
/// Only a name the manifest lists is served, and only from this folder. The name
/// arrives in a URL; a file that merely exists beside the manifest, or a path that
/// climbs out of it, is not something this route hands to anybody.
/// </para>
/// </remarks>
public sealed class Downloads(string folder)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public const string ManifestName = "downloads.json";

    public string Folder => folder;

    /// <summary>The manifest, or null where nothing has been published.</summary>
    public DownloadManifest? Manifest()
    {
        var path = Path.Combine(folder, ManifestName);

        if (!File.Exists(path))
        {
            return null;
        }

        using var stream = File.OpenRead(path);

        return JsonSerializer.Deserialize<DownloadManifest>(stream, Json);
    }

    /// <summary>The listed file and where it is, or null for anything not listed.</summary>
    public (DownloadEntry Entry, string Path)? Resolve(string name)
    {
        if (string.IsNullOrWhiteSpace(name)
            || name != System.IO.Path.GetFileName(name)
            || name.Equals(ManifestName, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var entry = Manifest()?.Files.FirstOrDefault(f => string.Equals(f.File, name, StringComparison.Ordinal));

        if (entry is null)
        {
            return null;
        }

        var path = System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, entry.File));
        var root = System.IO.Path.GetFullPath(folder) + System.IO.Path.DirectorySeparatorChar;

        return path.StartsWith(root, StringComparison.Ordinal) && File.Exists(path) ? (entry, path) : null;
    }

    /// <summary>
    /// Whether a file is part of a machine's set (0110). By name, because the names are
    /// the build's and fixed: a workstation gets the agent and its scripts, a connector's
    /// server the connector and its script, and neither the other's.
    /// </summary>
    public static bool Belongs(string file, string set) => set switch
    {
        "workstation" => file.StartsWith("blinky-workstation-", StringComparison.Ordinal)
                         || file.StartsWith("blinky-agent-", StringComparison.Ordinal)
                         || file is "install-windows-client.ps1" or "enable-ecc-smartcard-logon.ps1" or "blinky-server.json",
        "connector" => file.StartsWith("blinky-connector-", StringComparison.Ordinal)
                       || file.StartsWith("blinky-adcs-connector-", StringComparison.Ordinal)
                       || file is "Install-BlinkyConnector.ps1" or "blinky-server.json",
        _ => false,
    };

    public static string ContentType(string file) =>
        System.IO.Path.GetExtension(file).ToLowerInvariant() switch
        {
            ".msi" => "application/x-msi",
            ".zip" => "application/zip",
            ".ps1" or ".sh" or ".txt" or ".md" => "text/plain; charset=utf-8",
            ".crt" or ".pem" => "application/x-pem-file",
            _ => "application/octet-stream",
        };
}

/// <param name="Built">When the build that wrote it ran, ISO 8601.</param>
/// <param name="Revision">The commit it was built from, with -dirty for an uncommitted tree.</param>
public sealed record DownloadManifest(string? Built, string? Revision, IReadOnlyList<DownloadEntry> Files);

/// <param name="Kind">connector, agent, script.</param>
/// <param name="Description">One line for the console, in the console's language.</param>
public sealed record DownloadEntry(
    string File,
    string Kind,
    string? Version,
    long Size,
    string Sha256,
    string? Description);

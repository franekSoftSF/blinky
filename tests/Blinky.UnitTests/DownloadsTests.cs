using Blinky.Api.Distribution;

namespace Blinky.UnitTests;

/// <summary>
/// The console's downloads (0105): a name from a URL reaches a file only through the
/// manifest, and never outside the folder.
/// </summary>
public sealed class DownloadsTests : IDisposable
{
    private readonly string folder = System.IO.Directory.CreateTempSubdirectory("blinky-downloads-").FullName;

    public DownloadsTests()
    {
        File.WriteAllText(Path.Combine(folder, "blinky-adcs-connector-0.5.0.msi"), "msi");
        File.WriteAllText(Path.Combine(folder, "not-listed.ps1"), "secret-ish");
        File.WriteAllText(Path.Combine(folder, Downloads.ManifestName), """
            {"built":"2026-10-08T21:39:25Z","revision":"abc","files":[
              {"file":"blinky-adcs-connector-0.5.0.msi","kind":"connector","version":"0.5.0","size":3,"sha256":"AA","description":"Konektor"},
              {"file":"listed-but-missing.msi","kind":"agent","version":"0.5.0","size":1,"sha256":"BB","description":null}
            ]}
            """);
    }

    [Fact]
    public void A_listed_file_is_served_with_its_entry()
    {
        var found = new Downloads(folder).Resolve("blinky-adcs-connector-0.5.0.msi");

        Assert.NotNull(found);
        Assert.Equal("connector", found.Value.Entry.Kind);
        Assert.Equal(Path.Combine(folder, "blinky-adcs-connector-0.5.0.msi"), found.Value.Path);
    }

    [Theory]
    [InlineData("not-listed.ps1")]
    [InlineData("listed-but-missing.msi")]
    [InlineData("downloads.json")]
    [InlineData("../downloads.json")]
    [InlineData("..\\blinky-adcs-connector-0.5.0.msi")]
    [InlineData("")]
    public void Nothing_else_is(string name)
    {
        Assert.Null(new Downloads(folder).Resolve(name));
    }

    [Fact]
    public void A_folder_with_nothing_published_has_no_manifest_rather_than_an_error()
    {
        var empty = System.IO.Directory.CreateTempSubdirectory("blinky-downloads-empty-").FullName;

        try
        {
            Assert.Null(new Downloads(empty).Manifest());
            Assert.Null(new Downloads(empty).Resolve("anything.msi"));
        }
        finally
        {
            System.IO.Directory.Delete(empty, recursive: true);
        }
    }

    public void Dispose() => System.IO.Directory.Delete(folder, recursive: true);
}

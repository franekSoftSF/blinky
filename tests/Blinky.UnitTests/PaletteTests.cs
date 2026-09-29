using System.Text.RegularExpressions;
using Blinky.PaletteTool;

namespace Blinky.UnitTests;

/// <summary>
/// The one palette, and the two files generated from it.
/// </summary>
/// <remarks>
/// <para>
/// The console carried 269 distinct colours before 0099 - forty of them the
/// same green a digit apart, and a settings stylesheet repainting the accent
/// of every page with <c>!important</c>. Nothing could have caught that,
/// because a hex in a stylesheet is not checkable by anything.
/// </para>
/// <para>
/// So: colours are data in <see cref="Palette"/>, the stylesheet and the two
/// resource dictionaries are generated from it, and these tests fail when a
/// generated file is edited by hand, when a stylesheet grows a raw colour
/// again, or when a pair of text colours stops being readable.
/// </para>
/// </remarks>
public class PaletteTests
{
    private static string RepositoryFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine([directory.FullName, .. parts]);

            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate).Replace("\r\n", "\n");
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException(
            $"Could not find {Path.Combine(parts)} above {AppContext.BaseDirectory}");
    }

    /// <summary>
    /// WCAG 2.1 asks 4,5:1 of body text. Every pair that carries words meets it.
    /// </summary>
    [Fact]
    public void Every_pair_of_text_colours_is_readable()
    {
        var failures = new List<string>();

        foreach (var palette in Palette.All)
        {
            foreach (var pair in palette.TextPairs)
            {
                var contrast = Palette.Contrast(pair.Foreground, pair.Background);

                if (contrast < 4.5)
                {
                    failures.Add(
                        $"{palette.Name}: {pair.What} - {pair.Foreground} na {pair.Background} = {contrast:F2}:1");
                }
            }
        }

        Assert.Empty(failures);
    }

    /// <summary>
    /// Both themes define the same roles. A role in one and not the other is a
    /// colour that resolves to nothing the moment somebody switches theme.
    /// </summary>
    [Fact]
    public void Both_themes_define_the_same_roles()
    {
        var dark = Palette.Dark.Roles.Select(role => role.Role);
        var light = Palette.Light.Roles.Select(role => role.Role);

        Assert.Equal(dark, light);
    }

    [Fact]
    public void Every_colour_is_a_hex_of_the_right_length()
    {
        foreach (var palette in Palette.All)
        {
            foreach (var (role, colour) in palette.Roles)
            {
                Assert.True(
                    Regex.IsMatch(colour.Hex, "^#[0-9A-F]{6}([0-9A-F]{2})?$"),
                    $"{palette.Name}/{role} is {colour.Hex}");
            }
        }
    }

    [Fact]
    public void The_committed_stylesheet_is_what_the_generator_writes()
    {
        Assert.Equal(Generator.Tokens(), RepositoryFile("frontend", "src", "tokens.scss"));
    }

    [Theory]
    [InlineData("dark", "Dark.xaml")]
    [InlineData("light", "Light.xaml")]
    public void The_committed_dictionaries_are_what_the_generator_writes(string theme, string file)
    {
        var palette = Palette.All.Single(candidate => candidate.Name == theme);

        Assert.Equal(
            Generator.Theme(palette),
            RepositoryFile("src", "Blinky.Agent.Ui", "Themes", file));
    }

    /// <summary>
    /// The dictionaries are generated, but the views are not: every brush a
    /// view asks for by name has to exist in both.
    /// </summary>
    [Fact]
    public void Every_brush_the_views_ask_for_exists_in_both_themes()
    {
        var dark = Keys(Generator.Theme(Palette.Dark));
        var light = Keys(Generator.Theme(Palette.Light));

        Assert.Equal(dark, light);

        var views = new DirectoryInfo(AppContext.BaseDirectory);
        string? found = null;

        while (views is not null && found is null)
        {
            var candidate = Path.Combine(views.FullName, "src", "Blinky.Agent.Ui");
            found = System.IO.Directory.Exists(candidate) ? candidate : null;
            views = views.Parent;
        }

        Assert.NotNull(found);

        var asked = System.IO.Directory.EnumerateFiles(found, "*.xaml", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}Themes{Path.DirectorySeparatorChar}"))
            .SelectMany(path => Regex.Matches(File.ReadAllText(path), @"\{DynamicResource (\w+)\}"))
            .Select(match => match.Groups[1].Value)
            .Distinct()
            .Order()
            .ToList();

        var missing = asked.Where(key => !dark.Contains(key)).ToList();

        Assert.Equal([], missing);
    }

    /// <summary>
    /// No stylesheet carries a colour of its own.
    /// </summary>
    /// <remarks>
    /// This is the test that keeps 0099 from happening twice. A hex in a
    /// stylesheet is a colour nobody can find again: it does not follow the
    /// theme, no test can read it, and the next person needing that shade
    /// writes a fourth one a digit away. The one exception is written down
    /// here with its reason rather than left to be discovered.
    /// </remarks>
    [Fact]
    public void No_stylesheet_carries_a_colour_of_its_own()
    {
        // A QR code has to be black on white in both themes: a scanner reading
        // one inverted by a dark theme finds no contrast at all.
        var allowed = new[] { ("sign-in.ts", "#fff") };

        var source = SourceDirectory();
        var offenders = new List<string>();

        var files = System.IO.Directory.EnumerateFiles(source, "*.scss", SearchOption.AllDirectories)
            .Concat(System.IO.Directory.EnumerateFiles(source, "*.ts", SearchOption.AllDirectories))
            .Where(path => Path.GetFileName(path) != "tokens.scss");

        foreach (var file in files)
        {
            var text = Regex.Replace(File.ReadAllText(file), @"/\*.*?\*/", string.Empty, RegexOptions.Singleline);
            text = Regex.Replace(text, @"//[^
]*", string.Empty);

            foreach (var hex in Regex.Matches(text, @"#[0-9a-fA-F]{3,8}").Select(match => match.Value))
            {
                var name = Path.GetFileName(file);

                if (!allowed.Any(pair => pair == (name, hex)))
                {
                    offenders.Add($"{name}: {hex}");
                }
            }
        }

        Assert.Empty(offenders);
    }

    private static string SourceDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "frontend", "src");

            if (System.IO.Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"No frontend/src above {AppContext.BaseDirectory}");
    }

    private static IReadOnlyList<string> Keys(string dictionary) =>
        Regex.Matches(dictionary, @"x:Key=""(\w+)""")
            .Select(match => match.Groups[1].Value)
            .Order()
            .ToList();
}

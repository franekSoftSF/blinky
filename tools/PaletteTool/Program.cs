using Blinky.PaletteTool;

// Rewrites the three files the palette generates. Run it from the repository
// root after editing Palette.cs:
//
//     dotnet run --project tools/PaletteTool
//
// A repository root can be given as the one argument, which is what the test
// that checks the committed files does not need and CI does not use - it is
// there for the person running this from somewhere else.
var root = args.Length > 0 ? args[0] : Directory.GetCurrentDirectory();

if (!File.Exists(Path.Combine(root, "Blinky.slnx")))
{
    Console.Error.WriteLine($"{root} is not the repository root: no Blinky.slnx in it.");
    return 1;
}

Write(Path.Combine(root, "frontend", "src", "tokens.scss"), Generator.Tokens());
Write(Path.Combine(root, "src", "Blinky.Agent.Ui", "Themes", "Dark.xaml"), Generator.Theme(Palette.Dark));
Write(Path.Combine(root, "src", "Blinky.Agent.Ui", "Themes", "Light.xaml"), Generator.Theme(Palette.Light));

return 0;

// LF and UTF-8 without a BOM, because .editorconfig says so and because a
// generator that fights the repository's line endings makes every run a diff.
static void Write(string path, string content)
{
    File.WriteAllText(path, content.Replace("\r\n", "\n"), new System.Text.UTF8Encoding(false));
    Console.WriteLine($"wrote {path}");
}

namespace Blinky.PaletteTool;

/// <summary>One colour, as the hex somebody can paste into a design tool.</summary>
public readonly record struct Colour(string Hex)
{
    public byte R => Convert.ToByte(Hex.Substring(1, 2), 16);

    public byte G => Convert.ToByte(Hex.Substring(3, 2), 16);

    public byte B => Convert.ToByte(Hex.Substring(5, 2), 16);

    public override string ToString() => Hex;
}

/// <summary>A pair the eye has to separate, and what it is for.</summary>
public readonly record struct TextPair(string What, Colour Foreground, Colour Background);

/// <summary>
/// Every colour Blinky draws with, for one theme, as data.
/// </summary>
/// <remarks>
/// <para>
/// In C# rather than in the stylesheet or in XAML because three surfaces have
/// to agree - the Angular console, the WPF tray UI and the mark - and because
/// a test has to be able to read every pair of text colours and count the
/// contrast. Colours written straight into a stylesheet cannot be checked by
/// anything, and "looks fine on my screen" is how the console ended up with
/// 269 distinct hexes, forty of them the same green a digit apart.
/// </para>
/// <para>
/// The roles are named after what they do, not after what they look like: a
/// role that reads <c>Accent</c> is cyan in the dark theme and teal in the
/// light one, and neither name belongs in a stylesheet. The two themes define
/// exactly the same roles - one missing from either is a hole nobody sees
/// until somebody switches theme.
/// </para>
/// <para>
/// The accent works in one direction only. As a fill it carries near-black
/// text; as text it has to be darkened on white (<c>AccentText</c> in the
/// light theme) or it misses 4,5:1 by a hair. That is why <c>Accent</c> and
/// <c>AccentText</c> are two roles and not one.
/// </para>
/// </remarks>
public sealed record Palette(
    string Name,
    Colour Background,
    Colour BackgroundGlow,
    Colour Surface,
    Colour Panel,
    Colour PanelRaised,
    Colour Field,
    Colour Hover,
    Colour Border,
    Colour BorderStrong,
    Colour Text,
    Colour TextBody,
    Colour TextMuted,
    Colour TextFaint,
    Colour Accent,
    Colour AccentText,
    Colour OnAccent,
    Colour AccentSoft,
    Colour AccentBorder,
    Colour Ok,
    Colour OkSoft,
    Colour OkBorder,
    Colour Warning,
    Colour WarningSoft,
    Colour WarningBorder,
    Colour Danger,
    Colour DangerSoft,
    Colour DangerBorder,
    Colour Shadow,
    Colour AccentGlow)
{
    public static readonly Palette Dark = new(
        Name: "dark",
        Background: new("#07101E"),
        BackgroundGlow: new("#142B4E"),
        Surface: new("#081321"),
        Panel: new("#0D192B"),
        PanelRaised: new("#0E1C30"),
        Field: new("#0B1626"),
        Hover: new("#0E1D30"),
        Border: new("#1C2C44"),
        BorderStrong: new("#273952"),
        Text: new("#EAF2FF"),
        TextBody: new("#AAB8CA"),
        TextMuted: new("#93A3B8"),
        TextFaint: new("#8294AB"),
        Accent: new("#18C9DF"),
        AccentText: new("#35D6E8"),
        OnAccent: new("#03131B"),
        AccentSoft: new("#102F40"),
        AccentBorder: new("#2C596D"),
        Ok: new("#55DFAD"),
        OkSoft: new("#153B34"),
        OkBorder: new("#2A5C4B"),
        Warning: new("#FFD477"),
        WarningSoft: new("#40351E"),
        WarningBorder: new("#684C23"),
        Danger: new("#FF8993"),
        DangerSoft: new("#441E2A"),
        DangerBorder: new("#6A3946"),

        // The two with an alpha channel, and the only two the WPF dictionaries
        // skip: a drop shadow under a panel and the halo under an accent
        // button, both of which have to let the background through.
        Shadow: new("#00000033"),
        AccentGlow: new("#12C6DC25"));

    public static readonly Palette Light = new(
        Name: "light",
        Background: new("#EEF3F8"),
        BackgroundGlow: new("#D9EDF5"),
        Surface: new("#F9FBFD"),
        Panel: new("#FFFFFF"),
        PanelRaised: new("#FFFFFF"),
        Field: new("#FFFFFF"),
        Hover: new("#EAF1F6"),
        Border: new("#D8E1EB"),
        BorderStrong: new("#CBD7E2"),
        Text: new("#142238"),
        TextBody: new("#42556B"),
        TextMuted: new("#566A80"),
        TextFaint: new("#5A6D82"),
        Accent: new("#087D8C"),
        AccentText: new("#05606C"),
        OnAccent: new("#FFFFFF"),
        AccentSoft: new("#DDF2F5"),
        AccentBorder: new("#8FC9D0"),
        Ok: new("#0F6B48"),
        OkSoft: new("#D9F6E7"),
        OkBorder: new("#A9DCC4"),
        Warning: new("#6C4B00"),
        WarningSoft: new("#FFF0C7"),
        WarningBorder: new("#E8C879"),
        Danger: new("#A32036"),
        DangerSoft: new("#FFE0E4"),
        DangerBorder: new("#E0ABB0"),
        Shadow: new("#26446612"),
        AccentGlow: new("#087D8C1F"));

    public static IReadOnlyList<Palette> All => [Dark, Light];

    /// <summary>
    /// Every pair of colours that carries words, for the test that counts them.
    /// </summary>
    /// <remarks>
    /// Borders and fills are not here: WCAG asks 4,5:1 of text, and a border
    /// that met it would make the console look like a spreadsheet.
    /// </remarks>
    public IReadOnlyList<TextPair> TextPairs =>
    [
        new("tekst na tle", Text, Background),
        new("tekst na panelu", Text, Panel),
        new("tekst na powierzchni", Text, Surface),
        new("tekst na karcie", Text, PanelRaised),
        new("tekst w polu", Text, Field),
        new("tresc tabeli na panelu", TextBody, Panel),
        new("tresc tabeli na tle", TextBody, Background),
        new("tekst drugorzedny na tle", TextMuted, Background),
        new("tekst drugorzedny na panelu", TextMuted, Panel),
        new("tekst drugorzedny na powierzchni", TextMuted, Surface),
        new("podpis na tle", TextFaint, Background),
        new("podpis na panelu", TextFaint, Panel),
        new("napis na przycisku akcentowym", OnAccent, Accent),
        new("tekst akcentowy na tle", AccentText, Background),
        new("tekst akcentowy na panelu", AccentText, Panel),
        new("tekst akcentowy na powierzchni", AccentText, Surface),
        new("tekst akcentowy na plamie akcentu", AccentText, AccentSoft),
        new("stan poprawny na tle", Ok, Background),
        new("stan poprawny na panelu", Ok, Panel),
        new("stan poprawny na swojej plamie", Ok, OkSoft),
        new("ostrzezenie na tle", Warning, Background),
        new("ostrzezenie na panelu", Warning, Panel),
        new("ostrzezenie na swojej plamie", Warning, WarningSoft),
        new("blad na tle", Danger, Background),
        new("blad na panelu", Danger, Panel),
        new("blad na swojej plamie", Danger, DangerSoft),
    ];

    /// <summary>Every role, in the order both generated files list them.</summary>
    public IReadOnlyList<(string Role, Colour Colour)> Roles =>
    [
        ("background", Background),
        ("background-glow", BackgroundGlow),
        ("surface", Surface),
        ("panel", Panel),
        ("panel-raised", PanelRaised),
        ("field", Field),
        ("hover", Hover),
        ("border", Border),
        ("border-strong", BorderStrong),
        ("text", Text),
        ("text-body", TextBody),
        ("text-muted", TextMuted),
        ("text-faint", TextFaint),
        ("accent", Accent),
        ("accent-text", AccentText),
        ("on-accent", OnAccent),
        ("accent-soft", AccentSoft),
        ("accent-border", AccentBorder),
        ("ok", Ok),
        ("ok-soft", OkSoft),
        ("ok-border", OkBorder),
        ("warning", Warning),
        ("warning-soft", WarningSoft),
        ("warning-border", WarningBorder),
        ("danger", Danger),
        ("danger-soft", DangerSoft),
        ("danger-border", DangerBorder),
        ("shadow", Shadow),
        ("accent-glow", AccentGlow),
    ];

    /// <summary>WCAG 2.1 contrast ratio, 1:1 to 21:1.</summary>
    public static double Contrast(Colour a, Colour b)
    {
        var first = Luminance(a);
        var second = Luminance(b);

        var lighter = Math.Max(first, second);
        var darker = Math.Min(first, second);

        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double Luminance(Colour colour) =>
        (0.2126 * Channel(colour.R)) + (0.7152 * Channel(colour.G)) + (0.0722 * Channel(colour.B));

    private static double Channel(byte value)
    {
        var part = value / 255.0;

        return part <= 0.03928 ? part / 12.92 : Math.Pow((part + 0.055) / 1.055, 2.4);
    }
}

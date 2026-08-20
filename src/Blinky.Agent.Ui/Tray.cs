using System;
using System.Drawing;
using System.Windows.Forms;

namespace Blinky.Agent.Ui;

/// <summary>
/// The icon by the clock, and the menu behind it.
/// </summary>
/// <remarks>
/// <para>
/// <c>System.Windows.Forms.NotifyIcon</c> because WPF has no tray icon of its
/// own and never has. The alternative was a NuGet package for one icon and one
/// menu; this is two references in the project file and no dependency to keep
/// current.
/// </para>
/// <para>
/// The icon says whether a token is in a reader and nothing more interesting
/// than that. Anything else — expiry, state, what is in a slot — is a fact
/// about a card, and a card can leave the machine between two glances at an
/// icon that only redraws when something asks it to.
/// </para>
/// </remarks>
public sealed class Tray : IDisposable
{
    private readonly NotifyIcon icon;
    private readonly ToolStripMenuItem polish;
    private readonly ToolStripMenuItem english;

    public event Action? OpenRequested;
    public event Action? ExitRequested;

    public Tray()
    {
        polish = new ToolStripMenuItem("Polski", null, (_, _) => Switch("pl"));
        english = new ToolStripMenuItem("English", null, (_, _) => Switch("en"));

        var language = new ToolStripMenuItem(Strings.Current["Tray.Language"]);
        language.DropDownItems.Add(polish);
        language.DropDownItems.Add(english);

        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem(Strings.Current["Tray.Open"], null,
            (_, _) => OpenRequested?.Invoke()));
        menu.Items.Add(language);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem(Strings.Current["Tray.Exit"], null,
            (_, _) => ExitRequested?.Invoke()));

        icon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Visible = true,
            Text = Strings.Current["App.Name"],
            ContextMenuStrip = menu,
        };

        // Double-click opens, because that is what every other tray icon does.
        icon.DoubleClick += (_, _) => OpenRequested?.Invoke();

        Mark();
    }

    /// <summary>
    /// The hover text. Kept to 63 characters because Windows silently truncates
    /// beyond that, and a sentence cut mid-word reads as a bug.
    /// </summary>
    public void Describe(int tokenCount)
    {
        var text = tokenCount == 0
            ? Strings.Current["Tray.NoToken"]
            : string.Format(Strings.Current["Tray.TokenCount"], tokenCount);

        icon.Text = text.Length <= 63 ? text : text[..63];
    }

    private void Switch(string language)
    {
        Strings.Current.Use(language);

        // The menu was built with the old strings and does not re-bind: WPF
        // bindings update, Windows Forms items do not.
        Rebuild();
        Mark();
    }

    private void Rebuild()
    {
        if (icon.ContextMenuStrip is not { } menu)
        {
            return;
        }

        menu.Items[0].Text = Strings.Current["Tray.Open"];
        menu.Items[1].Text = Strings.Current["Tray.Language"];
        menu.Items[3].Text = Strings.Current["Tray.Exit"];
    }

    private void Mark()
    {
        polish.Checked = Strings.Current.IsPolish;
        english.Checked = !Strings.Current.IsPolish;
    }

    public void Dispose()
    {
        // Without this the icon stays by the clock until somebody hovers over
        // it, which looks like a process that would not die.
        icon.Visible = false;
        icon.Dispose();
    }
}

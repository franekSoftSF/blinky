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
    private readonly Icon trayIcon;
    private readonly ToolStripMenuItem open;
    private readonly ToolStripMenuItem exit;

    public event Action? OpenRequested;
    public event Action? ExitRequested;

    public Tray()
    {
        // Language and theme are chosen in the window, as in BlinkyLite; the
        // menu keeps what needs no window.
        open = new ToolStripMenuItem(Strings.Current["Tray.Open"], null,
            (_, _) => OpenRequested?.Invoke());
        exit = new ToolStripMenuItem(Strings.Current["Tray.Exit"], null,
            (_, _) => ExitRequested?.Invoke());

        var menu = new ContextMenuStrip();
        menu.Items.Add(open);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        // Windows Forms items do not bind, so a language chosen in the window
        // reaches the menu through the change notification instead.
        Strings.Current.PropertyChanged += (_, _) =>
        {
            open.Text = Strings.Current["Tray.Open"];
            exit.Text = Strings.Current["Tray.Exit"];
        };

        trayIcon = LoadTrayIcon();

        icon = new NotifyIcon
        {
            Icon = trayIcon,
            Visible = true,
            Text = Strings.Current["App.Name"],
            ContextMenuStrip = menu,
        };

        // Double-click opens, because that is what every other tray icon does.
        icon.DoubleClick += (_, _) => OpenRequested?.Invoke();
    }

    /// <summary>
    /// The icon at the size the notification area actually draws.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Asked for by size, from the packaged .ico, so Windows picks the 16px
    /// drawing that is in the file rather than shrinking the 256px one.
    /// <c>Icon.ExtractAssociatedIcon</c> — the obvious call, and what this used
    /// to do — returns whatever the shell considers the large icon, which the
    /// tray then squeezes down; the result is a smudge beside crisp system
    /// icons, at the one size this icon is seen at most.
    /// </para>
    /// <para>
    /// <c>SystemInformation.SmallIconSize</c> rather than a hard 16: it is 20
    /// at 125% scaling and 24 at 150%, and the .ico carries both.
    /// </para>
    /// </remarks>
    private static Icon LoadTrayIcon()
    {
        try
        {
            var packaged = System.Windows.Application.GetResourceStream(
                new Uri("Assets/blinky-agent.ico", UriKind.Relative));

            if (packaged is not null)
            {
                using var stream = packaged.Stream;

                return new Icon(stream, SystemInformation.SmallIconSize);
            }
        }
        catch (Exception)
        {
            // Falls through. A missing or unreadable icon is a cosmetic
            // problem, and a tray that refuses to appear over one would turn it
            // into an outage: without the tray there is no way to answer a PIN
            // prompt.
        }

        return (Icon)SystemIcons.Shield.Clone();
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

    public void Dispose()
    {
        // Without this the icon stays by the clock until somebody hovers over
        // it, which looks like a process that would not die.
        icon.Visible = false;
        icon.Dispose();
        trayIcon.Dispose();
    }
}

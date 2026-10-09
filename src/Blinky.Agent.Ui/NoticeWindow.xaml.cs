using System.Windows;
using System.Windows.Controls;

namespace Blinky.Agent.Ui;

/// <summary>What a notice is about, which decides its mark and colour.</summary>
public enum NoticeKind
{
    Success,
    Information,
    Warning,
}

/// <summary>
/// The agent's message box: a sentence, a mark, a button - in the window's
/// own theme.
/// </summary>
public partial class NoticeWindow : Window
{
    private NoticeWindow()
    {
        InitializeComponent();
    }

    /// <summary>Tells the person something and waits for OK.</summary>
    public static void Show(string message, NoticeKind kind = NoticeKind.Information)
    {
        var notice = Build(message, kind);
        notice.OkButton.Content = Strings.Current["Notice.Ok"];
        notice.ShowDialog();
    }

    /// <summary>
    /// Asks before something that cannot be undone. Cancel is the default
    /// button, so Enter pressed out of habit answers no.
    /// </summary>
    public static bool Confirm(string heading, string message, string confirm)
    {
        var notice = Build(message, NoticeKind.Warning);

        notice.Heading.Text = heading;
        notice.Heading.Visibility = Visibility.Visible;

        notice.CancelButton.Content = Strings.Current["Pin.Cancel"];
        notice.CancelButton.Visibility = Visibility.Visible;
        notice.CancelButton.IsDefault = true;

        // Danger, not the accent: the accent says "go on", and this is the
        // one button in the agent that takes a certificate off a card.
        notice.OkButton.Content = confirm;
        notice.OkButton.IsDefault = false;
        notice.OkButton.Style = (Style)notice.FindResource(typeof(Button));
        notice.OkButton.SetResourceReference(ForegroundProperty, "Danger");

        notice.Loaded += (_, _) => notice.CancelButton.Focus();

        return notice.ShowDialog() == true;
    }

    private static NoticeWindow Build(string message, NoticeKind kind)
    {
        var notice = new NoticeWindow { Title = Strings.Current["App.Name"] };
        notice.Body.Text = message;

        var (glyph, colour) = kind switch
        {
            NoticeKind.Success => ("\uE73E", "Managed"),
            NoticeKind.Warning => ("\uE7BA", "Warning"),
            _ => ("\uE946", "AccentText"),
        };

        notice.Mark.Text = glyph;
        notice.Mark.SetResourceReference(TextBlock.ForegroundProperty, colour);
        notice.Ring.SetResourceReference(Border.BorderBrushProperty, colour);

        // Over whatever the person is looking at, or centred on the screen
        // when nothing of ours is - the tray can raise one with no window open.
        var owner = Application.Current?.Windows.OfType<Window>()
            .FirstOrDefault(window => window.IsActive && window != notice);

        if (owner is not null)
        {
            notice.Owner = owner;
        }
        else
        {
            notice.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        return notice;
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}

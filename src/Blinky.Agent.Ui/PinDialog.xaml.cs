using System.Threading.Tasks;
using System.Windows;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// One layout for changing a PIN and for unblocking one.
/// </summary>
/// <remarks>
/// <para>
/// They differ in a single field — the current PIN, or the PUK — so they are
/// one window with one label that changes. Two windows would be two places to
/// get the confirmation logic subtly different.
/// </para>
/// <para>
/// The new PIN is asked for twice, and that is not ceremony. A mistyped PIN
/// that the card accepts is a token nobody can open and nothing can diagnose:
/// the card is perfectly happy, and the failure surfaces hours later looking
/// like a forgotten PIN. Two boxes and a comparison remove the whole failure
/// mode for nothing.
/// </para>
/// </remarks>
public partial class PinDialog : Window
{
    private readonly RequestClient client;
    private readonly long serial;
    private readonly bool unblocking;
    private readonly PinComplexityPolicy policy;

    public PinDialog(RequestClient client, long serial, bool unblocking,
        PinComplexityPolicy policy)
    {
        InitializeComponent();

        this.client = client;
        this.serial = serial;
        this.unblocking = unblocking;
        this.policy = policy;

        Title = Strings.Current[unblocking ? "Pin.UnblockTitle" : "Pin.ChangeTitle"];
        TitleText.Text = Title;
        FirstLabel.Text = Strings.Current[unblocking ? "Pin.Puk" : "Pin.Current"];

        Loaded += (_, _) => FirstBox.Focus();
    }

    /// <summary>
    /// Runs while somebody types, and never sends anything anywhere.
    /// </summary>
    /// <remarks>
    /// The mismatch is checked first. Telling somebody their PIN is too simple
    /// when what they actually did was mistype the confirmation sends them off
    /// to invent a new PIN for no reason.
    /// </remarks>
    private void Validate(object sender, RoutedEventArgs e)
    {
        var pin = NewBox.Password;
        var repeat = RepeatBox.Password;

        if (repeat.Length > 0 && pin != repeat)
        {
            Refuse(Strings.Current["Pin.Mismatch"]);
            return;
        }

        var verdict = PinRules.Check(pin, policy, serial);

        // Only once there is enough typed to judge: complaining "too short"
        // after the first keystroke is noise, and people learn to ignore the
        // line that is always red.
        if (pin.Length >= policy.MinimumLength && !verdict.IsAcceptable)
        {
            Refuse(verdict.Explanation);
            return;
        }

        MessageText.Text = string.Empty;
        OkButton.IsEnabled = pin.Length >= policy.MinimumLength && pin == repeat;
    }

    private void Refuse(string message)
    {
        MessageText.Text = message;
        OkButton.IsEnabled = false;
    }

    private async void Ok_Click(object sender, RoutedEventArgs e) => await SubmitAsync();

    private async Task SubmitAsync()
    {
        var first = FirstBox.Password;
        var pin = NewBox.Password;

        if (pin != RepeatBox.Password)
        {
            Refuse(Strings.Current["Pin.Mismatch"]);
            return;
        }

        OkButton.IsEnabled = false;
        MessageText.Foreground = System.Windows.Media.Brushes.Gray;
        MessageText.Text = Strings.Current["Pin.Working"];

        var request = new AgentRequest(
            unblocking ? AgentRequest.UnblockPin : AgentRequest.ChangePin, serial);

        var secrets = unblocking
            ? new AgentSecrets(Puk: first, NewPin: pin)
            : new AgentSecrets(CurrentPin: first, NewPin: pin);

        var response = await client.SendAsync(request, secrets);

        // Cleared as soon as the call returns. The boxes are the only place
        // these values existed in this process, and there is no reason for
        // them to outlive the request.
        FirstBox.Clear();
        NewBox.Clear();
        RepeatBox.Clear();

        MessageText.Foreground = System.Windows.Media.Brushes.Firebrick;

        if (response.Succeeded)
        {
            MessageBox.Show(
                Strings.Current[unblocking ? "Pin.Unblocked" : "Pin.Changed"],
                Strings.Current["App.Name"], MessageBoxButton.OK, MessageBoxImage.Information);

            DialogResult = true;
            return;
        }

        // The attempt count is the difference between "try again" and "one more
        // and this token is blocked", so it goes on the screen whenever the
        // card gave us one.
        var attempts = response.AttemptsRemaining is { } left
            ? " " + string.Format(Strings.Current["Pin.AttemptsLeft"], left)
            : string.Empty;

        MessageText.Text = response.Error + attempts;
        OkButton.IsEnabled = true;
        FirstBox.Focus();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

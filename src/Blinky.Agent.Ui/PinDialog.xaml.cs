using System.Globalization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>Which of the three the dialog is doing.</summary>
public enum PinDialogKind
{
    ChangePin,
    ChangePuk,
    Unblock,
}

/// <summary>
/// One layout for changing a PIN, changing a PUK, and unblocking.
/// </summary>
/// <remarks>
/// <para>
/// They differ in a single field — the current PIN, the current PUK, or the PUK
/// used to unblock — so they are one window with labels that move. Three
/// windows would be three places to get the confirmation logic subtly
/// different.
/// </para>
/// <para>
/// The new value is asked for twice, and that is not ceremony. A mistyped PIN
/// that the card accepts is a token nobody can open and nothing can diagnose:
/// the card is perfectly content, and the failure arrives hours later looking
/// like a forgotten PIN.
/// </para>
/// </remarks>
public partial class PinDialog : Window
{
    /// <summary>
    /// What PIV tokens leave the factory with. Public knowledge, printed in
    /// every vendor's documentation — which is exactly why a card still holding
    /// them is worth a warning.
    /// </summary>
    private const string FactoryPin = "123456";
    private const string FactoryPuk = "12345678";

    private readonly RequestClient client;
    private readonly TokenView token;
    private readonly PinDialogKind kind;
    private readonly PinComplexityPolicy policy;

    public PinDialog(RequestClient client, TokenView token, PinDialogKind kind,
        PinComplexityPolicy policy)
    {
        InitializeComponent();

        this.client = client;
        this.token = token;
        this.kind = kind;
        this.policy = policy;

        var strings = Strings.Current;

        Title = strings[kind switch
        {
            PinDialogKind.ChangePuk => "Puk.ChangeTitle",
            PinDialogKind.Unblock => "Pin.UnblockTitle",
            _ => "Pin.ChangeTitle",
        }];

        TitleText.Text = Title;
        RulesText.Text = strings["Pin.Rules"] + " " + strings["Pin.RulesCaveat"];

        FirstLabel.Text = strings[kind switch
        {
            PinDialogKind.ChangePuk => "Puk.Current",
            PinDialogKind.Unblock => "Pin.Puk",
            _ => "Pin.Current",
        }];

        var changingPuk = kind == PinDialogKind.ChangePuk;
        NewLabel.Text = strings[changingPuk ? "Puk.New" : "Pin.New"];
        RepeatLabel.Text = strings[changingPuk ? "Puk.Repeat" : "Pin.Repeat"];

        Prefill();

        Loaded += (_, _) =>
        {
            // Focus goes to the first empty box. Landing in a field that is
            // already filled in means the first keystroke silently replaces it.
            if (FirstBox.Password.Length > 0)
            {
                NewBox.Focus();
            }
            else
            {
                FirstBox.Focus();
            }
        };
    }

    /// <summary>
    /// Fills the current value in when the card says it is still the factory
    /// one.
    /// </summary>
    /// <remarks>
    /// Only when the card itself reports it. This is not a guess and not a
    /// fallback: <c>GET METADATA</c> answers whether the value is default, and
    /// where it says yes the value is published in the vendor's documentation
    /// and protects nothing. Making somebody type a number off a web page to
    /// get past a screen whose whole purpose is replacing it helps nobody.
    /// <para>
    /// Where the card does not say, or says no, the field stays empty. A
    /// prefilled wrong value would spend a card attempt on the first click.
    /// </para>
    /// </remarks>
    private void Prefill()
    {
        var prefilled = kind switch
        {
            PinDialogKind.ChangePin when token.PinIsDefault => FactoryPin,
            PinDialogKind.ChangePuk when token.PukIsDefault => FactoryPuk,
            PinDialogKind.Unblock when token.PukIsDefault => FactoryPuk,
            _ => null,
        };

        if (prefilled is null)
        {
            return;
        }

        FirstBox.Password = prefilled;

        MessageText.Foreground = (Brush?)TryFindResource("TextMuted") ?? Brushes.Gray;
        MessageText.Text = Strings.Current["Default.Prefilled"];
    }

    /// <summary>
    /// Runs while somebody types, and sends nothing anywhere.
    /// </summary>
    /// <remarks>
    /// The mismatch is tested first. Telling somebody their PIN is too simple
    /// when what they actually did was mistype the confirmation sends them off
    /// to invent a new one for no reason.
    /// </remarks>
    private void Validate(object sender, RoutedEventArgs e)
    {
        var value = NewBox.Password;
        var repeat = RepeatBox.Password;

        if (repeat.Length > 0 && value != repeat)
        {
            Refuse(Strings.Current["Pin.Mismatch"]);
            return;
        }

        var verdict = PinRules.Check(value, policy, token.Serial);

        // Only once there is enough typed to judge. Complaining "too short"
        // after one keystroke is noise, and a line that is always red is a line
        // people stop reading.
        if (value.Length >= policy.MinimumLength && !verdict.IsAcceptable)
        {
            Refuse(verdict.Explanation);
            return;
        }

        MessageText.Text = string.Empty;
        OkButton.IsEnabled = value.Length >= policy.MinimumLength && value == repeat;
    }

    private void Refuse(string message)
    {
        MessageText.Foreground = (Brush?)TryFindResource("Danger") ?? Brushes.Firebrick;
        MessageText.Text = message;
        OkButton.IsEnabled = false;
    }

    private async void Ok_Click(object sender, RoutedEventArgs e) => await SubmitAsync();

    private async Task SubmitAsync()
    {
        var first = FirstBox.Password;
        var value = NewBox.Password;

        if (value != RepeatBox.Password)
        {
            Refuse(Strings.Current["Pin.Mismatch"]);
            return;
        }

        OkButton.IsEnabled = false;
        MessageText.Foreground = (Brush?)TryFindResource("TextMuted") ?? Brushes.Gray;
        MessageText.Text = Strings.Current["Pin.Working"];

        var (op, secrets) = kind switch
        {
            PinDialogKind.ChangePuk => (AgentRequest.ChangePuk,
                new AgentSecrets(CurrentPin: first, NewPin: value)),

            PinDialogKind.Unblock => (AgentRequest.UnblockPin,
                new AgentSecrets(Puk: first, NewPin: value)),

            _ => (AgentRequest.ChangePin, new AgentSecrets(CurrentPin: first, NewPin: value)),
        };

        var response = await client.SendAsync(new AgentRequest(op, token.Serial), secrets);

        // Cleared the moment the call returns. These boxes were the only place
        // the values existed in this process and there is no reason for them to
        // outlive the request.
        FirstBox.Clear();
        NewBox.Clear();
        RepeatBox.Clear();

        if (response.Succeeded)
        {
            MessageBox.Show(
                Strings.Current[kind switch
                {
                    PinDialogKind.ChangePuk => "Puk.Changed",
                    PinDialogKind.Unblock => "Pin.Unblocked",
                    _ => "Pin.Changed",
                }],
                Strings.Current["App.Name"], MessageBoxButton.OK, MessageBoxImage.Information);

            DialogResult = true;
            return;
        }

        // The attempt count is the difference between "try again" and "one more
        // and this token is blocked", so it goes on screen whenever the card
        // gave us one.
        var attempts = response.AttemptsRemaining is { } left
            ? " " + string.Format(CultureInfo.CurrentCulture,
                Strings.Current["Pin.AttemptsLeft"], left)
            : string.Empty;

        Refuse(response.Error + attempts);
        OkButton.IsEnabled = true;
        FirstBox.Focus();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

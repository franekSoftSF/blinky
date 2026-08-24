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

    /// <summary>
    /// Sets a new PIN on a blocked token.
    /// </summary>
    /// <remarks>
    /// Asks for the new PIN and nothing else. The PUK is fetched, spent and
    /// replaced by the service without ever reaching this process — see
    /// <c>PukUnblock</c> and docs/10-agent-ui.md.
    /// </remarks>
    Unblock,

    /// <summary>
    /// Unblocking from a machine with no network, over a telephone.
    /// </summary>
    /// <remarks>
    /// The dialog shows a challenge to read out and takes the code an operator
    /// reads back. The replacement PUK is worked out from those two things on
    /// both sides, so nothing has to travel afterwards.
    /// </remarks>
    UnblockOffline,
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

    private readonly RequestClient client;
    private readonly TokenView token;
    private readonly PinDialogKind kind;
    private readonly PinComplexityPolicy policy;

    /// <summary>The code being read down a telephone, and half the derivation.</summary>
    private string challenge = string.Empty;

    public PinDialog(RequestClient client, TokenView token, PinDialogKind kind,
        PinComplexityPolicy policy)
    {
        InitializeComponent();

        this.client = client;
        this.token = token;
        this.kind = kind;
        this.policy = policy;

        var strings = Strings.Current;

        var offline = kind == PinDialogKind.UnblockOffline;
        var unblocking = kind == PinDialogKind.Unblock;

        Title = strings[offline ? "Pin.OfflineTitle"
            : unblocking ? "Pin.UnblockTitle"
            : "Pin.ChangeTitle"];

        TitleText.Text = Title;

        RulesText.Text = (offline ? strings["Pin.OfflineExplained"] + "  "
                             : unblocking ? strings["Pin.UnblockExplained"] + "  "
                             : string.Empty)
                         + strings["Pin.Rules"] + " " + strings["Pin.RulesCaveat"];

        // An online unblock asks for one thing: the new PIN. There is nothing
        // for the person to supply, because the PUK is not theirs to know.
        // Offline there is one thing - the code somebody read back.
        FirstLabel.Visibility = unblocking ? Visibility.Collapsed : Visibility.Visible;
        FirstBox.Visibility = unblocking || offline ? Visibility.Collapsed : Visibility.Visible;
        CodeBox.Visibility = offline ? Visibility.Visible : Visibility.Collapsed;

        ChallengePanel.Visibility = offline ? Visibility.Visible : Visibility.Collapsed;
        ChallengeLabel.Text = strings["Pin.ChallengeLabel"];

        FirstLabel.Text = strings[offline ? "Pin.OfflineCode" : "Pin.Current"];
        NewLabel.Text = strings["Pin.New"];
        RepeatLabel.Text = strings["Pin.Repeat"];

        Prefill();

        if (offline)
        {
            // Asked for as the window opens rather than when the person is
            // ready: it costs nothing, touches no card, and having the code
            // already on screen is the difference between a call that starts
            // and one that waits.
            Loaded += async (_, _) => await ShowChallengeAsync();
        }

        Loaded += (_, _) =>
        {
            // Focus goes to the first box a person has to fill. Landing in a
            // field that is already filled in means the first keystroke
            // silently replaces it.
            if (offline)
            {
                CodeBox.Focus();
            }
            else if (unblocking || FirstBox.Password.Length > 0)
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
        var prefilled = kind == PinDialogKind.ChangePin && token.PinIsDefault
            ? FactoryPin
            : null;

        if (prefilled is null)
        {
            return;
        }

        FirstBox.Password = prefilled;

        MessageText.Foreground = (Brush?)TryFindResource("TextMuted") ?? Brushes.Gray;
        MessageText.Text = Strings.Current["Default.Prefilled"];
    }

    /// <summary>
    /// Asks the service for a code to read out.
    /// </summary>
    /// <remarks>
    /// Kept here for the life of the dialog because the replacement PUK is
    /// derived from it: a second challenge would derive a different value and
    /// the card would end up holding one the server never recorded.
    /// </remarks>
    private async Task ShowChallengeAsync()
    {
        var answer = await client.SendAsync(
            new AgentRequest(AgentRequest.OfflineChallenge, token.Serial));

        if (answer is { Succeeded: true, Challenge: { Length: > 0 } code })
        {
            challenge = code;
            ChallengeText.Text = code;
            return;
        }

        ChallengeText.Text = "—";
        Refuse(answer.Error ?? Strings.Current["Error.NoService"]);
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

        var codeReady = kind != PinDialogKind.UnblockOffline || CodeBox.Text.Length > 0;

        OkButton.IsEnabled = value.Length >= policy.MinimumLength && value == repeat && codeReady;
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

        var request = kind switch
        {
            PinDialogKind.UnblockOffline =>
                new AgentRequest(AgentRequest.UnblockOffline, token.Serial, challenge),

            PinDialogKind.Unblock => new AgentRequest(AgentRequest.UnblockPin, token.Serial),

            _ => new AgentRequest(AgentRequest.ChangePin, token.Serial),
        };

        var secrets = kind switch
        {
            PinDialogKind.UnblockOffline =>
                new AgentSecrets(NewPin: value, OfflineResponse: CodeBox.Text),

            PinDialogKind.Unblock => new AgentSecrets(NewPin: value),

            _ => new AgentSecrets(CurrentPin: first, NewPin: value),
        };

        var response = await client.SendAsync(request, secrets);

        // Cleared the moment the call returns. These boxes were the only place
        // the values existed in this process and there is no reason for them to
        // outlive the request.
        FirstBox.Clear();
        NewBox.Clear();
        RepeatBox.Clear();
        CodeBox.Clear();

        if (response.Succeeded)
        {
            MessageBox.Show(
                Strings.Current[kind == PinDialogKind.ChangePin ? "Pin.Changed" : "Pin.Unblocked"],
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

    /// <summary>
    /// Lays the code out as it is typed, so the separators are there rather
    /// than being something to remember.
    /// </summary>
    /// <remarks>
    /// Typing the dashes by hand works - the decoder discards punctuation, and
    /// resolves I, L and O the same way this does - but a field that looks like
    /// it wants them invites somebody to type them, and every character typed
    /// is one that can go in wrong. This is a code being read aloud from one
    /// screen to another; the fewer keystrokes it needs, the fewer chances
    /// there are to mishear a letter.
    ///
    /// The caret goes to the end. Editing the middle of a transcribed code is
    /// not a thing anybody does - it is retyped - and keeping the caret in
    /// place across a reformat costs more than it is worth here.
    /// </remarks>
    private void CodeBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        var formatted = Blinky.Contracts.TransferCode.Format(CodeBox.Text);

        if (formatted == CodeBox.Text)
        {
            return;
        }

        CodeBox.TextChanged -= CodeBox_TextChanged;
        CodeBox.Text = formatted;
        CodeBox.CaretIndex = formatted.Length;
        CodeBox.TextChanged += CodeBox_TextChanged;
    }


    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

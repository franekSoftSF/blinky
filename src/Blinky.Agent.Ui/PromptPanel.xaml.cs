using System;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// Shows one prompt and returns the answer. The window around it decides
/// where it appears; this decides what it says and what it accepts.
/// </summary>
/// <remarks>
/// A PIN typed here goes down the pipe and is cleared from the box. It is never
/// written anywhere, and the box is a <c>PasswordBox</c> rather than a
/// <c>TextBox</c> so that it is not in the visual tree as text either.
/// </remarks>
public partial class PromptPanel : UserControl
{
    private TaskCompletionSource<PromptResponse>? pending;

    // PIV's six to eight unless the service says otherwise: a FIDO2 PIN is
    // four to 63, and the box once refused its ninth character.
    private int minLength = 6;
    private int maxLength = 8;

    public PromptPanel()
    {
        InitializeComponent();
    }

    /// <summary>Raised when the prompt was answered or cancelled, so the window can step back.</summary>
    public event Action? Finished;

    /// <summary>A provisional FIDO2 PIN is showing: closed only by saying it was written down.</summary>
    public bool MustAcknowledge { get; private set; }

    /// <summary>
    /// Inside the issuance window a touch or a finger needs no button - the
    /// window stays, and the step list says what is happening. Alone, the
    /// small window offers Close, as it always has.
    /// </summary>
    public bool InsideJob { get; set; }

    public Task<PromptResponse> ShowAsync(PromptRequest request)
    {
        // A prompt arriving over one still on screen answers the old one: the
        // service has stopped waiting for it, or it would not have sent this.
        pending?.TrySetResult(PromptResponse.Cancel());

        var answer = new TaskCompletionSource<PromptResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        pending = answer;

        TitleText.Text = request.Title;
        MessageText.Text = request.Message;

        // Inside the issuance window the step above already names what is
        // asked, in the station's language; the service's own heading would say
        // it twice, the second time in English.
        TitleText.Visibility = InsideJob ? Visibility.Collapsed : Visibility.Visible;

        var wantsPin = request.Type == PromptRequest.Pin;
        var fido2 = request.Applet == PromptRequest.Fido2;
        var information = request.Type is PromptRequest.Touch or PromptRequest.Fingerprint;

        MustAcknowledge = fido2 && request.Type == PromptRequest.Notice;

        minLength = request.MinLength ?? 6;
        maxLength = request.MaxLength ?? 8;

        PinBox.Password = string.Empty;
        PinBox.MaxLength = maxLength;
        PinBox.Visibility = wantsPin ? Visibility.Visible : Visibility.Collapsed;
        OkButton.Visibility = wantsPin ? Visibility.Visible : Visibility.Collapsed;
        Buttons.Visibility = information && InsideJob ? Visibility.Collapsed : Visibility.Visible;

        CancelButton.Content = Strings.Current[
            wantsPin ? "Pin.Cancel" : MustAcknowledge ? "Prompt.WrittenDown" : "Tokens.Close"];

        // Escape is a cancel, and a provisional PIN must not go away on one.
        CancelButton.IsCancel = !MustAcknowledge;

        // Nothing is unlocked by a FIDO2 PIN: it lets a passkey be made. Nor
        // by the PIN an enrolment asks for: it confirms the step.
        OkButton.Content = Strings.Current[fido2 ? "Prompt.Continue" : InsideJob ? "Pin.Ok" : "Prompt.Unlock"];

        // On a fingerprint prompt the count is worth showing from the start
        // rather than at two: three is all there is, and a Bio has no PUK -
        // once biometrics block, the PIN is the only way in.
        AttemptsText.Text = request.AttemptsRemaining switch
        {
            { } left when request.Type == PromptRequest.Fingerprint =>
                string.Format(CultureInfo.CurrentCulture,
                    Strings.Current["Prompt.FingerprintAttempts"], left),

            { } left when left <= 2 =>
                string.Format(CultureInfo.CurrentCulture,
                    Strings.Current["Prompt.PinAttempts"], left),

            _ => string.Empty,
        };

        // A touch or fingerprint prompt is information, not a question: the
        // card is what is being waited on, and the service takes it down when
        // it answers. Leaving these pending would hold the pipe open waiting
        // for a click nobody is going to make.
        if (information)
        {
            answer.TrySetResult(PromptResponse.Cancel());
        }

        return answer.Task;
    }

    public void FocusPin()
    {
        if (PinBox.Visibility == Visibility.Visible)
        {
            PinBox.Focus();
        }
    }

    /// <summary>Gives up on whatever is showing, as Cancel would.</summary>
    public void Cancel()
    {
        pending?.TrySetResult(PromptResponse.Cancel());
        Finish();
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => Answer();

    private void Cancel_Click(object sender, RoutedEventArgs e) => Cancel();

    private void PinBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            Answer();
        }
    }

    private void Answer()
    {
        var pin = PinBox.Password;

        if (pin.Length < minLength || pin.Length > maxLength)
        {
            // Refused here rather than on the card: a short PIN sent to the
            // token would still cost an attempt.
            AttemptsText.Text = string.Format(CultureInfo.CurrentCulture,
                Strings.Current["Prompt.PinLength"], minLength, maxLength);
            return;
        }

        pending?.TrySetResult(PromptResponse.WithPin(pin));
        Finish();
    }

    private void Finish()
    {
        PinBox.Password = string.Empty;
        pending = null;
        MustAcknowledge = false;
        Finished?.Invoke();
    }
}

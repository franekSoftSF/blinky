using System;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// The one window this process has. Hidden until the service asks for
/// something, and hidden again the moment it has an answer.
/// </summary>
/// <remarks>
/// A PIN typed here goes down the pipe and is cleared from the box. It is never
/// written anywhere, and the box is a <c>PasswordBox</c> rather than a
/// <c>TextBox</c> so that it is not in the visual tree as text either.
/// </remarks>
public partial class MainWindow : Window
{
    private TaskCompletionSource<PromptResponse>? pending;

    public MainWindow()
    {
        InitializeComponent();
    }

    /// <summary>Shows a prompt and waits for the user to answer it.</summary>
    public Task<PromptResponse> ShowPromptAsync(PromptRequest request)
    {
        var answer = new TaskCompletionSource<PromptResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        pending = answer;

        Dispatcher.Invoke(() =>
        {
            TitleText.Text = request.Title;
            MessageText.Text = request.Message;

            var wantsPin = request.Type == PromptRequest.Pin;

            PinBox.Password = string.Empty;
            PinBox.Visibility = wantsPin ? Visibility.Visible : Visibility.Collapsed;
            OkButton.Visibility = wantsPin ? Visibility.Visible : Visibility.Collapsed;
            CancelButton.Content = wantsPin ? "Cancel" : "Close";

            // On a fingerprint prompt the count is worth showing from the
            // start rather than at two: three is all there is, and a Bio has no
            // PUK - once biometrics block, the PIN is the only way in.
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

            Show();
            Activate();
            Topmost = true;
            PinBox.Focus();
        });

        // A touch or fingerprint prompt is information, not a question: the
        // card is what is being waited on, and the service takes the window
        // down when it answers. Leaving these pending would hold the pipe open
        // waiting for a click nobody is going to make.
        if (request.Type is PromptRequest.Touch or PromptRequest.Fingerprint)
        {
            answer.TrySetResult(PromptResponse.Cancel());
        }

        return answer.Task;
    }

    /// <summary>Takes the window down, whatever it was showing.</summary>
    public void Dismiss() => Dispatcher.Invoke(Hide);

    private void Ok_Click(object sender, RoutedEventArgs e) => Answer();

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        pending?.TrySetResult(PromptResponse.Cancel());
        Finish();
    }

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

        if (pin.Length is < 6 or > 8)
        {
            // Refused here rather than on the card: a short PIN sent to the
            // token would still cost an attempt.
            AttemptsText.Text = "A PIN is between six and eight characters";
            return;
        }

        pending?.TrySetResult(PromptResponse.WithPin(pin));
        Finish();
    }

    private void Finish()
    {
        PinBox.Password = string.Empty;
        pending = null;
        Hide();
    }
}

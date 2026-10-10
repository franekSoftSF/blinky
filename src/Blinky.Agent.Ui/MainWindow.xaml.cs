using System.Threading.Tasks;
using System.Windows;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// The small window for a prompt outside any job. Hidden until the service
/// asks for something, and hidden again the moment it has an answer.
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        Prompt.Finished += Hide;

        // Hidden, never closed. A window closed with the X is gone for good, and
        // the next prompt the service sent - the PIN at the next sign-in - threw
        // on Show() and never appeared, until somebody restarted the tray.
        Closing += (_, e) =>
        {
            e.Cancel = true;

            if (!Prompt.MustAcknowledge)
            {
                Prompt.Cancel();
            }
        };
    }

    /// <summary>Shows a prompt and waits for the user to answer it.</summary>
    public Task<PromptResponse> ShowPromptAsync(PromptRequest request) =>
        Dispatcher.Invoke(() =>
        {
            var answer = Prompt.ShowAsync(request);

            Show();
            Activate();
            Topmost = true;
            Prompt.FocusPin();

            return answer;
        });

    /// <summary>Takes the window down, whatever it was showing.</summary>
    public void Dismiss() => Dispatcher.Invoke(Hide);
}

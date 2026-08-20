using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// Runs in the user's session, waiting for the service to ask for something.
/// </summary>
/// <remarks>
/// <para>
/// Starts with no window on screen. The service in session 0 cannot draw one,
/// and this process cannot hold the reader — that split is the reason both
/// exist, and this end of it is deliberately almost empty.
/// </para>
/// <para>
/// <c>--prompt-once</c> shows one prompt and exits, which is how the pipe gets
/// tested without a service running.
/// </para>
/// </remarks>
public partial class App : Application
{
    private readonly CancellationTokenSource stopping = new();

    private MainWindow? window;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        window = new MainWindow();

        Trace($"started with {e.Args.Length} args: {string.Join(" ", e.Args)}");

        if (Array.Exists(e.Args, a => a == "--prompt-once"))
        {
            Trace("self test requested");

            // Deferred until the message loop is pumping. Showing a window
            // from OnStartup runs before Application.Run(), and the window
            // never acquires a handle - the process sits there alive with
            // nothing on screen, which is a miserable thing to diagnose.
            Dispatcher.InvokeAsync(RunOnce, DispatcherPriority.ApplicationIdle);
            return;
        }

        Trace("waiting for the service on the pipe");

        var client = new PromptClient(request => window.ShowPromptAsync(request));

        _ = client.RunAsync(stopping.Token);
    }

    /// <summary>Shows one PIN prompt locally, prints the outcome, and exits.</summary>
    private async void RunOnce()
    {
        Trace("showing the prompt");

        Trace($"window handle before showing: {new System.Windows.Interop.WindowInteropHelper(window!).Handle}");

        var response = await window!.ShowPromptAsync(
            PromptRequest.ForPin(29177301, 3, "Self test - nothing is sent anywhere."));

        MessageBox.Show(
            response.Cancelled
                ? "Cancelled."
                : $"A PIN of {response.Pin!.Length} characters was entered and discarded.",
            "Blinky self test");

        Shutdown();
    }

    /// <summary>
    /// A window-less process has nowhere to print. Diagnosing why nothing
    /// appeared needs somewhere to look, and this is it.
    /// </summary>
    private static void Trace(string message)
    {
        try
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "blinky-agent-ui.log");

            System.IO.File.AppendAllText(path,
                $"{DateTime.Now:HH:mm:ss} {message}{System.Environment.NewLine}");
        }
        catch
        {
            // Diagnostics must never be the reason something fails.
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        stopping.Cancel();
        base.OnExit(e);
    }
}

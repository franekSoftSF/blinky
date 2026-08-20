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
    private TokensWindow? tokens;
    private Tray? tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Before any window is constructed: a window built against an empty
        // resource dictionary resolves every DynamicResource to nothing and
        // comes up in system colours.
        Theme.Apply(ThemeChoice.System);

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

        // The tray is the half the person starts. The prompt pipe above is the
        // half that starts on them, and the two are deliberately independent:
        // a tray that failed to appear must not stop a PIN prompt arriving.
        tray = new Tray();
        tray.OpenRequested += ShowTokens;
        tray.ExitRequested += Shutdown;

        Trace("tray icon shown");
    }

    /// <summary>
    /// Shows the token list, reloading it every time. The window is kept rather
    /// than recreated so that its position survives being closed, but its
    /// contents never do — a token can leave the machine between two openings.
    /// </summary>
    private async void ShowTokens()
    {
        try
        {
            tokens ??= new TokensWindow();

            tokens.Show();
            tokens.Activate();

            await tokens.LoadAsync();
        }
        catch (Exception ex)
        {
            Trace($"the token window failed: {ex}");
        }
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
        tray?.Dispose();
        base.OnExit(e);
    }
}

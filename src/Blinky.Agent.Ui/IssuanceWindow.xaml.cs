using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// The window a job that needs the person runs in, from its start to its end
/// (0084a).
/// </summary>
/// <remarks>
/// <para>
/// Told, not asked: the service says the job started, which step it is on, and
/// how it ended, and the window draws that. The steps are marked as they are
/// reached rather than in a fixed order - a card already personalised skips
/// PersonaliseCard, and a key behind the PIN asks for it early - so a step the
/// service never mentioned is simply passed over.
/// </para>
/// <para>
/// Hidden, never closed, like the small prompt window: the next job opens the
/// same window again.
/// </para>
/// </remarks>
public partial class IssuanceWindow : Window
{
    private IReadOnlyList<string> steps = [];
    private JobContext? context;
    private int current = -1;
    private readonly HashSet<int> reached = [];

    public IssuanceWindow()
    {
        InitializeComponent();

        Prompt.Finished += () => PromptCard.Visibility = Visibility.Collapsed;

        Closing += (_, e) =>
        {
            e.Cancel = true;

            // The provisional PIN stays until somebody says it was written down.
            if (Prompt.MustAcknowledge)
            {
                return;
            }

            // A PIN request still open is answered as cancelled: the person
            // closed the window, which is a no, not a wait.
            if (PromptCard.Visibility == Visibility.Visible)
            {
                Prompt.Cancel();
            }

            Hide();
        };
    }

    /// <summary>True between a job's start and its end: prompts belong in here.</summary>
    public bool Active { get; private set; }

    public void Start(PromptRequest request) => Dispatcher.Invoke(() =>
    {
        Active = true;
        context = request.Job;
        steps = request.Steps ?? [];
        current = -1;
        failedAt = -1;
        reached.Clear();

        var strings = Strings.Current;

        OperationText.Text = strings[context?.Operation == JobContext.Passkey
            ? "Issue.TitlePasskey"
            : "Issue.TitleCard"];
        ContextText.Text = Describe(context);

        PromptCard.Visibility = Visibility.Collapsed;
        RunningPanel.Visibility = Visibility.Visible;
        EndPanel.Visibility = Visibility.Collapsed;

        StepTitle.Text = strings["Issue.Starting"];
        StepHint.Text = string.Empty;
        StepIcon.Text = string.Empty;

        Render();

        Show();
        Activate();
    });

    public void Step(string step) => Dispatcher.Invoke(() =>
    {
        var index = IndexOf(step);

        if (index < 0)
        {
            return;
        }

        reached.Add(index);
        current = index;

        StepTitle.Text = StepTitleOf(step);
        StepHint.Text = StepHintOf(step);
        StepIcon.Text = StepIconOf(step);

        Render();
    });

    public Task<PromptResponse> ShowPromptAsync(PromptRequest request) => Dispatcher.Invoke(() =>
    {
        // A touch is the step itself - the instruction above says what to do -
        // and a card repeating it, in the service's English, adds nothing.
        if (request.Type == PromptRequest.Touch)
        {
            Show();
            Activate();
            return Task.FromResult(PromptResponse.Cancel());
        }

        var answer = Prompt.ShowAsync(request);

        PromptCard.Visibility = Visibility.Visible;

        Show();
        Activate();
        Prompt.FocusPin();

        return answer;
    });

    /// <summary>
    /// The service took a prompt down - the card answered the touch. The step
    /// stays; only the prompt goes, and never a provisional PIN nobody has
    /// acknowledged yet.
    /// </summary>
    public void Dismiss() => Dispatcher.Invoke(() =>
    {
        if (!Prompt.MustAcknowledge)
        {
            PromptCard.Visibility = Visibility.Collapsed;
        }
    });

    public void End(PromptRequest request) => Dispatcher.Invoke(() =>
    {
        Active = false;

        var strings = Strings.Current;
        var succeeded = request.Succeeded == true;
        var passkey = context?.Operation == JobContext.Passkey;

        if (succeeded)
        {
            for (var i = 0; i < steps.Count; i++)
            {
                reached.Add(i);
            }

            current = -1;
        }
        else if (request.Step is { } failed && IndexOf(failed) is var at and >= 0)
        {
            current = at;
        }

        failedAt = succeeded ? -1 : current;
        Render();

        PromptCard.Visibility = Visibility.Collapsed;
        RunningPanel.Visibility = Visibility.Collapsed;
        EndPanel.Visibility = Visibility.Visible;

        var colour = succeeded ? "Managed" : "Danger";
        EndMark.Text = succeeded ? "\uE73E" : "\uE711";
        EndMark.SetResourceReference(ForegroundProperty, colour);
        EndRing.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, colour);

        EndTitle.Text = strings[succeeded ? "Issue.Done" : "Issue.Failed"];
        EndText.Text = succeeded
            ? strings[passkey ? "Issue.DonePasskey" : "Issue.DoneCard"]
            : failedAt >= 0
                ? string.Format(CultureInfo.CurrentCulture, strings["Issue.FailedAt"], StepTitleOf(steps[failedAt]))
                : strings["Issue.FailedNoStep"];

        // The sentence the service gave, as it gave it: it is what somebody
        // reads out to the help desk.
        EndDetail.Text = succeeded ? string.Empty : request.Message;

        Show();
        Activate();
    });

    private int failedAt = -1;

    private void Close_Click(object sender, RoutedEventArgs e) => Hide();

    private int IndexOf(string step)
    {
        for (var i = 0; i < steps.Count; i++)
        {
            if (string.Equals(steps[i], step, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Done is everything before the furthest step reached, and every step
    /// reached on the way; now is the last one named.
    /// </summary>
    private void Render()
    {
        var furthest = reached.Count == 0 ? -1 : reached.Max();
        var rows = new List<StepRow>();

        for (var i = 0; i < steps.Count; i++)
        {
            var state = i == failedAt && !Active ? StepState.Failed
                : i == current && Active ? StepState.Current
                : i < furthest || reached.Contains(i) ? StepState.Done
                : StepState.ToDo;

            rows.Add(StepRow.For(StepTitleOf(steps[i]), state));
        }

        StepList.ItemsSource = rows;

        var done = rows.Count(row => row.State == StepState.Done);
        Progress.Value = steps.Count == 0 ? 0 : (double)done / steps.Count;
    }

    private static string Describe(JobContext? job)
    {
        if (job is null)
        {
            return string.Empty;
        }

        var strings = Strings.Current;
        var parts = new List<string>();

        if (job.Holder is { Length: > 0 } holder)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, strings["Issue.For"],
                job.HolderUpn is { Length: > 0 } upn ? $"{holder} ({upn})" : holder));
        }

        if (job.Login is { Length: > 0 } login)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, strings["Issue.Account"], login, job.Provider));
        }

        if (job.Profile is { Length: > 0 } profile)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, strings["Issue.Profile"], profile));
        }

        if (job.RequestedBy is { Length: > 0 } operatorName)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, strings["Issue.RequestedBy"], operatorName));
        }

        return string.Join("  ·  ", parts);
    }

    private static string StepTitleOf(string step) => Strings.Current["Step." + step];

    private static string StepHintOf(string step) => Strings.Current["StepHint." + step];

    private static string StepIconOf(string step) => step switch
    {
        "ChoosePin" or "VerifyUser" or Fido2Steps.Pin => "\uE8D7",
        "PersonaliseCard" or Fido2Steps.MinPinLength or Fido2Steps.ForcePinChange => "\uE713",
        "GenerateKey" or "BuildAndSignCsr" => "\uE72E",
        "Attest" => "\uEA18",
        "SubmitToCa" or Fido2Steps.Challenge or Fido2Steps.Register => "\uE774",
        Fido2Steps.Touch => "\uE7C9",
        _ => "\uE8CC",
    };

    private enum StepState
    {
        ToDo,
        Current,
        Done,
        Failed,
    }

    /// <summary>One step as the list draws it, with its brushes resolved from the live theme.</summary>
    private sealed record StepRow(
        string Title,
        StepState State,
        string Mark,
        Brush RingFill,
        Brush RingBrush,
        Brush MarkBrush,
        Brush TextBrush,
        FontWeight Weight)
    {
        public static StepRow For(string title, StepState state) => state switch
        {
            StepState.Done => new(title, state, "\uE73E", Look("Panel"), Look("Managed"), Look("Managed"),
                Look("Text"), FontWeights.Normal),
            StepState.Current => new(title, state, "\uE768", Look("Background"), Look("Accent"), Look("AccentText"),
                Look("Text"), FontWeights.SemiBold),
            StepState.Failed => new(title, state, "\uE711", Look("Background"), Look("Danger"), Look("Danger"),
                Look("Danger"), FontWeights.SemiBold),
            _ => new(title, state, string.Empty, Look("Background"), Look("Divider"), Look("TextMuted"),
                Look("TextMuted"), FontWeights.Normal),
        };

        private static Brush Look(string key) =>
            Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }
}

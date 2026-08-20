using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// What is on the tokens in this machine, read fresh every time it is shown.
/// </summary>
/// <remarks>
/// Nothing is cached between openings. A token can leave the machine between
/// two glances at the same window, and a list that remembered what it last saw
/// would be confidently wrong at exactly that moment.
/// </remarks>
public partial class TokensWindow : Window
{
    private readonly RequestClient client = new();
    private PinComplexityPolicy policy = PinComplexityPolicy.Default;

    public TokensWindow()
    {
        InitializeComponent();

        Loaded += async (_, _) => await LoadAsync();
    }

    public async Task LoadAsync()
    {
        StatusText.Text = Strings.Current["Pin.Working"];

        // The policy comes from the service rather than being assumed here, so
        // that what the window explains and what the service enforces are the
        // same rules.
        var policyResponse = await client.SendAsync(new AgentRequest(AgentRequest.GetPinPolicy));
        if (policyResponse is { Succeeded: true, PinComplexityPolicy: { } published })
        {
            policy = published;
        }

        var response = await client.SendAsync(new AgentRequest(AgentRequest.ListTokens));

        StatusText.Text = string.Empty;

        if (!response.Succeeded)
        {
            Show(response.Error ?? Strings.Current["Error.NoService"]);
            return;
        }

        var tokens = response.Tokens ?? [];

        if (tokens.Count == 0)
        {
            Show(Strings.Current["Tokens.Empty"] + " " + Strings.Current["Tokens.EmptyHint"]);
            return;
        }

        EmptyText.Visibility = Visibility.Collapsed;
        TokenList.ItemsSource = tokens.Select(TokenRow.From).ToList();
    }

    private void Show(string message)
    {
        TokenList.ItemsSource = null;
        EmptyText.Text = message;
        EmptyText.Visibility = Visibility.Visible;
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private void Close_Click(object sender, RoutedEventArgs e) => Hide();

    private async void ChangePin_Click(object sender, RoutedEventArgs e) =>
        await OpenPinDialogAsync(sender, unblocking: false);

    private async void Unblock_Click(object sender, RoutedEventArgs e) =>
        await OpenPinDialogAsync(sender, unblocking: true);

    private async Task OpenPinDialogAsync(object sender, bool unblocking)
    {
        if (sender is not FrameworkElement { Tag: long serial })
        {
            return;
        }

        var dialog = new PinDialog(client, serial, unblocking, policy) { Owner = this };

        if (dialog.ShowDialog() == true)
        {
            // The attempt counter moved, so the list is out of date the moment
            // this returns.
            await LoadAsync();
        }
    }
}

/// <summary>One token, flattened into the strings the template draws.</summary>
/// <remarks>
/// Formatting here rather than in XAML converters: the sentences are
/// translated, and a converter would have to reach for the table anyway.
/// </remarks>
public sealed record TokenRow(
    long Serial,
    string Heading,
    string SubHeading,
    string Warning,
    Visibility WarningVisibility,
    bool HasPuk,
    IReadOnlyList<SlotRow> Slots)
{
    public static TokenRow From(TokenView token)
    {
        var strings = Strings.Current;

        var heading = $"{strings["Tokens.Serial"]} {token.Serial}";

        var parts = new string?[]
        {
            $"{strings["Tokens.Reader"]}: {token.ReaderName}",

            // Firmware and the attempt count are both absent on firmware too
            // old to be asked. Left out rather than shown as a blank label.
            token.FirmwareVersion is { } firmware
                ? $"{strings["Tokens.Firmware"]}: {firmware}"
                : null,
            token.PinAttemptsRemaining is { } attempts
                ? $"{strings["Tokens.PinAttempts"]}: {attempts}"
                : null,
        };

        var subHeading = string.Join("   ", parts.Where(part => part is not null));

        return new TokenRow(
            token.Serial,
            heading,
            subHeading,
            strings["Tokens.NoPuk"],

            // A token with no PUK is not an error to hide: it is the one fact
            // that decides whether a blocked PIN is recoverable, and the person
            // holding it should know before they block it.
            token.HasPuk ? Visibility.Collapsed : Visibility.Visible,
            token.HasPuk,
            [.. token.Slots.Select(SlotRow.From)]);
    }
}

/// <summary>One slot, in two lines.</summary>
public sealed record SlotRow(string SlotId, string Line1, string Line2)
{
    public static SlotRow From(SlotView slot)
    {
        var strings = Strings.Current;

        if (slot.Subject is null)
        {
            return new SlotRow(slot.SlotId,
                strings[slot.HasKeyWithoutCertificate
                    ? "Slot.KeyNoCertificate"
                    : "Slot.Empty"],
                string.Empty);
        }

        var expiry = slot.NotAfter is { } notAfter
            ? $"{strings["Slot.Expires"]}: "
              + notAfter.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
              + " " + Remaining(slot.DaysRemaining)
            : string.Empty;

        var issuer = slot.Issuer is { } signedBy
            ? $"{strings["Slot.Issuer"]}: {signedBy}    "
            : string.Empty;

        return new SlotRow(slot.SlotId, slot.Subject, issuer + expiry);
    }

    private static string Remaining(int? days) => days switch
    {
        null => string.Empty,
        < 0 => string.Format(CultureInfo.CurrentCulture,
            Strings.Current["Slot.Expired"], Math.Abs(days.Value)),
        _ => string.Format(CultureInfo.CurrentCulture,
            Strings.Current["Slot.ExpiresIn"], days.Value),
    };
}

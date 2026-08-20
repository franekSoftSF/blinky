using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// Devices on the left, what is in their slots in the middle, what can be done
/// about it on the right.
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
    private IReadOnlyList<TokenView> tokens = [];

    public TokensWindow()
    {
        InitializeComponent();

        Loaded += async (_, _) => await LoadAsync();
    }

    private TokenView? Selected => DeviceList.SelectedIndex >= 0
                                   && DeviceList.SelectedIndex < tokens.Count
        ? tokens[DeviceList.SelectedIndex]
        : null;

    public async Task LoadAsync()
    {
        StatusText.Text = Strings.Current["Pin.Working"];

        // From the service rather than assumed here, so that what this window
        // explains and what the service enforces are the same rules.
        var published = await client.SendAsync(new AgentRequest(AgentRequest.GetPinPolicy));
        if (published is { Succeeded: true, PinComplexityPolicy: { } rules })
        {
            policy = rules;
        }

        var remembered = Selected?.Serial;

        var response = await client.SendAsync(new AgentRequest(AgentRequest.ListTokens));

        StatusText.Text = string.Empty;

        if (!response.Succeeded)
        {
            ShowNothing(response.Error ?? Strings.Current["Error.NoService"]);
            return;
        }

        tokens = response.Tokens ?? [];

        if (tokens.Count == 0)
        {
            ShowNothing(Strings.Current["Tokens.Empty"] + " "
                        + Strings.Current["Tokens.EmptyHint"]);
            return;
        }

        DeviceList.ItemsSource = tokens.Select(DeviceRow.From).ToList();

        // The same device stays selected across a refresh where it can. A list
        // that jumped back to the first token after every PIN change would
        // move the thing somebody was looking at.
        var index = remembered is { } serial
            ? tokens.Select((token, i) => (token, i))
                .Where(pair => pair.token.Serial == serial)
                .Select(pair => pair.i)
                .DefaultIfEmpty(0)
                .First()
            : 0;

        DeviceList.SelectedIndex = index;
    }

    private void ShowNothing(string message)
    {
        tokens = [];
        DeviceList.ItemsSource = null;
        SlotList.ItemsSource = null;
        DefaultsBanner.Visibility = Visibility.Collapsed;
        ManagementPanel.Visibility = Visibility.Collapsed;

        HeaderText.Text = Strings.Current["Tokens.Title"];
        SubHeaderText.Text = string.Empty;
        EmptyText.Text = message;
        EmptyText.Visibility = Visibility.Visible;
    }

    private void Device_Changed(object sender, SelectionChangedEventArgs e) => ShowSelected();

    private void ShowSelected()
    {
        if (Selected is not { } token)
        {
            return;
        }

        EmptyText.Visibility = Visibility.Collapsed;
        ManagementPanel.Visibility = Visibility.Visible;

        HeaderText.Text = Strings.Current["Slots.Header"];
        SubHeaderText.Text = DeviceRow.Describe(token);

        SlotList.ItemsSource = token.Slots.Select(SlotRow.From).ToList();

        ShowDefaults(token);
        ShowManagement(token);
    }

    /// <summary>
    /// One banner for everything still at its factory value.
    /// </summary>
    /// <remarks>
    /// Two separate warnings for the PIN and the PUK would be two things to
    /// dismiss and the same single fact: nobody has personalised this token.
    /// <para>
    /// The management key is left out on purpose even when it is still at the
    /// factory value. It is an operator's secret, this window cannot change
    /// it, and a warning nobody reading it can act on is how people are taught
    /// to dismiss warnings.
    /// </para>
    /// </remarks>
    private void ShowDefaults(TokenView token)
    {
        var strings = Strings.Current;

        var atFactory = new List<string>();

        if (token.PinIsDefault)
        {
            atFactory.Add(strings["Default.Pin"]);
        }

        if (atFactory.Count == 0)
        {
            DefaultsBanner.Visibility = Visibility.Collapsed;
            return;
        }

        DefaultsText.Text = strings["Default.Banner"] + " " + string.Join(", ", atFactory) + ".";
        DefaultsBanner.Visibility = Visibility.Visible;
    }

    private void ShowManagement(TokenView token)
    {
        var strings = Strings.Current;

        PinStateText.Text = Attempts(token.PinAttemptsRemaining)
                            + (token.PinIsDefault ? "  •  " + strings["Default.Warning"] : string.Empty);

        // A token with no PUK is not a token with a PUK we cannot see. The Bio
        // has none by design, and offering an action that would certainly fail
        // teaches people that this window guesses.
        UnblockButton.IsEnabled = token.HasPuk;
        OfflineButton.IsEnabled = token.HasPuk;

        OfflineStateText.Text = token.HasPuk
            ? strings["Manage.OfflineHint"]
            : strings["Tokens.NoPuk"];

        UnblockStateText.Text = token.HasPuk
            ? strings["Manage.UnblockHint"]
            : strings["Tokens.NoPuk"];

    }

    private static string Attempts(int? remaining) => remaining is { } left
        ? string.Format(CultureInfo.CurrentCulture, Strings.Current["Pin.AttemptsLeft"], left)
        : Strings.Current["Manage.Unknown"];

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private async void ChangePin_Click(object sender, RoutedEventArgs e) =>
        await OpenAsync(PinDialogKind.ChangePin);

    private async void Unblock_Click(object sender, RoutedEventArgs e) =>
        await OpenAsync(PinDialogKind.Unblock);

    private async void UnblockOffline_Click(object sender, RoutedEventArgs e) =>
        await OpenAsync(PinDialogKind.UnblockOffline);

    private async Task OpenAsync(PinDialogKind kind)
    {
        if (Selected is not { } token)
        {
            return;
        }

        var dialog = new PinDialog(client, token, kind, policy) { Owner = this };

        if (dialog.ShowDialog() == true)
        {
            // The attempt counter moved and a default may no longer be one, so
            // everything on screen is out of date the moment this returns.
            await LoadAsync();
        }
    }
}

/// <summary>One device in the left column.</summary>
public sealed record DeviceRow(string Name, string Line2)
{
    public static DeviceRow From(TokenView token) =>
        new(Label(token), $"S/N: {token.Serial}"
                         + (token.FirmwareVersion is { } firmware ? $"  F/W: {firmware}" : string.Empty));

    /// <summary>
    /// What the card actually said, never a model name worked out from it.
    /// </summary>
    /// <remarks>
    /// The form factor comes from an attestation and is therefore absent on a
    /// token holding no key. Filling that gap by reading a model out of a
    /// firmware version would put a guess in the one line people read as the
    /// identity of the thing in their hand — the same mistake doc 08 records
    /// for the form-factor column.
    /// </remarks>
    private static string Label(TokenView token)
    {
        var strings = Strings.Current;

        var name = token.FormFactor is { Length: > 0 } form
            ? form
            : strings["Device.Generic"];

        if (token.FingerprintsEnrolled)
        {
            name += "  " + strings["Device.Biometric"];
        }

        return token.IsFipsDevice ? name + "  FIPS" : name;
    }

    public static string Describe(TokenView token)
    {
        var strings = Strings.Current;

        return $"{strings["Tokens.Reader"]}: {token.ReaderName}"
               + $"    {strings["Tokens.Serial"]}: {token.Serial}"
               + (token.FirmwareVersion is { } firmware
                   ? $"    {strings["Tokens.Firmware"]}: {firmware}"
                   : string.Empty);
    }
}

/// <summary>One slot, ready for the template.</summary>
public sealed record SlotRow(
    string SlotId,
    string SlotName,
    string Subject,
    string Detail,
    string BadgeText,
    Visibility BadgeVisibility,
    Brush BadgeBackground,
    Brush BadgeForeground)
{
    public static SlotRow From(SlotView slot)
    {
        var strings = Strings.Current;

        var name = strings[$"Slot.Name.{slot.SlotId.ToUpperInvariant()}"];

        var subject = slot.Subject
                      ?? strings[slot.HasKeyWithoutCertificate
                          ? "Slot.KeyNoCertificate"
                          : "Slot.Empty"];

        var detail = slot.Subject is null
            ? string.Empty
            : string.Join("    ", new[]
                {
                    slot.Issuer is { } issuer ? $"{strings["Slot.Issuer"]}: {issuer}" : null,
                    Expiry(slot),
                    slot.KeyAlgorithm,
                }
                .Where(part => !string.IsNullOrEmpty(part)));

        var (text, background, foreground) = Badge(slot.Management);

        return new SlotRow(slot.SlotId.ToLowerInvariant(), name, subject, detail,
            text,
            slot.Management == SlotManagement.Empty ? Visibility.Collapsed : Visibility.Visible,
            background, foreground);
    }

    /// <summary>
    /// Managed, unmanaged, or unknown — and unknown is shown rather than
    /// hidden. A blank badge would read as "fine".
    /// </summary>
    private static (string Text, Brush Background, Brush Foreground) Badge(SlotManagement state)
    {
        var strings = Strings.Current;

        return state switch
        {
            SlotManagement.Managed => (strings["Badge.Managed"],
                Look("ManagedSoft"), Look("Managed")),

            SlotManagement.Unmanaged => (strings["Badge.Unmanaged"],
                Look("WarningSoft"), Look("Warning")),

            _ => (strings["Badge.Unknown"], Look("PanelRaised"), Look("TextMuted")),
        };
    }

    /// <summary>
    /// Resolved from the live dictionary so a badge follows a theme switch.
    /// Falls back to grey rather than throwing if a key is ever missing.
    /// </summary>
    private static Brush Look(string key) =>
        Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;

    private static string? Expiry(SlotView slot)
    {
        if (slot.NotAfter is not { } notAfter)
        {
            return null;
        }

        var date = notAfter.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        var remaining = slot.DaysRemaining switch
        {
            null => string.Empty,
            < 0 => " " + string.Format(CultureInfo.CurrentCulture,
                Strings.Current["Slot.Expired"], Math.Abs(slot.DaysRemaining.Value)),
            var days => " " + string.Format(CultureInfo.CurrentCulture,
                Strings.Current["Slot.ExpiresIn"], days),
        };

        return $"{Strings.Current["Slot.Expires"]}: {date}{remaining}";
    }
}

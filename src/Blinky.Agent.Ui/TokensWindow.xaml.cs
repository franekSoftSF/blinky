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
        ShowBiometrics(token);
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

    /// <summary>
    /// The fingerprint situation, in words, on every token.
    /// </summary>
    /// <remarks>
    /// Including "this one has no sensor", which is the line that stops a
    /// person wondering why their other key behaves differently. A Bio with no
    /// finger enrolled previously showed nothing here at all, and nothing reads
    /// as an ordinary key rather than as a step somebody has not taken yet.
    /// </remarks>
    private void ShowBiometrics(TokenView token)
    {
        var strings = Strings.Current;

        BiometricText.Text = strings["Bio." + token.Biometrics];

        BiometricDetailText.Text = token.Biometrics switch
        {
            BiometricAvailability.Enrolled when token.BiometricAttemptsRemaining is { } left =>
                string.Format(CultureInfo.CurrentCulture, strings["Bio.Attempts"], left)
                + "  " + strings["Bio.AddMore"],

            BiometricAvailability.NotEnrolled or BiometricAvailability.Blocked =>
                strings["Bio.AddMore"],

            _ => string.Empty,
        };
    }

    private static string Attempts(int? remaining) => remaining is { } left
        ? string.Format(CultureInfo.CurrentCulture, Strings.Current["Pin.AttemptsLeft"], left)
        : Strings.Current["Manage.Unknown"];

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is { } token && sender is FrameworkElement { Tag: string slot })
        {
            await CertificateActions.ExportAsync(client, token.Serial, slot);
        }
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is { } token && sender is FrameworkElement { Tag: string slot })
        {
            await CertificateActions.InstallAsync(client, token.Serial, slot);
        }
    }

    /// <remarks>
    /// Asked before done, and the question names the slot and the token. This
    /// takes a working credential off somebody's key and there is no undo on
    /// the card: the private key survives, the certificate does not.
    /// </remarks>
    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } token || sender is not FrameworkElement { Tag: string slot })
        {
            return;
        }

        var confirm = MessageBox.Show(
            string.Format(CultureInfo.CurrentCulture, Strings.Current["Cert.DeleteConfirm"],
                slot.ToUpperInvariant(), token.Serial),
            Strings.Current["Cert.Delete"], MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        var response = await client.SendAsync(
            new AgentRequest(AgentRequest.DeleteCertificate, token.Serial, slot));

        if (!response.Succeeded)
        {
            MessageBox.Show(response.Error ?? Strings.Current["Error.NoService"],
                Strings.Current["App.Name"], MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        await LoadAsync();
    }

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
public sealed record DeviceRow(string Name, string Line2, Visibility ManagedVisibility)
{
    public static DeviceRow From(TokenView token) =>
        new(Label(token),
            $"S/N: {token.Serial}"
            + (token.FirmwareVersion is { } firmware ? $"  F/W: {firmware}" : string.Empty),

            // Shown when Blinky put something on this token, and absent
            // otherwise - including when the backend could not be asked. An
            // "unknown" badge belongs on a slot, where the question is about
            // one credential; on a device it would be a badge on every token
            // in the list every time the network hiccuped.
            token.Slots.Any(slot => slot.Management == SlotManagement.Managed)
                ? Visibility.Visible
                : Visibility.Collapsed);

    /// <summary>
    /// What the card actually said, and nothing worked out from it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "YubiKey" is a finding rather than an assumption: everything in this
    /// list answered <c>GET SERIAL</c>, a Yubico instruction that other
    /// vendors' PIV cards refuse with <c>6D00</c> — the agent drops a card
    /// with no serial from the inventory entirely. So a token that reached
    /// this window is one whose own applet identified its maker.
    /// </para>
    /// <para>
    /// The shape after it comes from the attestation and is therefore missing
    /// on a token holding no key, which is why the name degrades to plain
    /// "YubiKey" rather than to a model. A marketing name reconstructed from a
    /// firmware version — "YubiKey 5C NFC" from 5.7.1 — would be a guess in
    /// the one line people read as the identity of the thing in their hand,
    /// and doc 08 records that exact mistake once already.
    /// </para>
    /// </remarks>
    private static string Label(TokenView token)
    {
        var strings = Strings.Current;

        var name = strings["Device.YubiKey"];

        // The Bio says so through its biometric slot, which is a fact about
        // the applet rather than a form factor - and it is present whether or
        // not anybody has enrolled a finger.
        if (token.FingerprintsEnrolled)
        {
            return name + " " + strings["Device.Bio"];
        }

        if (token.FormFactor is { Length: > 0 } form)
        {
            var described = strings["Device.Form." + form];

            // The table above is by name, so an unrecognised form factor falls
            // through to the raw value rather than to nothing: a new one
            // should read oddly, not vanish.
            name += " " + (described == "Device.Form." + form ? form : described);
        }

        return token.IsFipsDevice ? name + " FIPS" : name;
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
    string Protection,
    Brush ProtectionColour,
    Visibility ActionsVisibility,
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
        var (protection, protectionColour) = Protects(slot);

        return new SlotRow(slot.SlotId.ToLowerInvariant(), name, subject, detail,

            // The protection line is worth showing wherever there is a key,
            // certificate or not: a bare key with no verification behind it is
            // the same hazard as a certified one.
            slot.PinPolicy is null ? string.Empty : protection,
            protectionColour,

            // Nothing to export, install or delete without a certificate.
            slot.Subject is null ? Visibility.Collapsed : Visibility.Visible,
            text,
            slot.Management == SlotManagement.Empty ? Visibility.Collapsed : Visibility.Visible,
            background, foreground);
    }

    /// <summary>
    /// What has to be proved before the private key will be used.
    /// </summary>
    /// <remarks>
    /// Shown because "nothing" is a possible answer and the worst one: a key
    /// with PIN policy Never signs for whoever is holding the token. Blinky
    /// refuses to generate one, but it does not put every key on every card —
    /// a slot filled by something else can be anything at all, and this is
    /// where that becomes visible instead of implied.
    /// </remarks>
    private static (string Text, Brush Colour) Protects(SlotView slot)
    {
        var strings = Strings.Current;

        return slot.PinPolicy switch
        {
            null => (string.Empty, Look("TextFaint")),

            "Never" => (strings["Slot.ProtectedByNothing"], Look("Danger")),

            "MatchOnce" or "MatchAlways" =>
                (strings["Slot.ProtectedByFingerprint"], Look("Managed")),

            var other => (string.Format(CultureInfo.CurrentCulture,
                strings["Slot.ProtectedByPin"], other), Look("TextFaint")),
        };
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

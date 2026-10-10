using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;

namespace Blinky.Agent.Ui;

/// <summary>
/// Everything the user reads, in Polish and English.
/// </summary>
/// <remarks>
/// <para>
/// A dictionary with an indexer rather than <c>.resx</c> and satellite
/// assemblies, for one reason that matters here: the language can change while
/// the window is open. Bindings go through the indexer, and raising
/// <see cref="Binding.IndexerName"/> re-reads every one of them. With resx the
/// choice is made when the process starts and testing the other language means
/// restarting — which is exactly what somebody checking the translations does
/// not want to do.
/// </para>
/// <para>
/// The cost is that this is not a file a translator can be handed. When a third
/// language appears, move to resx and keep this indexer as the lookup in front
/// of it; the XAML does not change.
/// </para>
/// </remarks>
public sealed class Strings : INotifyPropertyChanged
{
    public static Strings Current { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>The language in use: <c>pl</c> or <c>en</c>.</summary>
    public string Language { get; private set; } = Detect();

    public bool IsPolish => Language == "pl";

    /// <summary>
    /// Falls back to the key itself rather than throwing or returning empty. A
    /// missing translation should be a visibly wrong label, not a blank one:
    /// blank looks like a layout bug and gets reported as the wrong problem.
    /// </summary>
    public string this[string key] =>
        Table(Language).TryGetValue(key, out var value) ? value
        : English.TryGetValue(key, out var fallback) ? fallback
        : key;

    public void Use(string language)
    {
        if (Language == language)
        {
            return;
        }

        Language = language;

        // Binding.IndexerName is "Item[]", which tells WPF every indexed
        // binding is stale. Naming a single key would update one label.
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(Binding.IndexerName));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsPolish)));
    }

    /// <summary>Polish for a Polish machine, English for everything else.</summary>
    private static string Detect() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "pl" ? "pl" : "en";

    private static Dictionary<string, string> Table(string language) =>
        language == "pl" ? Polish : English;

    private static readonly Dictionary<string, string> English = new()
    {
        ["App.Name"] = "Blinky",
        ["Notice.Ok"] = "OK",
        ["Tray.Open"] = "Open Blinky",
        ["Tray.Refresh"] = "Refresh",
        ["Tray.Language"] = "Język / Language",
        ["Tray.Exit"] = "Exit",
        ["Tray.NoToken"] = "No token in a reader",
        ["Tray.TokenCount"] = "{0} token(s) present",

        ["Tokens.Title"] = "Your tokens",
        ["Tokens.Empty"] = "No token found in any reader on this machine.",
        ["Tokens.EmptyHint"] = "Plug one in — the list refreshes when you press Refresh.",
        ["Tokens.Serial"] = "Serial",
        ["Tokens.Reader"] = "Reader",
        ["Tokens.Firmware"] = "Firmware",
        ["Tokens.PinAttempts"] = "PIN attempts left",
        ["Tokens.NoPuk"] = "This token has no PUK. A blocked PIN cannot be recovered.",
        ["Tokens.Refresh"] = "Refresh",
        ["Tokens.ChangePin"] = "Change PIN",
        ["Tokens.Unblock"] = "Unblock PIN",
        ["Tokens.Close"] = "Close",

        ["Slot.Empty"] = "empty",
        ["Slot.KeyNoCertificate"] = "a key with no certificate — an enrolment that did not finish",
        ["Slot.Issuer"] = "Issued by",
        ["Slot.Expires"] = "Expires",
        ["Slot.ExpiresIn"] = "in {0} days",
        ["Slot.Expired"] = "expired {0} days ago",

        ["Pin.ChangeTitle"] = "Change the PIN",
        ["Pin.UnblockTitle"] = "Unblock the PIN",
        ["Pin.Current"] = "Current PIN",
        ["Pin.New"] = "New PIN",
        ["Pin.Repeat"] = "New PIN again",
        ["Pin.Mismatch"] = "The two entries do not match.",
        ["Pin.Ok"] = "Confirm",
        ["Pin.Cancel"] = "Cancel",
        ["Pin.Working"] = "Talking to the card…",
        ["Pin.Changed"] = "The PIN was changed.",
        ["Pin.Unblocked"] = "The PIN was unblocked and set.",
        ["Pin.AttemptsLeft"] = "{0} attempts remain.",
        ["Pin.Rules"] = "Six to eight digits. Not the factory PIN, not all the same digit, "
                        + "not a straight run, and not part of the serial printed on the token.",
        ["Pin.RulesCaveat"] = "These rules catch a PIN that is obviously bad. They cannot tell "
                              + "whether yours is a good one.",

        ["Manage.Title"] = "Manage",
        ["Manage.UnblockHint"] = "Sets a new PIN. Needs the backend.",
        ["Pin.UnblockExplained"] = "You are not asked for a PUK: Blinky holds it, spends it "
                                   + "on this unblock and replaces it straight afterwards. "
                                   + "This needs the backend to be reachable.",
        ["Manage.Unknown"] = "not reported by this firmware",

        ["Default.Banner"] = "Still at the factory value:",
        ["Default.Pin"] = "PIN",
        ["Default.Warning"] = "factory value",
        ["Default.Prefilled"] = "Filled in with the factory value, which is what this card "
                                + "reports it still has.",

        ["Device.YubiKey"] = "YubiKey",
        ["Device.Bio"] = "Bio",
        ["Device.Form.UsbAKeychain"] = "USB-A keychain",
        ["Device.Form.UsbANano"] = "USB-A nano",
        ["Device.Form.UsbCKeychain"] = "USB-C keychain",
        ["Device.Form.UsbCNano"] = "USB-C nano",
        ["Device.Form.UsbCLightning"] = "USB-C / Lightning",
        ["Device.Form.UsbABiometricKeychain"] = "Bio, USB-A",
        ["Device.Form.UsbCBiometricKeychain"] = "Bio, USB-C",
        ["Device.Generic"] = "PIV token",
        ["Device.Biometric"] = "(biometric)",

        ["Slots.Header"] = "Certificates",
        ["Slot.Name.9A"] = "Authentication",
        ["Slot.Name.9C"] = "Digital signature",
        ["Slot.Name.9D"] = "Key management",
        ["Slot.Name.9E"] = "Card authentication",

        ["Badge.Managed"] = "managed",
        ["Badge.Unmanaged"] = "not managed",
        ["Badge.Unknown"] = "unknown",


        ["Tray.Theme"] = "Motyw / Theme",
        ["Tray.ThemeSystem"] = "System",
        ["Tray.ThemeLight"] = "Light",
        ["Tray.ThemeDark"] = "Dark",

        ["Manage.Offline"] = "Unblock by telephone",
        ["Manage.OfflineHint"] = "For a machine with no connection to the backend.",
        ["Pin.OfflineTitle"] = "Unblock by telephone",
        ["Pin.OfflineExplained"] = "Read the code below to your helpdesk and type back the one "
                                   + "they read to you. The code they give works once, on this "
                                   + "token only, and stops working the moment it is used.",
        ["Pin.ChallengeLabel"] = "Read this out",
        ["Pin.OfflineCode"] = "Code from the helpdesk",
        ["Cert.Export"] = "Export",
        ["Cert.Install"] = "Install for me",
        ["Cert.Delete"] = "Delete",
        ["Cert.ExportTitle"] = "Save the certificate",
        ["Cert.Exported"] = "Saved to {0}",
        ["Cert.Installed"] = "{0} is now in your personal certificate store. "
                             + "The private key stays on the token. Windows can only use the "
                             + "pair once a minidriver links them - normally that happens on "
                             + "its own when the token is inserted.",
        ["Cert.DeleteConfirm"] = "Delete the certificate in slot {0} of token {1}? "
                                 + "The private key stays where it is. The certificate cannot "
                                 + "be recovered from the card.",

        ["Slot.ProtectedByNothing"] = "Signs without asking for anything",
        ["Slot.ProtectedByFingerprint"] = "Needs a fingerprint",
        ["Slot.ProtectedByPin"] = "Needs the PIN ({0})",

        ["Bio.NotSupported"] = "No fingerprint sensor",
        ["Bio.NotEnrolled"] = "Sensor present, no fingerprint enrolled",
        ["Bio.Enrolled"] = "Fingerprint enrolled",
        ["Bio.Blocked"] = "Fingerprint blocked - the PIN is the way in",
        ["Bio.Attempts"] = "{0} match attempts left",
        ["Bio.AddMore"] = "More fingerprints are added in Yubico Authenticator or Windows "
                          + "sign-in options - not here: enrolling one is a FIDO operation, "
                          + "not a PIV one.",
        ["Prompt.FingerprintTitle"] = "Blinky needs your fingerprint",
        ["Prompt.FingerprintAttempts"] = "{0} attempts before the sensor stops accepting; "
                                         + "after that it asks for your PIN.",
        ["Prompt.PinAttempts"] = "{0} attempts remaining before the PIN is blocked",
        ["Prompt.PinTitle"] = "Blinky needs your PIN",
        ["Prompt.TouchTitle"] = "Touch your token",
        ["Prompt.Unlock"] = "Unlock",
        ["Prompt.Continue"] = "Continue",
        ["Prompt.WrittenDown"] = "I have written it down",
        ["Issue.TitleCard"] = "Issuing a sign-in card",
        ["Issue.TitlePasskey"] = "Creating a passkey",
        ["Issue.For"] = "for {0}",
        ["Issue.Account"] = "account {0} at {1}",
        ["Issue.Profile"] = "profile: {0}",
        ["Issue.RequestedBy"] = "requested by: {0}",
        ["Issue.Steps"] = "Steps",
        ["Issue.Now"] = "Now",
        ["Issue.Starting"] = "Starting…",
        ["Issue.KeepKey"] = "Leave the key in the computer until you see the summary.",
        ["Issue.Done"] = "Done",
        ["Issue.DoneCard"] = "The certificate is on your key. Sign out and sign in again with the card to use it.",
        ["Issue.DonePasskey"] = "The passkey is ready. You can sign in with it at your organisation's sign-in page.",
        ["Issue.Failed"] = "It did not work",
        ["Issue.FailedAt"] = "Stopped at: {0}. Nothing more is needed from you now; the help desk can see what happened.",
        ["Issue.FailedNoStep"] = "It stopped before the first step. The help desk can see what happened.",
        ["Step.AuthenticateManagementKey"] = "Connecting to the key",
        ["StepHint.AuthenticateManagementKey"] = "Blinky is checking that it may manage this key. Nothing to do yet.",
        ["Step.PersonaliseCard"] = "Preparing the key",
        ["StepHint.PersonaliseCard"] = "Blinky sets the key's own security settings. Nothing to do.",
        ["Step.ChoosePin"] = "Choosing your PIN",
        ["StepHint.ChoosePin"] = "Choose the PIN you will type every time you sign in with this key. Keep it to yourself.",
        ["Step.GenerateKey"] = "Creating the key on the card",
        ["StepHint.GenerateKey"] = "The private key is made inside the key and never leaves it. If the key blinks, touch it.",
        ["Step.Attest"] = "Proving the key is genuine",
        ["StepHint.Attest"] = "The key proves it is a genuine YubiKey. Nothing to do.",
        ["Step.VerifyUser"] = "Confirming with your PIN",
        ["StepHint.VerifyUser"] = "Type the key's PIN so it can sign the certificate request.",
        ["Step.BuildAndSignCsr"] = "Signing the request",
        ["StepHint.BuildAndSignCsr"] = "The key signs the request for your certificate. If it blinks, touch it.",
        ["Step.SubmitToCa"] = "Issuing the certificate",
        ["StepHint.SubmitToCa"] = "The certificate authority is issuing your certificate. This can take a few seconds.",
        ["Step.WriteCertificate"] = "Saving the certificate on the key",
        ["StepHint.WriteCertificate"] = "Almost done. Do not remove the key.",
        ["Step.Fido2OpenKey"] = "Connecting to the key",
        ["StepHint.Fido2OpenKey"] = "Blinky is opening the key's FIDO2 part. Nothing to do yet.",
        ["Step.Fido2Pin"] = "FIDO2 PIN",
        ["StepHint.Fido2Pin"] = "This is the key's FIDO2 PIN, used for passkeys - not the smart card PIN you sign in to Windows with.",
        ["Step.Fido2MinPinLength"] = "PIN rules",
        ["StepHint.Fido2MinPinLength"] = "Blinky sets the shortest PIN the key will accept. Nothing to do.",
        ["Step.Fido2Challenge"] = "Asking the provider",
        ["StepHint.Fido2Challenge"] = "Blinky asks your organisation's sign-in service for a new passkey. Nothing to do.",
        ["Step.Fido2Touch"] = "Touching the key",
        ["StepHint.Fido2Touch"] = "When the key starts blinking, touch its gold contact. That touch creates the passkey.",
        ["Step.Fido2Register"] = "Registering the passkey",
        ["StepHint.Fido2Register"] = "The sign-in service is recording the passkey for your account. Nothing to do.",
        ["Step.Fido2ForcePinChange"] = "PIN change on first use",
        ["StepHint.Fido2ForcePinChange"] = "The first time you use the passkey, the key will ask you for a new FIDO2 PIN.",
        ["Passkey.Request"] = "Request a passkey",
        ["Passkey.Checking"] = "Asking the server…",
        ["Passkey.Hint"] = "Asks the help desk for a passkey (FIDO2) on this key, for signing in without a password.",
        ["Passkey.Pending"] = "Waiting for the help desk since {0:g}.",
        ["Passkey.Approved"] = "Approved. Keep the key in this computer: Blinky will ask for its FIDO2 PIN and a touch.",
        ["Passkey.Rejected"] = "Refused: {0}. You can ask again.",
        ["Passkey.Sent"] = "The request went to the help desk. This window will show their answer.",
        ["Prompt.PinLength"] = "A PIN here is {0} to {1} characters",
        ["Error.NoService"] = "The Blinky agent service is not answering on this machine.",
    };

    private static readonly Dictionary<string, string> Polish = new()
    {
        ["App.Name"] = "Blinky",
        ["Notice.Ok"] = "OK",
        ["Tray.Open"] = "Otwórz Blinky",
        ["Tray.Refresh"] = "Odśwież",
        ["Tray.Language"] = "Język / Language",
        ["Tray.Exit"] = "Zakończ",
        ["Tray.NoToken"] = "Brak tokenu w czytniku",
        ["Tray.TokenCount"] = "Tokeny w czytnikach: {0}",

        ["Tokens.Title"] = "Twoje tokeny",
        ["Tokens.Empty"] = "W żadnym czytniku tej maszyny nie ma tokenu.",
        ["Tokens.EmptyHint"] = "Włóż token — lista odświeży się po naciśnięciu Odśwież.",
        ["Tokens.Serial"] = "Numer seryjny",
        ["Tokens.Reader"] = "Czytnik",
        ["Tokens.Firmware"] = "Firmware",
        ["Tokens.PinAttempts"] = "Pozostałe próby PIN",
        ["Tokens.NoPuk"] = "Ten token nie ma PUK-u. Zablokowanego PIN-u nie da się odzyskać.",
        ["Tokens.Refresh"] = "Odśwież",
        ["Tokens.ChangePin"] = "Zmień PIN",
        ["Tokens.Unblock"] = "Odblokuj PIN",
        ["Tokens.Close"] = "Zamknij",

        ["Slot.Empty"] = "pusty",
        ["Slot.KeyNoCertificate"] = "klucz bez certyfikatu — niedokończone wystawienie",
        ["Slot.Issuer"] = "Wystawca",
        ["Slot.Expires"] = "Wygasa",
        ["Slot.ExpiresIn"] = "za {0} dni",
        ["Slot.Expired"] = "wygasł {0} dni temu",

        ["Pin.ChangeTitle"] = "Zmiana PIN-u",
        ["Pin.UnblockTitle"] = "Odblokowanie PIN-u",
        ["Pin.Current"] = "Obecny PIN",
        ["Pin.New"] = "Nowy PIN",
        ["Pin.Repeat"] = "Nowy PIN ponownie",
        ["Pin.Mismatch"] = "Oba wpisy się różnią.",
        ["Pin.Ok"] = "Zatwierdź",
        ["Pin.Cancel"] = "Anuluj",
        ["Pin.Working"] = "Rozmowa z kartą…",
        ["Pin.Changed"] = "PIN został zmieniony.",
        ["Pin.Unblocked"] = "PIN został odblokowany i ustawiony.",
        ["Pin.AttemptsLeft"] = "Pozostałe próby: {0}.",
        ["Pin.Rules"] = "Od sześciu do ośmiu cyfr. Nie fabryczny PIN, nie same identyczne cyfry, "
                        + "nie ciąg pod rząd i nie fragment numeru seryjnego wydrukowanego na tokenie.",
        ["Pin.RulesCaveat"] = "Te reguły wyłapują PIN oczywiście zły. Nie potrafią stwierdzić, "
                              + "czy Twój jest dobry.",

        ["Manage.Title"] = "Zarządzanie",
        ["Manage.UnblockHint"] = "Ustawia nowy PIN. Wymaga połączenia z serwerem.",
        ["Pin.UnblockExplained"] = "Nie pytamy o PUK: Blinky go przechowuje, zużywa na to "
                                   + "odblokowanie i zaraz potem wymienia. Wymaga to "
                                   + "połączenia z serwerem.",
        ["Manage.Unknown"] = "ten firmware tego nie podaje",

        ["Default.Banner"] = "Nadal wartość fabryczna:",
        ["Default.Pin"] = "PIN",
        ["Default.Warning"] = "wartość fabryczna",
        ["Default.Prefilled"] = "Wpisane wartością fabryczną, bo karta sama zgłasza, że wciąż ją ma.",

        ["Device.YubiKey"] = "YubiKey",
        ["Device.Bio"] = "Bio",
        ["Device.Form.UsbAKeychain"] = "USB-A, breloczek",
        ["Device.Form.UsbANano"] = "USB-A nano",
        ["Device.Form.UsbCKeychain"] = "USB-C, breloczek",
        ["Device.Form.UsbCNano"] = "USB-C nano",
        ["Device.Form.UsbCLightning"] = "USB-C / Lightning",
        ["Device.Form.UsbABiometricKeychain"] = "Bio, USB-A",
        ["Device.Form.UsbCBiometricKeychain"] = "Bio, USB-C",
        ["Device.Generic"] = "Token PIV",
        ["Device.Biometric"] = "(biometryczny)",

        ["Slots.Header"] = "Certyfikaty",
        ["Slot.Name.9A"] = "Uwierzytelnienie",
        ["Slot.Name.9C"] = "Podpis cyfrowy",
        ["Slot.Name.9D"] = "Zarządzanie kluczem",
        ["Slot.Name.9E"] = "Uwierzytelnianie kartą",

        ["Badge.Managed"] = "zarządzany",
        ["Badge.Unmanaged"] = "niezarządzany",
        ["Badge.Unknown"] = "nieznany",


        ["Tray.Theme"] = "Motyw / Theme",
        ["Tray.ThemeSystem"] = "Systemowy",
        ["Tray.ThemeLight"] = "Jasny",
        ["Tray.ThemeDark"] = "Ciemny",

        ["Manage.Offline"] = "Odblokuj przez telefon",
        ["Manage.OfflineHint"] = "Dla maszyny bez połączenia z serwerem.",
        ["Pin.OfflineTitle"] = "Odblokowanie przez telefon",
        ["Pin.OfflineExplained"] = "Przeczytaj poniższy kod helpdeskowi i wpisz ten, który "
                                   + "odczytają Tobie. Ich kod działa raz, tylko na tym tokenie "
                                   + "i przestaje działać w chwili użycia.",
        ["Pin.ChallengeLabel"] = "Przeczytaj to",
        ["Pin.OfflineCode"] = "Kod od helpdesku",
        ["Cert.Export"] = "Eksportuj",
        ["Cert.Install"] = "Zainstaluj u mnie",
        ["Cert.Delete"] = "Usuń",
        ["Cert.ExportTitle"] = "Zapisz certyfikat",
        ["Cert.Exported"] = "Zapisano do {0}",
        ["Cert.Installed"] = "{0} jest teraz w Twoim osobistym magazynie certyfikatów. "
                             + "Klucz prywatny zostaje na tokenie. Windows użyje tej pary "
                             + "dopiero, gdy minidriver je powiąże - zwykle dzieje się to samo "
                             + "po włożeniu tokenu.",
        ["Cert.DeleteConfirm"] = "Usunąć certyfikat ze slotu {0} tokenu {1}? "
                                 + "Klucz prywatny zostaje na miejscu. Certyfikatu nie da się "
                                 + "odzyskać z karty.",

        ["Slot.ProtectedByNothing"] = "Podpisuje bez pytania o cokolwiek",
        ["Slot.ProtectedByFingerprint"] = "Wymaga odcisku palca",
        ["Slot.ProtectedByPin"] = "Wymaga PIN-u ({0})",

        ["Bio.NotSupported"] = "Brak czytnika odcisku",
        ["Bio.NotEnrolled"] = "Czytnik jest, żaden odcisk nie zapisany",
        ["Bio.Enrolled"] = "Odcisk zapisany",
        ["Bio.Blocked"] = "Odcisk zablokowany - wejście przez PIN",
        ["Bio.Attempts"] = "Pozostałe próby dopasowania: {0}",
        ["Bio.AddMore"] = "Kolejne odciski dodaje się w Yubico Authenticator albo w opcjach "
                          + "logowania Windows - nie tutaj: zapis odcisku to operacja FIDO, "
                          + "nie PIV.",
        ["Prompt.FingerprintTitle"] = "Blinky prosi o odcisk palca",
        ["Prompt.FingerprintAttempts"] = "Pozostałe próby: {0}. Potem klucz poprosi o PIN.",
        ["Prompt.PinAttempts"] = "Pozostałe próby przed zablokowaniem PIN-u: {0}",
        ["Prompt.PinTitle"] = "Blinky prosi o PIN",
        ["Prompt.TouchTitle"] = "Dotknij tokenu",
        ["Prompt.Unlock"] = "Odblokuj",
        ["Prompt.Continue"] = "Dalej",
        ["Prompt.WrittenDown"] = "PIN zapisany",
        ["Issue.TitleCard"] = "Wydanie karty do logowania",
        ["Issue.TitlePasskey"] = "Tworzenie passkeya",
        ["Issue.For"] = "dla: {0}",
        ["Issue.Account"] = "konto {0} w {1}",
        ["Issue.Profile"] = "profil: {0}",
        ["Issue.RequestedBy"] = "zlecenie od: {0}",
        ["Issue.Steps"] = "Kroki",
        ["Issue.Now"] = "Teraz",
        ["Issue.Starting"] = "Rozpoczynanie…",
        ["Issue.KeepKey"] = "Nie wyjmuj klucza z komputera, dopóki nie zobaczysz podsumowania.",
        ["Issue.Done"] = "Gotowe",
        ["Issue.DoneCard"] = "Certyfikat jest na kluczu. Wyloguj się i zaloguj ponownie kartą, aby go użyć.",
        ["Issue.DonePasskey"] = "Passkey jest gotowy. Możesz logować się nim na stronie logowania swojej organizacji.",
        ["Issue.Failed"] = "Nie udało się",
        ["Issue.FailedAt"] = "Przerwane na kroku: {0}. Teraz nic więcej nie musisz robić; helpdesk widzi, co się stało.",
        ["Issue.FailedNoStep"] = "Przerwane przed pierwszym krokiem. Helpdesk widzi, co się stało.",
        ["Step.AuthenticateManagementKey"] = "Połączenie z kluczem",
        ["StepHint.AuthenticateManagementKey"] = "Blinky sprawdza, czy może zarządzać tym kluczem. Na razie nic nie musisz robić.",
        ["Step.PersonaliseCard"] = "Przygotowanie klucza",
        ["StepHint.PersonaliseCard"] = "Blinky ustawia zabezpieczenia klucza. Nic nie musisz robić.",
        ["Step.ChoosePin"] = "Wybór PIN-u",
        ["StepHint.ChoosePin"] = "Wybierz PIN, który będziesz wpisywać przy każdym logowaniu tym kluczem. Nie zdradzaj go nikomu.",
        ["Step.GenerateKey"] = "Tworzenie klucza na karcie",
        ["StepHint.GenerateKey"] = "Klucz prywatny powstaje w samym kluczu i nigdy go nie opuszcza. Jeśli klucz zamruga, dotknij go.",
        ["Step.Attest"] = "Potwierdzenie autentyczności",
        ["StepHint.Attest"] = "Klucz udowadnia, że jest prawdziwym YubiKeyem. Nic nie musisz robić.",
        ["Step.VerifyUser"] = "Potwierdzenie PIN-em",
        ["StepHint.VerifyUser"] = "Wpisz PIN klucza, żeby mógł podpisać wniosek o certyfikat.",
        ["Step.BuildAndSignCsr"] = "Podpisanie wniosku",
        ["StepHint.BuildAndSignCsr"] = "Klucz podpisuje wniosek o Twój certyfikat. Jeśli zamruga, dotknij go.",
        ["Step.SubmitToCa"] = "Wystawienie certyfikatu",
        ["StepHint.SubmitToCa"] = "Urząd certyfikacji wystawia certyfikat. To może potrwać kilka sekund.",
        ["Step.WriteCertificate"] = "Zapis certyfikatu na kluczu",
        ["StepHint.WriteCertificate"] = "Prawie gotowe. Nie wyjmuj klucza.",
        ["Step.Fido2OpenKey"] = "Połączenie z kluczem",
        ["StepHint.Fido2OpenKey"] = "Blinky otwiera część FIDO2 klucza. Na razie nic nie musisz robić.",
        ["Step.Fido2Pin"] = "PIN FIDO2",
        ["StepHint.Fido2Pin"] = "To PIN części FIDO2 klucza, do passkeyów - nie PIN karty, którym logujesz się do Windows.",
        ["Step.Fido2MinPinLength"] = "Reguły PIN-u",
        ["StepHint.Fido2MinPinLength"] = "Blinky ustawia najkrótszy PIN, jaki klucz przyjmie. Nic nie musisz robić.",
        ["Step.Fido2Challenge"] = "Zapytanie do dostawcy",
        ["StepHint.Fido2Challenge"] = "Blinky prosi usługę logowania Twojej organizacji o nowy passkey. Nic nie musisz robić.",
        ["Step.Fido2Touch"] = "Dotknięcie klucza",
        ["StepHint.Fido2Touch"] = "Gdy klucz zacznie migać, dotknij jego złotego styku. To dotknięcie tworzy passkey.",
        ["Step.Fido2Register"] = "Rejestracja passkeya",
        ["StepHint.Fido2Register"] = "Usługa logowania zapisuje passkey na Twoim koncie. Nic nie musisz robić.",
        ["Step.Fido2ForcePinChange"] = "Zmiana PIN-u przy pierwszym użyciu",
        ["StepHint.Fido2ForcePinChange"] = "Przy pierwszym użyciu passkeya klucz poprosi Cię o nowy PIN FIDO2.",
        ["Passkey.Request"] = "Poproś o passkey",
        ["Passkey.Checking"] = "Pytam serwer…",
        ["Passkey.Hint"] = "Prosi helpdesk o passkey (FIDO2) na tym kluczu, do logowania bez hasła.",
        ["Passkey.Pending"] = "Czeka na helpdesk od {0:g}.",
        ["Passkey.Approved"] = "Zatwierdzone. Zostaw klucz w komputerze: Blinky poprosi o PIN FIDO2 i dotknięcie.",
        ["Passkey.Rejected"] = "Odrzucone: {0}. Możesz poprosić ponownie.",
        ["Passkey.Sent"] = "Prośba poszła do helpdesku. Odpowiedź pokaże się w tym oknie.",
        ["Prompt.PinLength"] = "Ten PIN ma od {0} do {1} znaków",
        ["Error.NoService"] = "Usługa agenta Blinky nie odpowiada na tej maszynie.",
    };
}

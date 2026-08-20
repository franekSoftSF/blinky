using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Windows;
using Blinky.Contracts;
using Microsoft.Win32;

namespace Blinky.Agent.Ui;

/// <summary>
/// Getting a certificate off the card and into somewhere useful.
/// </summary>
/// <remarks>
/// <para>
/// The card is read by the service; the file and the store are written here.
/// That split is not arbitrary. The service runs as <c>LocalSystem</c>, and its
/// idea of "the current user's certificate store" is <c>SYSTEM</c>'s — putting
/// a cardholder's certificate there would file it under an account nobody logs
/// in as. The store that matters belongs to the person at the keyboard, and
/// this process is the one running as them.
/// </para>
/// </remarks>
public static class CertificateActions
{
    /// <summary>Saves a slot's certificate as PEM or DER.</summary>
    public static async Task ExportAsync(RequestClient client, long serial, string slotId)
    {
        var certificate = await ReadAsync(client, serial, slotId);
        if (certificate is null)
        {
            return;
        }

        using (certificate)
        {
            var dialog = new SaveFileDialog
            {
                FileName = $"{serial}-{slotId}.cer",

                // DER first because it is what Windows double-clicks into the
                // certificate viewer; PEM for everything that expects text.
                Filter = "Certificate (*.cer)|*.cer|PEM (*.pem;*.crt)|*.pem;*.crt",
                Title = Strings.Current["Cert.ExportTitle"],
            };

            if (dialog.ShowDialog() != true)
            {
                return;
            }

            var pem = dialog.FileName.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)
                      || dialog.FileName.EndsWith(".crt", StringComparison.OrdinalIgnoreCase);

            if (pem)
            {
                await File.WriteAllTextAsync(dialog.FileName, certificate.ExportCertificatePem());
            }
            else
            {
                await File.WriteAllBytesAsync(dialog.FileName, certificate.RawData);
            }

            Say(string.Format(Strings.Current["Cert.Exported"], dialog.FileName));
        }
    }

    /// <summary>
    /// Puts the certificate into this user's personal store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What this does and does not do is worth being exact about, because the
    /// difference is invisible in <c>certmgr.msc</c>. It installs the
    /// <b>certificate</b>. The private key stays on the token, where it
    /// belongs, and Windows can only use the pair if a minidriver links the two
    /// — normally the smart card certificate propagation service does that on
    /// its own the moment the token is inserted.
    /// </para>
    /// <para>
    /// So this is a repair for when propagation has not happened, and on this
    /// bench it had not: with HID ActivClient owning the minidriver binding, a
    /// certificate written into a PIV slot never reached the store. A
    /// certificate here with no key behind it will appear in the list and
    /// refuse to authenticate, which reads as a broken certificate rather than
    /// a missing link — so the message says so.
    /// </para>
    /// </remarks>
    public static async Task InstallAsync(RequestClient client, long serial, string slotId)
    {
        var certificate = await ReadAsync(client, serial, slotId);
        if (certificate is null)
        {
            return;
        }

        using (certificate)
        {
            try
            {
                // CurrentUser, and this process is the user. The service could
                // not do this if it wanted to.
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);

                Say(string.Format(Strings.Current["Cert.Installed"], certificate.Subject));
            }
            catch (Exception ex)
            {
                Say(ex.Message, error: true);
            }
        }
    }

    private static async Task<X509Certificate2?> ReadAsync(RequestClient client, long serial,
        string slotId)
    {
        var response = await client.SendAsync(
            new AgentRequest(AgentRequest.ReadCertificate, serial, slotId));

        if (response is { Succeeded: true, CertificatePem: { Length: > 0 } pem })
        {
            return X509Certificate2.CreateFromPem(pem);
        }

        Say(response.Error ?? Strings.Current["Error.NoService"], error: true);

        return null;
    }

    private static void Say(string message, bool error = false) =>
        MessageBox.Show(message, Strings.Current["App.Name"], MessageBoxButton.OK,
            error ? MessageBoxImage.Warning : MessageBoxImage.Information);
}

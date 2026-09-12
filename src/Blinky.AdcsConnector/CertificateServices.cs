using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Blinky.Contracts;
using Microsoft.Win32;

namespace Blinky.AdcsConnector;

/// <summary>
/// ADCS, reached the only way ADCS can be reached: <c>ICertRequest3</c> and
/// <c>ICertAdmin2</c>, in process, on the machine.
/// </summary>
/// <remarks>
/// <para>
/// Late bound through <c>IDispatch</c> rather than through an interop assembly.
/// <c>certcli.dll</c> carries a type library, but embedding it pins the build to
/// whichever Windows SDK generated the wrapper and puts a component that is not
/// on a clean build agent into the dependency list. Six methods do not justify
/// that.
/// </para>
/// <para>
/// Every call here blocks. A cancellation token bounds how long the connector
/// waits and does not stop the call - there is no way to abort a DCOM call in
/// flight, and pretending otherwise would leak a thread per timeout instead of
/// admitting one. See <see cref="CertificateServiceHost"/>.
/// </para>
/// </remarks>
public sealed class CertificateServices(ILogger<CertificateServices> logger) : ICertificateServices
{
    // ICertRequest submission flags. Microsoft's names kept, because the only
    // documentation for what these mean is Microsoft's.
    private const int CrInBase64 = 0x1;
    private const int CrInPkcs10 = 0x100;
    private const int CrInCmc = 0x400;

    private const int CrOutBase64 = 0x1;
    private const int CrOutChain = 0x100;

    // ICertConfig: the CA running on this machine, not the one a user would be
    // asked to pick out of a dialog. A connector is installed beside its CA.
    private const int CcLocalActiveConfig = 0x4;

    /// <summary>Un-revoking a held certificate. Never sent by Blinky today.</summary>
    private const int ReasonUnrevoke = -1;

    private const uint AccessDenied = 0x80070005;

    public CaDescription Describe(string? caConfig, CancellationToken ct)
    {
        var config = Resolve(caConfig);

        var request = Create("CertificateAuthority.Request");
        try
        {
            // An empty submission is not a way to ask a CA whether it is there:
            // it costs a database row and a denial in the CA's own log. The CA
            // certificate is the thing worth having, it is what
            // GetCACertificate returns, and asking for it proves the DCOM path
            // works end to end.
            var chain = TryGetCaChain(request, config);

            return new CaDescription(
                config,
                NameOf(config),
                AdminAvailable: TryOpenAdmin(config),
                CertificateChain: chain,
                Templates: TryReadTemplates(NameOf(config)));
        }
        finally
        {
            Release(request);
        }
    }

    public SubmissionOutcome Submit(
        byte[] request, AdcsRequestFormat format, string? attributes, string? caConfig,
        CancellationToken ct)
    {
        var config = Resolve(caConfig);
        var flags = CrInBase64 | (format == AdcsRequestFormat.Cmc ? CrInCmc : CrInPkcs10);

        var certRequest = Create("CertificateAuthority.Request");
        try
        {
            logger.LogInformation(
                "Submitting a {Format} request of {Bytes} bytes to {Config}",
                format, request.Length, config);

            var disposition = ToDisposition(Invoke<int>(
                certRequest,
                "Submit",
                flags,
                Convert.ToBase64String(request),
                attributes ?? string.Empty,
                config));

            return Collect(certRequest, disposition);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            throw Translate(ex, config);
        }
        finally
        {
            Release(certRequest);
        }
    }

    public SubmissionOutcome Retrieve(int requestId, string? caConfig, CancellationToken ct)
    {
        var config = Resolve(caConfig);

        var certRequest = Create("CertificateAuthority.Request");
        try
        {
            var disposition = ToDisposition(
                Invoke<int>(certRequest, "RetrievePending", requestId, config));

            return Collect(certRequest, disposition);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            throw Translate(ex, config);
        }
        finally
        {
            Release(certRequest);
        }
    }

    public RevocationOutcome Revoke(
        string serialNumber, int reason, DateTimeOffset? effectiveAt, string? caConfig,
        CancellationToken ct)
    {
        var config = Resolve(caConfig);

        var admin = Create("CertificateAuthority.Admin");
        try
        {
            logger.LogInformation(
                "Revoking {Serial} at {Config}, reason {Reason}", serialNumber, config, reason);

            Invoke<object?>(
                admin, "RevokeCertificate", config, serialNumber, reason, ToDate(effectiveAt));

            return new RevocationOutcome(reason != ReasonUnrevoke, null, null);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            // Distinguished from a fault deliberately: "this account may not
            // manage certificates" is a grant somebody has to make, and it
            // reads nothing like a CA that is down.
            return new RevocationOutcome(false, ex.Message, ex.HResult);
        }
        finally
        {
            Release(admin);
        }
    }

    /// <summary>Pulls the certificate, the chain and the CA's own words out.</summary>
    private SubmissionOutcome Collect(object certRequest, AdcsDisposition disposition)
    {
        var requestId = Invoke<int>(certRequest, "GetRequestId");
        var message = TryInvoke<string>(certRequest, "GetDispositionMessage");
        var status = TryInvoke<int>(certRequest, "GetLastStatus");

        if (disposition != AdcsDisposition.Issued)
        {
            logger.LogWarning(
                "Request {RequestId} came back {Disposition}: {Message}",
                requestId, disposition, message);

            return new SubmissionOutcome(disposition, requestId, null, null, message, status);
        }

        var certificate = FromBase64(Invoke<string>(certRequest, "GetCertificate", CrOutBase64));

        // The chain in one call. Rebuilding it on the caller's side would mean a
        // Linux container holding the customer's CA hierarchy in a trust store
        // somebody has to maintain, to learn something the CA already knows.
        var chain = TryInvoke<string>(certRequest, "GetCertificate", CrOutBase64 | CrOutChain);

        return new SubmissionOutcome(
            disposition,
            requestId,
            certificate,
            chain is null ? null : FromBase64(chain),
            message,
            status);
    }

    private string Resolve(string? caConfig)
    {
        if (caConfig is { Length: > 0 })
        {
            return caConfig;
        }

        var config = Create("CertificateAuthority.Config");
        try
        {
            return Invoke<string>(config, "GetConfig", CcLocalActiveConfig);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            throw new CertificateServiceException(
                "No certification authority is active on this machine and none was named. "
                + "Set Connector:CaConfig to HOST\\CA common name.", ex.HResult, ex);
        }
        finally
        {
            Release(config);
        }
    }

    /// <summary>
    /// A DATE of zero tells ADCS to stamp its own clock, which is the right
    /// answer when Blinky did not name a time: the alternative is sending this
    /// machine's idea of UTC to a CA whose reading of an unqualified DATE is
    /// not something to guess at. A named time is sent as UTC and that
    /// assumption is <b>unverified</b> against a real CA - docs/15.
    /// </summary>
    private static DateTime ToDate(DateTimeOffset? effectiveAt) =>
        effectiveAt is { } when
            ? when.UtcDateTime
            : new DateTime(1899, 12, 30, 0, 0, 0, DateTimeKind.Unspecified);

    /// <summary>The CA's common name - the half after the backslash.</summary>
    private static string NameOf(string caConfig)
    {
        var separator = caConfig.IndexOf('\\');

        return separator < 0 ? caConfig : caConfig[(separator + 1)..];
    }

    private byte[]? TryGetCaChain(object certRequest, string config)
    {
        try
        {
            // GetCACertificate(fExchangeCertificate, strConfig, Flags): the
            // signing certificate, as a chain, base64.
            var chain = Invoke<string>(
                certRequest, "GetCACertificate", 0, config, CrOutBase64 | CrOutChain);

            return FromBase64(chain);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            logger.LogWarning(
                "{Config} would not hand over its certificate: {Message}", config, ex.Message);

            return null;
        }
    }

    private bool TryOpenAdmin(string config)
    {
        object admin;
        try
        {
            admin = Create("CertificateAuthority.Admin");
        }
        catch (CertificateServiceException)
        {
            // ICertAdmin2 lives in certadm.dll, which arrives with the CA role
            // or the management tools; ICertRequest3 lives in certcli.dll, which
            // is on every Windows. So the two can be present separately, and a
            // machine with only the second can enrol and not revoke. Measured on
            // a bench with neither a CA nor the tools, where this threw out of
            // describe and took the whole registration down - which reported a
            // usable connector as broken.
            logger.LogInformation(
                "CertificateAuthority.Admin is not registered on this machine, so revocation "
                + "through this connector is unavailable. Enrolment is unaffected.");

            return false;
        }

        try
        {
            // Un-revoking a serial that cannot exist. It reaches the CA's
            // permission check and fails there for the right reason, which is
            // exactly what is being asked - whether this account may manage
            // certificates - without touching a real certificate. Access denied
            // is the answer "no"; anything else means the call was allowed as
            // far as the database, which is the answer "yes".
            Invoke<object?>(admin, "RevokeCertificate", config, "00", ReasonUnrevoke, ToDate(null));

            return true;
        }
        catch (Exception ex) when (FromTheCa(ex) && (uint)ex.HResult == AccessDenied)
        {
            return false;
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            return true;
        }
        finally
        {
            Release(admin);
        }
    }

    /// <summary>
    /// The templates the CA is configured to issue, read from where the CA
    /// keeps them.
    /// </summary>
    /// <remarks>
    /// The registry rather than an interface, because no ICertAdmin call lists
    /// them: the authoritative list is the <c>Templates</c> value the CA itself
    /// maintains, alternating OID and name. Best effort and marked as such - a
    /// null here means "not established", and 0033 must not read it as "none".
    /// </remarks>
    private IReadOnlyList<string>? TryReadTemplates(string caName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\" + caName);

            if (key?.GetValue("Templates") is not string[] entries)
            {
                return null;
            }

            // Pairs of OID then name. The name is the half a template
            // permission is granted on and the half an attribute string names.
            return [.. entries.Where((_, index) => index % 2 == 1)];
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.LogWarning("The template list of {CaName} is not readable by this account", caName);

            return null;
        }
    }

    private static AdcsDisposition ToDisposition(int value) =>
        Enum.IsDefined(typeof(AdcsDisposition), value)
            ? (AdcsDisposition)value
            : AdcsDisposition.Error;

    private static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false);

        if (type is null)
        {
            throw new CertificateServiceException(
                progId + " is not registered on this machine. The connector belongs on the "
                + "certification authority itself, or on a machine carrying the Certification "
                + "Authority management tools.");
        }

        return Activator.CreateInstance(type)
            ?? throw new CertificateServiceException(progId + " could not be created.");
    }

    private static T Invoke<T>(object target, string member, params object?[] arguments)
    {
        try
        {
            var result = target.GetType().InvokeMember(
                member, BindingFlags.InvokeMethod, null, target, arguments);

            return result is null ? default! : (T)result;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is { } inner)
        {
            // Late binding wraps whatever the CA threw. Without this every
            // catch in this file is dead code - measured on a machine with no
            // Certification Authority, where a describe produced a 500 and a
            // stack trace instead of the 502 and the reason it was written to
            // produce.
            ExceptionDispatchInfo.Capture(inner).Throw();

            throw;
        }
    }

    /// <summary>
    /// Whether an exception came from the call rather than from this code.
    /// </summary>
    /// <remarks>
    /// Broader than <see cref="COMException"/> on purpose. .NET maps some
    /// HRESULTs to their own types before anything here sees them:
    /// <c>CCertConfig::GetConfig</c> on a machine with no CA arrives as a
    /// <see cref="FileNotFoundException"/> carrying 0x80070002, and access
    /// denied arrives as <see cref="UnauthorizedAccessException"/>. Everything
    /// inside the guarded blocks is a COM call, so everything but this class's
    /// own refusals belongs to the CA.
    /// </remarks>
    private static bool FromTheCa(Exception ex) =>
        ex is not CertificateServiceException and not OperationCanceledException;

    private T? TryInvoke<T>(object target, string member, params object?[] arguments)
    {
        try
        {
            return Invoke<T>(target, member, arguments);
        }
        catch (Exception ex) when (FromTheCa(ex))
        {
            // Not fatal by design. These are the calls that add detail to an
            // answer already in hand; losing the detail is worth less than
            // losing the certificate.
            logger.LogDebug("{Member} was not answered: {Message}", member, ex.Message);

            return default;
        }
    }

    private static byte[] FromBase64(string value) => Convert.FromBase64String(value.Trim());

    private static CertificateServiceException Translate(Exception ex, string config) =>
        new(config + " refused the request: " + ex.Message, ex.HResult, ex);

    private static void Release(object instance)
    {
        if (Marshal.IsComObject(instance))
        {
            Marshal.FinalReleaseComObject(instance);
        }
    }
}

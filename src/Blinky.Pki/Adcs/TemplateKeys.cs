namespace Blinky.Pki.Adcs;

/// <summary>
/// What a template demands of a key, set against the algorithms Blinky enrols with.
/// </summary>
/// <remarks>
/// <para>
/// The minimum key size is compared by the CA with the request's key length whatever
/// the algorithm. The lab CA denied a P-256 key against a template left on the default
/// 2048 with <c>CERTSRV_E_KEY_LENGTH</c>, after reading the CMC and applying the
/// template, and that is the only reason this exists: nothing before the submission
/// said so.
/// </para>
/// <para>
/// The algorithm a version 4 template names is read too, and a mismatch is only a
/// warning, because the CA does not enforce it. Measured on the lab CA with the template
/// set to <c>ECDH_P256</c> and a 256-bit minimum: a P-256 key and an RSA 2048 key were
/// both issued from the same template, on the same day.
/// </para>
/// </remarks>
public static class TemplateKeys
{
    /// <summary>The length the CA will measure, for each algorithm name Blinky uses.</summary>
    public static int? BitsOf(string algorithm) => algorithm.ToUpperInvariant() switch
    {
        "RSA2048" => 2048,
        "RSA3072" => 3072,
        "RSA4096" => 4096,
        "ECCP256" => 256,
        "ECCP384" => 384,
        _ => null,
    };

    /// <summary>
    /// <c>msPKI-Asymmetric-Algorithm</c> out of a version 4 template's
    /// <c>msPKI-RA-Application-Policies</c>, or null when it names none.
    /// </summary>
    /// <remarks>
    /// Version 4 packs several settings into that attribute as name, type and value
    /// separated by backticks - <c>msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P256`</c> -
    /// which is how the lab's own template stored its signature policy. A template on a
    /// legacy provider names no algorithm at all.
    /// </remarks>
    public static string? AsymmetricAlgorithm(IReadOnlyList<string>? policies)
    {
        foreach (var policy in policies ?? [])
        {
            var parts = policy.Split('`');

            for (var index = 0; index + 2 < parts.Length; index += 3)
            {
                if (string.Equals(parts[index], "msPKI-Asymmetric-Algorithm", StringComparison.OrdinalIgnoreCase)
                    && parts[index + 2] is { Length: > 0 } value)
                {
                    return value;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Whether a key of Blinky's <paramref name="algorithm"/> is the kind the template
    /// names. ECDH and ECDSA on the same curve are the same key.
    /// </summary>
    public static bool Matches(string algorithm, string templateAlgorithm)
    {
        var wanted = templateAlgorithm.ToUpperInvariant();

        return algorithm.ToUpperInvariant() switch
        {
            "RSA2048" or "RSA3072" or "RSA4096" => wanted == "RSA",
            "ECCP256" => wanted is "ECDSA_P256" or "ECDH_P256",
            "ECCP384" => wanted is "ECDSA_P384" or "ECDH_P384",
            _ => false,
        };
    }
}

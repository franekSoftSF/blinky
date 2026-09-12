namespace Blinky.Secrets;

/// <summary>
/// Everything the PKCS#11 provider needs, and nothing about any one device.
/// </summary>
/// <remarks>
/// There is no SoftHSM setting here and there is not meant to be. SoftHSM2 is a
/// module path; a YubiHSM is a different module path and a connector its own
/// configuration file names. Anything a particular device needs beyond this
/// belongs in that device's own configuration, outside this process, which is
/// what keeps "add a real HSM" a deployment change.
/// </remarks>
public sealed class Pkcs11KeyProviderOptions
{
    /// <summary>The PKCS#11 module to load.</summary>
    public string Module { get; init; } = string.Empty;

    /// <summary>
    /// Which token to use, by its label.
    /// </summary>
    /// <remarks>
    /// By label rather than by slot number. Slot numbers are assigned by the
    /// module and move when anything else is plugged in or initialised; a label
    /// is what the person who provisioned the token chose.
    /// </remarks>
    public string TokenLabel { get; init; } = "blinky";

    /// <summary>
    /// A file holding the user PIN, readable only by this process's user.
    /// </summary>
    /// <remarks>
    /// Preferred over <see cref="Pin"/>, and the reason is the whole point of
    /// the exercise: a PIN in the environment is exposed by exactly the means
    /// that make an environment secret worse than a file, so moving the keys
    /// into a device while leaving the PIN in the environment moves the
    /// problem rather than solving it.
    /// </remarks>
    public string? PinFile { get; init; }

    /// <summary>The user PIN inline. For a laboratory; prefer a file.</summary>
    public string? Pin { get; init; }

    /// <summary>Which generation of each key this deployment writes with.</summary>
    public int ManagementKeyVersion { get; init; } = 1;

    /// <summary>Which generation of each key this deployment writes with.</summary>
    public int PukKekVersion { get; init; } = PukKekVersions.FirstProviderVersion;

    /// <summary>
    /// Whether a key the device will let out is refused.
    /// </summary>
    /// <remarks>
    /// True, and turning it off has to be a decision that shows up in a diff.
    /// A token can be provisioned with extractable keys and looks identical
    /// from the outside; a deployment that has done that has the interface of a
    /// device and the custody of a file, and would report the former.
    /// </remarks>
    public bool RequireNonExportable { get; init; } = true;
}

/// <summary>
/// Which PUK envelope generations mean what.
/// </summary>
/// <remarks>
/// Version one is not a provider key and never will be: it named the raw
/// configured KEK used directly as an AES-GCM key, which is precisely the shape
/// a device cannot serve without handing the key out. Provider-held generations
/// start above it, so an envelope's recorded version says which of the two
/// schemes opens it without anything else having to be written down.
/// </remarks>
public static class PukKekVersions
{
    /// <summary>The raw configured KEK, used directly. Decrypt only, from now on.</summary>
    public const int Legacy = 1;

    /// <summary>The first generation held by a provider and used through a derivation.</summary>
    public const int FirstProviderVersion = 2;
}

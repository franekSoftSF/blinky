using System.Reflection;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Blinky.Secrets;

/// <summary>
/// Teaches Pkcs11Interop where <c>dlopen</c> lives on a modern Linux.
/// </summary>
/// <remarks>
/// <para>
/// Pkcs11Interop reaches a PKCS#11 module through <c>dlopen</c>, which it
/// imports as <c>libdl</c>. Since glibc 2.34 that library is a stub kept for
/// binary compatibility and the symbols live in libc; the unversioned
/// <c>libdl.so</c> that a <c>DllImport</c> looks for is part of the development
/// package and is not on a runtime image. The result is a
/// <c>DllNotFoundException</c> listing eight paths that were tried and not one
/// of them <c>libdl.so.2</c>, which is sitting right there.
/// </para>
/// <para>
/// The alternatives were worse. Installing the development package to obtain a
/// symlink puts a compiler toolchain in a production image; creating the
/// symlink in the Dockerfile fixes one image and leaves a developer's own
/// machine broken in a way that reads as a bug in this code. A resolver is
/// eight lines, belongs to the process rather than to the image, and is
/// exercised by the tests.
/// </para>
/// <para>
/// Found by running the provisioning tool against the reference module for the
/// first time, which is exactly what that first run is for.
/// </para>
/// </remarks>
internal static class NativeLoader
{
    private static int installed;

    /// <summary>
    /// Registers the resolver once, before anything calls into the library.
    /// </summary>
    /// <remarks>
    /// Once, because a second <c>SetDllImportResolver</c> for the same assembly
    /// throws; and before, because a resolver registered after the import has
    /// already failed does not get a second chance.
    /// </remarks>
    internal static void Prepare()
    {
        if (Interlocked.Exchange(ref installed, 1) == 1)
        {
            return;
        }

        if (!OperatingSystem.IsLinux())
        {
            // Windows and macOS reach dlopen or its equivalent by other means,
            // and their loaders find it. Nothing to correct.
            return;
        }

        NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, "libdl", StringComparison.Ordinal))
        {
            // Zero means "no opinion", and the runtime carries on with its own
            // search. Answering for anything but the one library that is
            // wrong would make this a loader rather than a correction.
            return IntPtr.Zero;
        }

        // The versioned stub first, because it is what the import was written
        // for. libc second, because on glibc 2.34 and later that is where the
        // symbols actually are and a distribution may ship no stub at all.
        foreach (var candidate in new[] { "libdl.so.2", "libc.so.6" })
        {
            if (NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        return IntPtr.Zero;
    }
}

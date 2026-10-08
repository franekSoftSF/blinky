using Blinky.Passkeys;

namespace Blinky.Api.Passkeys;

/// <summary>The identity providers this deployment can register passkeys with, by name.</summary>
/// <remarks>
/// Built from the database by <see cref="PasskeyProviders"/> and rebuilt when a
/// provider changes; the ceremony only asks it for a name. Usually empty: an
/// on-premises PIV deployment has no reason to reach a cloud, and this is the only
/// thing in the stack that does.
/// </remarks>
public sealed class PasskeyDirectories
{
    private readonly Func<IReadOnlyList<IPasskeyDirectory>> load;
    private readonly Lock gate = new();
    private Dictionary<string, IPasskeyDirectory>? byName;

    public PasskeyDirectories(Func<IReadOnlyList<IPasskeyDirectory>> load) => this.load = load;

    /// <summary>A fixed set, for tests.</summary>
    public PasskeyDirectories(IEnumerable<IPasskeyDirectory> directories)
    {
        var fixedSet = directories.ToList();
        load = () => fixedSet;
    }

    public IReadOnlyCollection<IPasskeyDirectory> All => Current().Values;

    public IPasskeyDirectory? Find(string name) => Current().GetValueOrDefault(name);

    /// <summary>The next lookup builds the set again from the database.</summary>
    public void Invalidate()
    {
        lock (gate)
        {
            byName = null;
        }
    }

    private Dictionary<string, IPasskeyDirectory> Current()
    {
        lock (gate)
        {
            return byName ??= load().ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);
        }
    }
}

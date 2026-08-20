// Blinky - asks a token whether it can delete a private key, and does it.
//
//     dotnet run --project tools/SlotProbe -- <serial> <slot>
//
// PIV has no delete-key command; Yubico added one in firmware 5.7. This exists
// to find out which of those a given token is, on the token, rather than by
// reading a version number and hoping.
//
// It destroys a key. There is no undo and no copy anywhere.

using Blinky.Piv;
using Blinky.Piv.Pcsc;

if (args.Length < 2 || !long.TryParse(args[0], out var wanted))
{
    Console.Error.WriteLine("usage: SlotProbe <serial> <slot>");
    return 2;
}

var slotName = args[1];

using var context = PcscContext.Establish();

foreach (var reader in context.ListReaders())
{
    using var card = context.Connect(reader);
    if (card is null)
    {
        continue;
    }

    using var connection = new PivConnection(card, ownsTransport: false);
    var session = new PivSession(connection);
    using var transaction = connection.BeginTransaction();

    if (!session.Select() || session.GetSerialNumber() != (uint)wanted)
    {
        continue;
    }

    var slot = PivSlot.Credentials.First(s =>
        s.Name.Equals(slotName, StringComparison.OrdinalIgnoreCase));

    Console.WriteLine($"firmware {session.GetFirmwareVersion()}");
    Console.WriteLine($"before   {Describe(session, slot)}");

    var management = session.GetManagementKeyMetadata()!;
    session.AuthenticateManagementKey(ManagementKey.Default(management.Algorithm));

    try
    {
        session.DeleteKey(slot);
        Console.WriteLine("delete   accepted");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"delete   {ex.Message}");
    }

    Console.WriteLine($"after    {Describe(session, slot)}");
    return 0;
}

Console.Error.WriteLine($"Token {wanted} is not in any reader.");
return 1;

static string Describe(PivSession session, PivSlot slot)
{
    var metadata = session.GetSlotMetadata(slot);

    return metadata is null
        ? "no key"
        : $"{metadata.Algorithm}, pin={metadata.PinPolicy}, touch={metadata.TouchPolicy}";
}

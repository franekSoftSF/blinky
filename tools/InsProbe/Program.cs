// Blinky - instruction probe.
//
// Answers one question about a card: does it understand an instruction at all?
//
// The measurement that put INS 47 in the standard PIV table rather than the
// Yubico one came from here, and this tool is committed so that finding can be
// repeated rather than taken on trust. See docs/08-hardware-notes.md.
//
//     dotnet run --project tools/InsProbe
//
// Reading the result:
//
//     6D00   the card does not know this instruction
//     6982   it knows it, and wants the management key or a PIN first
//     6A80   it knows it, parsed the data, and rejected what was in it
//
// The control matters as much as the probe. INS 4E is not defined by anything,
// so whatever a card answers to that is what "I do not know this" looks like on
// that card. Without it, 6982 only means "not 6D00".

using Blinky.Piv;
using Blinky.Piv.Pcsc;

if (!PcscContext.IsSupported)
{
    Console.Error.WriteLine("Blinky.Piv talks to readers through winscard.dll; "
                            + "this build is Windows-only.");
    return 4;
}

// GENERATE ASYMMETRIC KEY PAIR, slot 9A, with algorithm identifier FF.
//
// FF IS DELIBERATE AND MUST STAY WRONG. No algorithm has that identifier, so
// nothing can be generated whatever the card decides about authorisation. Put
// a real algorithm here - 11 for ECC P-256, say - and this stops being a
// question and starts being a key on somebody's token, in a slot that may not
// have been empty.
var generateKeyPair = new ApduCommand(0x47, p1: 0x00, p2: 0x9A,
    data: new byte[] { 0xAC, 0x03, 0x80, 0x01, 0xFF }, le: 0);

// Defined by nobody. This is the control.
var undefined = new ApduCommand(0x4E, le: 0);

using var context = PcscContext.Establish();
var probed = 0;

Console.WriteLine("Blinky instruction probe - nothing is written\n");

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

    if (!session.Select())
    {
        continue;
    }

    var kind = session.IsYubiKey() ? "YubiKey" : "not a YubiKey";
    var generate = connection.Send(generateKeyPair).Status;
    var control = connection.Send(undefined).Status;

    Console.WriteLine(reader);
    Console.WriteLine($"    {kind,-14}  INS 47 -> {generate}   "
                      + $"INS 4E (control) -> {control}");

    probed++;
}

if (probed == 0)
{
    Console.WriteLine("No reader presented a card with a PIV applet.");
    return 3;
}

return 0;

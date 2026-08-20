// Blinky - asks a Bio Multi-protocol how its fingerprint verification is
// addressed, instead of assuming.
//
//     dotnet run --project tools/BioProbe                  read-only, free
//     dotnet run --project tools/BioProbe -- --match       one match, costs an attempt
//     dotnet run --project tools/BioProbe -- --temporary-pin
//
// Doc 03 records the temporary-PIN request encoding as unverified, and says why:
// finding out costs a match attempt and needs a finger on the sensor. There are
// three attempts before biometrics block - which is survivable, since a blocked
// fingerprint falls back to the PIN - but it is not something to spend by
// accident, so nothing here touches the sensor without being asked to.
//
// Eight of the eleven hardware findings in doc 08 came from asking the card
// rather than reasoning about it, and every one of them had a plausible wrong
// answer waiting. This is the same shape of question.

using Blinky.Piv;
using Blinky.Piv.Pcsc;

var match = args.Contains("--match");
var temporaryPin = args.Contains("--temporary-pin");

if (!PcscContext.IsSupported)
{
    Console.Error.WriteLine("This build talks to readers through winscard.dll.");
    return 2;
}

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

    if (!session.Select())
    {
        continue;
    }

    var serial = session.GetSerialNumber();
    var biometrics = session.GetBiometricMetadata();

    Console.WriteLine($"reader   {reader}");
    Console.WriteLine($"serial   {serial?.ToString() ?? "not a YubiKey"}");

    if (biometrics is null)
    {
        // Every non-Bio token answers slot 96 with 6A88. That is the detection.
        Console.WriteLine("bio      no on-card comparison (the card said so, not the model name)");
        Console.WriteLine();
        continue;
    }

    Console.WriteLine($"bio      enrolled={biometrics.FingerprintsEnrolled} "
                      + $"attempts={biometrics.AttemptsRemaining} "
                      + $"temporaryPin={biometrics.TemporaryPinSet}");
    Console.WriteLine();

    // Free: no data field, no attempt consumed. Already observed answering
    // 63C3 on this bench, and repeated here as the control - if this stops
    // reading the way doc 03 records, nothing below is trustworthy either.
    Report("VERIFY 96, no data (check only)", connection,
        new ApduCommand(0x20, p1: 0x00, p2: 0x96));

    if (!match && !temporaryPin)
    {
        Console.WriteLine();
        Console.WriteLine("Nothing else was sent. --match asks for a fingerprint and spends one");
        Console.WriteLine("of the attempts above; --temporary-pin does the same and asks the card");
        Console.WriteLine("for a temporary PIN as well.");
        Console.WriteLine();
        continue;
    }

    Console.WriteLine();
    Console.WriteLine(">>> put a finger on the sensor when it lights <<<");
    Console.WriteLine();

    if (match)
    {
        // The candidates, in the order they are worth trying. A card that does
        // not recognise an encoding answers 6A80 or 6A88 and consumes nothing,
        // so a wrong guess here is cheap; the expensive one is the one that
        // works and then waits for a finger.
        Report("VERIFY 96, empty TLV 03", connection,
            new ApduCommand(0x20, p1: 0x00, p2: 0x96, data: new byte[] { 0x03, 0x00 }));

        Report("VERIFY 96, single byte 00", connection,
            new ApduCommand(0x20, p1: 0x00, p2: 0x96, data: new byte[] { 0x00 }));
    }

    if (temporaryPin)
    {
        // Get one, then spend it. A match on its own returns 9000 and still
        // leaves a key refusing to sign with 6982 - observed on this bench -
        // so the temporary PIN is not a convenience for policy Always. It
        // looks like the mechanism by which a fingerprint satisfies a slot at
        // all, and this is the pair of calls that says so either way.
        var issued = connection.Send(new ApduCommand(0x20, p1: 0x00, p2: 0x96,
            data: new byte[] { 0x02, 0x00 }, le: 0));

        Console.WriteLine($"{"VERIFY 96, TLV 02 (get a temporary PIN)",-52} "
                          + $"SW={issued.Status.Value:X4}  {issued.Data.Length} bytes");

        if (issued.Data.Length > 0)
        {
            var temporary = issued.Data.ToArray();
            var use = new byte[2 + temporary.Length];
            use[0] = 0x01;
            use[1] = (byte)temporary.Length;
            temporary.CopyTo(use, 2);

            Report("VERIFY 96, TLV 01 + that value (spend it)", connection,
                new ApduCommand(0x20, p1: 0x00, p2: 0x96, data: use));

            Array.Clear(temporary);
            Array.Clear(use);
        }
    }

    Console.WriteLine();
}

return 0;

static void Report(string what, PivConnection connection, ApduCommand command)
{
    try
    {
        var response = connection.Send(command);

        var status = response.Status.Value;
        var retries = response.Status.RetriesLeft;

        // The length, never the value. A temporary PIN comes back in this
        // field, and a probe that prints it puts a live credential into a
        // terminal, a scrollback buffer and whatever captured the session -
        // which is the same rule that keeps serials out of the fixtures.
        Console.WriteLine($"{what,-52} SW={status:X4}"
                          + (retries is { } left ? $"  attempts={left}" : string.Empty)
                          + (response.Data.Length > 0
                              ? $"  {response.Data.Length} bytes returned (not printed)"
                              : string.Empty));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"{what,-52} threw: {ex.Message}");
    }
}

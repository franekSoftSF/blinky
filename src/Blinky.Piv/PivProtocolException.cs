namespace Blinky.Piv;

/// <summary>
/// The exchange itself was malformed - a response too short to hold a status
/// word, a transcript that ran out. Distinct from <see cref="PivException"/>,
/// which means the card understood the command and refused it.
/// </summary>
public sealed class PivProtocolException(string message) : Exception(message);

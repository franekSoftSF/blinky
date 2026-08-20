namespace Blinky.Piv.Attestation;

/// <summary>The physical shape of a token, as it attests to it.</summary>
public enum FormFactor : byte
{
    Unknown = 0x00,
    UsbAKeychain = 0x01,
    UsbANano = 0x02,
    UsbCKeychain = 0x03,
    UsbCNano = 0x04,
    UsbCLightning = 0x05,
    UsbABiometricKeychain = 0x06,
    UsbCBiometricKeychain = 0x07,
}

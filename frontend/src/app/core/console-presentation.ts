import { CredentialRow, SlotRow } from './console.store';

const formFactors: Record<string, { pl: string; en: string }> = {
  UsbAKeychain: { pl: 'USB-A, breloczek', en: 'USB-A keychain' },
  UsbANano: { pl: 'USB-A nano', en: 'USB-A nano' },
  UsbCKeychain: { pl: 'USB-C, breloczek', en: 'USB-C keychain' },
  UsbCNano: { pl: 'USB-C nano', en: 'USB-C nano' },
  UsbCLightning: { pl: 'USB-C / Lightning', en: 'USB-C / Lightning' },
  UsbABiometricKeychain: { pl: 'Bio, USB-A', en: 'Bio, USB-A' },
  UsbCBiometricKeychain: { pl: 'Bio, USB-C', en: 'Bio, USB-C' },
};
export function displayFormFactor(value: string | undefined, language: 'pl' | 'en'): string {
  return value
    ? (formFactors[value]?.[language] ?? value)
    : language === 'pl'
      ? 'Token PIV'
      : 'PIV token';
}
export function occupiedSlots(
  slots: SlotRow[],
  credentials: CredentialRow[],
  serial: number,
): SlotRow[] {
  const revoked = new Set(credentials.filter((c) => c.state === 'Revoked').map((c) => c.id));
  return slots.filter(
    (slot) =>
      slot.tokenSerial === serial &&
      slot.state !== 'Empty' &&
      !!slot.credentialId &&
      !revoked.has(slot.credentialId),
  );
}
export function jobResultMessage(result: string | null | undefined): string | null {
  if (!result) return null;
  try {
    const parsed = JSON.parse(result) as Record<string, unknown>;
    return String(parsed['message'] ?? parsed['error'] ?? parsed['detail'] ?? result);
  } catch {
    return result;
  }
}

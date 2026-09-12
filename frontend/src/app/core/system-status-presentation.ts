import { SecretsStatus, SystemStatus } from './console.store';
export type StatusTone = 'success' | 'warning' | 'danger' | 'neutral';
export function custodyTone(custody: SystemStatus['keyCustody']): StatusTone {
  return !custody ? 'neutral' : custody.productionReady ? 'success' : 'warning';
}
export function crlTone(crl: SystemStatus['revocationList']): StatusTone {
  return crl.expired ? 'danger' : crl.published ? 'success' : 'warning';
}
export function custodyLabel(custody: SystemStatus['keyCustody']): string {
  return !custody
    ? 'Zewnętrzny urząd certyfikacji'
    : custody.productionReady
      ? 'Gotowe produkcyjnie'
      : 'Odpowiednie dla laboratorium';
}

// Three states, because a provider holding configuration values has no device
// to ask. Answering "exportable" there is true and useless: it puts the
// strongest warning on this page onto the default arrangement, and makes the
// case that matters - a token holding a key it would hand out - look the same
// as an ordinary laboratory. Null is neutral; danger is reserved for a device
// that was asked and said yes.
export function secretExportTone(nonExportable: boolean | null): StatusTone {
  return nonExportable === null ? 'neutral' : nonExportable ? 'success' : 'danger';
}

export function secretExportLabel(
  nonExportable: boolean | null,
): 'secretsExportUnknown' | 'secretsProtected' | 'secretsExportable' {
  return nonExportable === null
    ? 'secretsExportUnknown'
    : nonExportable
      ? 'secretsProtected'
      : 'secretsExportable';
}
export function secretWriteKeyPresent(
  secrets: SecretsStatus,
  purpose: string,
  version: number,
): boolean {
  return secrets.keys.some((key) => key.purpose === purpose && key.version === version);
}

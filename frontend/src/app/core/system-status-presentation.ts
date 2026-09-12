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

export function secretExportTone(nonExportable: boolean): StatusTone {
  return nonExportable ? 'success' : 'danger';
}
export function secretWriteKeyPresent(
  secrets: SecretsStatus,
  purpose: string,
  version: number,
): boolean {
  return secrets.keys.some((key) => key.purpose === purpose && key.version === version);
}

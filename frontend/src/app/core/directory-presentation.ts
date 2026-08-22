import { DirectoryAccessResult } from './console.store';

export function parseAccounts(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((account) => account.trim())
    .filter(Boolean);
}
export function directoryAccessTone(
  result: DirectoryAccessResult,
): 'unknown' | 'extra' | 'readonly' {
  return !result.determined ? 'unknown' : result.anythingExtra ? 'extra' : 'readonly';
}
export function directoryAccessTitle(result: DirectoryAccessResult): string {
  return !result.determined
    ? 'Nie udało się określić'
    : result.anythingExtra
      ? 'Konto ma dodatkowe uprawnienia'
      : 'Tylko odczyt — dokładnie tyle dziś potrzeba';
}

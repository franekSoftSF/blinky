import { describe, expect, it } from 'vitest';
import { directoryAccessTitle, directoryAccessTone, parseAccounts } from './directory-presentation';
const access = (determined: boolean, anythingExtra: boolean) => ({
  subject: 'CN=Admin',
  determined,
  userCertificate: false,
  altSecurityIdentities: false,
  anythingExtra,
  detail: 'detail',
  wouldEnable: 'nothing',
});
describe('directory diagnostics presentation', () => {
  it('keeps an undetermined permission distinct from no permission', () => {
    expect(directoryAccessTone(access(false, false))).toBe('unknown');
    expect(directoryAccessTone(access(true, false))).toBe('readonly');
  });
  it('presents read-only access as the intended state', () =>
    expect(directoryAccessTitle(access(true, false))).toContain('dokładnie tyle'));
  it('accepts comma, semicolon and whitespace separated accounts', () =>
    expect(parseAccounts('admin, jkowalski; anna\npiotr')).toEqual([
      'admin',
      'jkowalski',
      'anna',
      'piotr',
    ]));
});

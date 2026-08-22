import { describe, expect, it } from 'vitest';
import { displayFormFactor, jobResultMessage, occupiedSlots } from './console-presentation';

describe('console presentation', () => {
  it('uses the physical slot state instead of credential history', () => {
    expect(
      occupiedSlots(
        [{ tokenSerial: 42, slotId: '9a', state: 'Empty', credentialId: 'old' }],
        [],
        42,
      ),
    ).toEqual([]);
    expect(
      occupiedSlots(
        [{ tokenSerial: 42, slotId: '9c', state: 'Occupied', credentialId: 'live' }],
        [],
        42,
      ),
    ).toHaveLength(1);
    expect(
      occupiedSlots(
        [{ tokenSerial: 42, slotId: '9d', state: 'Occupied', credentialId: 'revoked' }],
        [{ id: 'revoked', tokenSerial: 42, slotId: '9d', state: 'Revoked' }],
        42,
      ),
    ).toEqual([]);
  });
  it('uses the tray wording for form factors', () =>
    expect(displayFormFactor('UsbAKeychain', 'pl')).toBe('USB-A, breloczek'));
  it('extracts a useful failed job message', () =>
    expect(jobResultMessage('{"error":"card removed"}')).toBe('card removed'));
});

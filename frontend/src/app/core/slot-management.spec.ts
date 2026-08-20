import { describe, expect, it } from 'vitest';
import { slotManagementTone } from './slot-management';

describe('slot management presentation', () => {
  it('does not present an unreachable backend as a foreign credential', () => {
    expect(slotManagementTone('Unknown')).toBe('neutral');
    expect(slotManagementTone('Unknown')).not.toBe(slotManagementTone('Unmanaged'));
  });

  it('keeps managed, unmanaged and empty visually distinct', () => {
    expect(new Set([
      slotManagementTone('Managed'),
      slotManagementTone('Unmanaged'),
      slotManagementTone('Empty'),
    ]).size).toBe(3);
  });
});

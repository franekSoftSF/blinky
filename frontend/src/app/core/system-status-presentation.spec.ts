import { describe, expect, it } from 'vitest';
import { crlTone, custodyLabel, custodyTone } from './system-status-presentation';
describe('deployment status presentation', () => {
  it('presents file custody as guidance, not a failure', () => {
    const custody = {
      tier: 'File',
      description: 'File',
      productionReady: false,
      detail: 'lab',
      available: [],
    };
    expect(custodyTone(custody)).toBe('warning');
    expect(custodyLabel(custody)).toContain('laboratorium');
  });
  it('reserves danger for an expired revocation list', () => {
    expect(crlTone({ published: false, path: 'x', expired: false })).toBe('warning');
    expect(crlTone({ published: true, path: 'x', expired: true })).toBe('danger');
  });
});

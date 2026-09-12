import { describe, expect, it } from 'vitest';
import {
  crlTone,
  custodyLabel,
  custodyTone,
  secretExportLabel,
  secretExportTone,
} from './system-status-presentation';
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
  it('keeps the export alarm for a device that was asked and said yes', () => {
    // Null is a provider with no device to ask, and it must not look like a
    // token holding a key it would hand out. Answering danger for both put the
    // strongest warning on this page onto the default arrangement.
    expect(secretExportTone(null)).toBe('neutral');
    expect(secretExportLabel(null)).toBe('secretsExportUnknown');
    expect(secretExportTone(true)).toBe('success');
    expect(secretExportLabel(true)).toBe('secretsProtected');
    expect(secretExportTone(false)).toBe('danger');
    expect(secretExportLabel(false)).toBe('secretsExportable');
  });
});

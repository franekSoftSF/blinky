/**
 * Whether the certificate in a physical PIV slot belongs to Blinky.
 *
 * This must never become a boolean. Unknown commonly means that the agent
 * could not reach the backend, not that a foreign credential was discovered.
 */
export type SlotManagement = 'Managed' | 'Unmanaged' | 'Unknown' | 'Empty';
export type SlotManagementTone = 'success' | 'warning' | 'neutral' | 'muted';

export function slotManagementTone(state: SlotManagement): SlotManagementTone {
  switch (state) {
    case 'Managed': return 'success';
    case 'Unmanaged': return 'warning';
    case 'Unknown': return 'neutral';
    case 'Empty': return 'muted';
  }
}

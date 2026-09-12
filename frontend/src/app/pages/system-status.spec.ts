import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { ConsoleStore, SecretsStatus, SystemStatus } from '../core/console.store';
import { I18n } from '../core/i18n';
import { SystemStatusPage } from './system-status';

const secrets = (): SecretsStatus => ({
  provider: 'pkcs11',
  custody: {
    tier: 'Pkcs11',
    description: 'token',
    productionReady: false,
    detail: 'test provider',
  },
  writingWith: { managementKey: 2, pukKek: 2 },
  keys: [1, 2].map((version) => ({
    purpose: 'ManagementKeyMaster',
    version,
    label: 'master/v' + version,
    nonExportable: version === 2,
    usage:
      version === 1 ? null : { operations: 12, failures: 1, lastUsedAt: '2026-09-12T09:32:57Z' },
  })),
  managementKeyMasterConfigured: true,
  legacyPukEnvelopesReadable: false,
});

async function render(value: SecretsStatus | null | undefined, language: 'pl' | 'en' = 'en') {
  TestBed.configureTestingModule({
    providers: [
      {
        provide: ConsoleStore,
        useValue: {
          systemStatus: async () =>
            ({
              secrets: value,
              certificateAuthority: { name: 'CA', backend: 'builtin' },
              keyCustody: null,
              revocationList: { published: false, expired: false, path: '' },
              directory: { configured: false },
              agents: { total: 0, enrolled: 0 },
            }) as SystemStatus,
        },
      },
    ],
  });
  TestBed.inject(I18n).use(language);
  const fixture = TestBed.createComponent(SystemStatusPage);
  await fixture.whenStable();
  fixture.detectChanges();
  return fixture.nativeElement.querySelector('.secrets-panel') as HTMLElement;
}

describe('master secrets panel', () => {
  beforeEach(() => TestBed.resetTestingModule());
  it.each([null, undefined])('handles unavailable secrets %s', async (value) => {
    const panel = await render(value);
    expect(panel.textContent).toContain('Secrets information unavailable');
    expect(panel.querySelector('[data-tone="neutral"]')).toBeTruthy();
  });
  it('shows all generations, missing write key, extractability and process counters', async () => {
    const panel = await render(secrets());
    expect(panel.textContent).toContain('master/v1');
    expect(panel.textContent).toContain('master/v2');
    expect(panel.textContent).toContain('Unused since process start');
    expect(panel.textContent).toContain('reset when it restarts');
    expect(panel.textContent).toContain('Selected generation missing from provider');
    expect(panel.querySelector('[data-tone="danger"]')?.textContent).toContain('Exportable');
    expect(panel.textContent).toContain('Not production ready');
    expect(panel.textContent).toContain('Blinky:Puk:Kek');
    expect(panel.textContent).toContain('2026-09-12');
  });
  it('keeps factory management keys neutral and follows productionReady for configuration', async () => {
    const value = secrets();
    value.provider = 'configuration';
    value.managementKeyMasterConfigured = false;
    value.keys = [];
    value.legacyPukEnvelopesReadable = true;
    value.custody.productionReady = true;
    const panel = await render(value);
    expect(
      Array.from(panel.querySelectorAll('[data-tone="neutral"]')).some((el) =>
        el.textContent?.includes('factory management key'),
      ),
    ).toBe(true);
    expect(panel.querySelector('[data-tone="success"]')?.textContent).toContain('Production ready');
    expect(panel.textContent).toContain('Provider reported no keys');
  });
  it('renders Polish labels', async () => {
    const panel = await render(secrets(), 'pl');
    expect(panel.textContent).toContain('Sekrety główne');
    expect(panel.textContent).toContain('Nieużywany od uruchomienia procesu');
    expect(panel.textContent).toContain('Eksportowalny — niezabezpieczony');
  });
});

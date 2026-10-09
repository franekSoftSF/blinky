import { Component, computed, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { I18n } from '../core/i18n';
import { AuthStore } from '../core/auth.store';

type Backend = 'BuiltIn' | 'Adcs';

interface AdcsSettings {
  transport: string;
  caConfig: string | null;
  connectorUrl: string | null;
  serverFingerprint: string | null;
  clientCertificatePath: string | null;
  clientCertificatePasswordFile: string | null;
  timeoutSeconds: number;
  allowRevocation: boolean;
  keyAlgorithms: string[];
}

interface CaInstance {
  id: string;
  name: string;
  backend: Backend;
  isEnabled: boolean;
  isDefault: boolean;
  profiles: number;
  adcs: AdcsSettings | null;
  builtInDirectory: string | null;
}

interface Profile {
  id: string;
  name: string;
  description: string | null;
  caInstanceId: string;
  caInstanceName: string;
  backend: Backend;
  slotId: string;
  keyAlgorithm: string;
  validityDays: number;
  extendedKeyUsages: string[];
  includeUpnSan: boolean;
  includeSidExtension: boolean;
  adcsTemplateName: string | null;
  requiredPinPolicy: string | null;
  requiredTouchPolicy: string | null;
  isEnabled: boolean;
}

interface Choices {
  slots: string[];
  keyAlgorithms: string[];
  pinPolicies: string[];
  touchPolicies: string[];
}

interface CaDraft {
  name: string;
  backend: Backend;
  isEnabled: boolean;
  transport: string;
  caConfig: string;
  connectorUrl: string;
  serverFingerprint: string;
  clientCertificatePath: string;
  clientCertificatePasswordFile: string;
  allowRevocation: boolean;
  keyAlgorithms: string[];
  builtInDirectory: string;
}

interface ProfileDraft {
  name: string;
  description: string;
  caInstanceId: string;
  slotId: string;
  keyAlgorithm: string;
  validityDays: string;
  extendedKeyUsages: string;
  includeUpnSan: boolean;
  includeSidExtension: boolean;
  adcsTemplateName: string;
  requiredPinPolicy: string;
  requiredTouchPolicy: string;
  isEnabled: boolean;
}

/** The EKUs an operator reaches for, so nobody types an OID from memory. */
const KNOWN_EKUS: ReadonlyArray<{ oid: string; label: string }> = [
  { oid: '1.3.6.1.5.5.7.3.2', label: 'Client Authentication' },
  { oid: '1.3.6.1.4.1.311.20.2.2', label: 'Smart Card Logon' },
  { oid: '1.3.6.1.4.1.311.10.3.12', label: 'Document Signing' },
  { oid: '1.3.6.1.5.5.7.3.4', label: 'Secure Email (S/MIME)' },
];

const EMPTY_CA: CaDraft = {
  name: '', backend: 'Adcs', isEnabled: true, transport: 'ConnectorPolls', caConfig: '', connectorUrl: '',
  serverFingerprint: '', clientCertificatePath: '', clientCertificatePasswordFile: '', allowRevocation: true,
  keyAlgorithms: [], builtInDirectory: '',
};

const EMPTY_PROFILE: ProfileDraft = {
  name: '', description: '', caInstanceId: '', slotId: '9A', keyAlgorithm: 'Rsa2048', validityDays: '365',
  extendedKeyUsages: '1.3.6.1.5.5.7.3.2\n1.3.6.1.4.1.311.20.2.2', includeUpnSan: true, includeSidExtension: true,
  adcsTemplateName: '', requiredPinPolicy: '', requiredTouchPolicy: '', isEnabled: true,
};

/**
 * Certificate authorities and certificate profiles, as rows (0108).
 *
 * Until 0108 the CA was CA_BACKEND in the server's .env and the profiles were two
 * constants in the build: changing a template name, or the CA a connector asks, took
 * a shell on the server. Here it takes an administrator. A profile names its CA, its
 * template on a Microsoft CA, the slot, the key, and the PIN and touch policy the card
 * must attest - the last two checked before the CA is asked.
 */
@Component({
  selector: 'app-ca-profiles',
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">{{ i18n.t('administration') }}</p>
        <h1>{{ i18n.t('cpTitle') }}</h1>
        <p>{{ i18n.t('cpLede') }}</p>
      </div>
    </section>

    @if (!admin()) {
      <p class="notice">{{ i18n.t('cpAdminOnly') }}</p>
    }
    @if (message(); as text) {
      <p class="cp-message" role="status">{{ text }}</p>
    }
    @if (error(); as text) {
      <p class="inline-error cp-error" role="alert">{{ text }}</p>
    }

    <h2 class="cp-heading">{{ i18n.t('cpAuthorities') }}</h2>
    @for (ca of instances(); track ca.id) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">{{ ca.backend === 'Adcs' ? 'M' : 'B' }}</div>
          <div>
            <h2>{{ ca.name }}</h2>
            <p>
              {{ ca.backend === 'Adcs' ? i18n.t('cpAdcs') : i18n.t('cpBuiltIn') }} ·
              {{ ca.isEnabled ? i18n.t('ppEnabled') : i18n.t('ppDisabled') }} · {{ ca.profiles }} {{ i18n.t('cpProfilesCount') }}
            </p>
          </div>
          @if (ca.isDefault) {
            <span class="pill">{{ i18n.t('cpDefault') }}</span>
          }
        </header>
        <div class="setting-body cp-grid">
          @if (ca.adcs; as a) {
            <dl class="cp-facts">
              <dt>{{ i18n.t('cpTransport') }}</dt><dd>{{ a.transport }}</dd>
              <dt>{{ i18n.t('cpCaConfig') }}</dt><dd class="mono">{{ a.caConfig || i18n.t('cpLocalCa') }}</dd>
              @if (a.transport === 'Connector') {
                <dt>{{ i18n.t('cpConnectorUrl') }}</dt><dd class="mono">{{ a.connectorUrl }}</dd>
              }
              <dt>{{ i18n.t('cpAlgorithms') }}</dt><dd>{{ a.keyAlgorithms.join(', ') || i18n.t('cpAny') }}</dd>
              <dt>{{ i18n.t('cpRevocation') }}</dt><dd>{{ a.allowRevocation ? i18n.t('cpYes') : i18n.t('cpNo') }}</dd>
            </dl>
          } @else {
            <dl class="cp-facts">
              <dt>{{ i18n.t('cpDirectory') }}</dt><dd class="mono">{{ ca.builtInDirectory || '/etc/blinky/ca' }}</dd>
            </dl>
          }
          @if (tested()[ca.id]; as result) {
            <p class="cp-tested" [class.inline-error]="result.error">{{ result.text }}</p>
          }
          @if (admin()) {
            <div class="cp-actions">
              <button type="button" [disabled]="busy()" (click)="editCa(ca)">{{ i18n.t('ppEdit') }}</button>
              <button type="button" [disabled]="busy()" (click)="testCa(ca)">{{ i18n.t('cpTest') }}</button>
              <button class="row-action danger" type="button" [disabled]="busy() || ca.profiles > 0"
                      [title]="ca.profiles > 0 ? i18n.t('cpCaInUse') : ''" (click)="removeCa(ca)">
                {{ i18n.t('ppDelete') }}
              </button>
            </div>
          }
        </div>
      </article>
    } @empty {
      <article class="panel"><div class="empty"><span>◆</span><strong>{{ i18n.t('cpNoCa') }}</strong></div></article>
    }

    @if (admin()) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">{{ editingCa() ? '✎' : '+' }}</div>
          <div>
            <h2>{{ editingCa() ? i18n.t('ppEditing') + ' ' + ca().name : i18n.t('cpNewCa') }}</h2>
            <p>{{ i18n.t('cpNewCaLede') }}</p>
          </div>
        </header>
        <form class="probe-form cp-form" (submit)="saveCa($event)">
          <label>
            {{ i18n.t('cpBackend') }}
            <select name="backend" [value]="ca().backend" [disabled]="!!editingCa()" (change)="setCa('backend', value($event))">
              <option value="Adcs">{{ i18n.t('cpAdcs') }}</option>
              <option value="BuiltIn">{{ i18n.t('cpBuiltIn') }}</option>
            </select>
          </label>
          <label>
            {{ i18n.t('ppName') }}
            <input name="name" [value]="ca().name" placeholder="digitalworkspace" (input)="setCa('name', value($event))" />
          </label>
          @if (ca().backend === 'Adcs') {
            <label>
              {{ i18n.t('cpTransport') }}
              <select name="transport" [value]="ca().transport" (change)="setCa('transport', value($event))">
                <option value="ConnectorPolls">{{ i18n.t('cpPolls') }}</option>
                <option value="Connector">{{ i18n.t('cpListens') }}</option>
              </select>
            </label>
            <label>
              {{ i18n.t('cpCaConfig') }}
              <input name="caConfig" [value]="ca().caConfig" placeholder="SUBCA\\DigitalWorkspace Issuing CA - homelab"
                     (input)="setCa('caConfig', value($event))" />
            </label>
            @if (ca().transport === 'Connector') {
              <label>
                {{ i18n.t('cpConnectorUrl') }}
                <input name="url" [value]="ca().connectorUrl" placeholder="https://ca01.example:8444"
                       (input)="setCa('connectorUrl', value($event))" />
              </label>
              <label>
                {{ i18n.t('cpFingerprint') }}
                <input name="fingerprint" [value]="ca().serverFingerprint" (input)="setCa('serverFingerprint', value($event))" />
              </label>
              <label>
                {{ i18n.t('cpClientCert') }}
                <input name="clientCert" [value]="ca().clientCertificatePath" placeholder="/etc/blinky/certs/adcs-client.p12"
                       (input)="setCa('clientCertificatePath', value($event))" />
              </label>
              <label>
                {{ i18n.t('cpPasswordFile') }}
                <input name="passwordFile" [value]="ca().clientCertificatePasswordFile"
                       (input)="setCa('clientCertificatePasswordFile', value($event))" />
              </label>
            }
            <fieldset class="cp-checks">
              <legend>{{ i18n.t('cpAlgorithms') }}</legend>
              @for (alg of choices().keyAlgorithms; track alg) {
                <label class="pk-check">
                  <input type="checkbox" [checked]="ca().keyAlgorithms.includes(alg)" (change)="toggleAlgorithm(alg)" />
                  {{ alg }}
                </label>
              }
            </fieldset>
            <label class="pk-check">
              <input type="checkbox" [checked]="ca().allowRevocation" (change)="setCaFlag('allowRevocation', $event)" />
              {{ i18n.t('cpRevocation') }}
            </label>
          } @else {
            <label>
              {{ i18n.t('cpDirectory') }}
              <input name="directory" [value]="ca().builtInDirectory" placeholder="/etc/blinky/ca"
                     (input)="setCa('builtInDirectory', value($event))" />
            </label>
          }
          <label class="pk-check">
            <input type="checkbox" [checked]="ca().isEnabled" (change)="setCaFlag('isEnabled', $event)" />
            {{ i18n.t('ppEnabled') }}
          </label>
          <button class="primary" type="submit" [disabled]="busy()">{{ i18n.t('ppSave') }}</button>
          @if (editingCa()) {
            <button type="button" (click)="cancelCa()">{{ i18n.t('ppCancel') }}</button>
          }
        </form>
      </article>
    }

    <h2 class="cp-heading">{{ i18n.t('cpProfiles') }}</h2>
    <article class="panel">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{{ i18n.t('ppName') }}</th>
              <th>{{ i18n.t('cpCa') }}</th>
              <th>{{ i18n.t('cpTemplate') }}</th>
              <th>{{ i18n.t('cpSlot') }}</th>
              <th>{{ i18n.t('cpKey') }}</th>
              <th>{{ i18n.t('cpValidity') }}</th>
              <th>{{ i18n.t('status') }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (p of profiles(); track p.id) {
              <tr>
                <td>
                  <strong>{{ p.name }}</strong>
                  @if (p.description) {
                    <small class="block">{{ p.description }}</small>
                  }
                  <small class="block muted">{{ ekuLabels(p.extendedKeyUsages) }}</small>
                </td>
                <td>{{ p.caInstanceName }}</td>
                <td class="mono">{{ p.adcsTemplateName || '—' }}</td>
                <td>{{ p.slotId }}</td>
                <td>{{ p.keyAlgorithm }}</td>
                <td>{{ p.validityDays }} {{ i18n.t('days') }}</td>
                <td>
                  <em class="state" [attr.data-state]="p.isEnabled ? 'Issued' : 'Blocked'">
                    {{ p.isEnabled ? i18n.t('ppEnabled') : i18n.t('ppDisabled') }}
                  </em>
                </td>
                <td class="row-actions">
                  @if (admin()) {
                    <button class="row-action" type="button" [disabled]="busy()" (click)="editProfile(p)">{{ i18n.t('ppEdit') }}</button>
                    <button class="row-action danger" type="button" [disabled]="busy()" (click)="removeProfile(p)">
                      {{ i18n.t('ppDelete') }}
                    </button>
                  }
                </td>
              </tr>
            } @empty {
              <tr><td colspan="8">{{ i18n.t('cpNoProfiles') }}</td></tr>
            }
          </tbody>
        </table>
      </div>
    </article>

    @if (admin()) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">{{ editingProfile() ? '✎' : '+' }}</div>
          <div>
            <h2>{{ editingProfile() ? i18n.t('ppEditing') + ' ' + profile().name : i18n.t('cpNewProfile') }}</h2>
            <p>{{ i18n.t('cpNewProfileLede') }}</p>
          </div>
        </header>
        <form class="probe-form cp-form" (submit)="saveProfile($event)">
          <label>
            {{ i18n.t('ppName') }}
            <input name="name" [value]="profile().name" [readOnly]="!!editingProfile()" placeholder="podpis-dokumentow"
                   (input)="setProfile('name', value($event))" />
          </label>
          <label>
            {{ i18n.t('cpDescription') }}
            <input name="description" [value]="profile().description" (input)="setProfile('description', value($event))" />
          </label>
          <label>
            {{ i18n.t('cpCa') }}
            <select name="ca" [value]="profile().caInstanceId" (change)="setProfile('caInstanceId', value($event))">
              @for (ca of instances(); track ca.id) {
                <option [value]="ca.id">{{ ca.name }}</option>
              }
            </select>
          </label>
          @if (selectedCaIsAdcs()) {
            <label>
              {{ i18n.t('cpTemplate') }}
              <input name="template" [value]="profile().adcsTemplateName" placeholder="BlinkySmartCardLogon"
                     (input)="setProfile('adcsTemplateName', value($event))" />
            </label>
          }
          <label>
            {{ i18n.t('cpSlot') }}
            <select name="slot" [value]="profile().slotId" (change)="setProfile('slotId', value($event))">
              @for (slot of choices().slots; track slot) {
                <option [value]="slot">{{ slot }}</option>
              }
            </select>
          </label>
          <label>
            {{ i18n.t('cpKey') }}
            <select name="key" [value]="profile().keyAlgorithm" (change)="setProfile('keyAlgorithm', value($event))">
              @for (alg of choices().keyAlgorithms; track alg) {
                <option [value]="alg">{{ alg }}</option>
              }
            </select>
          </label>
          <label>
            {{ i18n.t('cpValidity') }}
            <input name="days" inputmode="numeric" [value]="profile().validityDays" (input)="setProfile('validityDays', value($event))" />
          </label>
          <label>
            {{ i18n.t('cpPinPolicy') }}
            <select name="pin" [value]="profile().requiredPinPolicy" (change)="setProfile('requiredPinPolicy', value($event))">
              <option value="">{{ i18n.t('cpAny') }}</option>
              @for (p of choices().pinPolicies; track p) {
                <option [value]="p">{{ p }}</option>
              }
            </select>
          </label>
          <label>
            {{ i18n.t('cpTouchPolicy') }}
            <select name="touch" [value]="profile().requiredTouchPolicy" (change)="setProfile('requiredTouchPolicy', value($event))">
              <option value="">{{ i18n.t('cpAny') }}</option>
              @for (p of choices().touchPolicies; track p) {
                <option [value]="p">{{ p }}</option>
              }
            </select>
          </label>
          <label class="cp-wide">
            {{ i18n.t('cpEkus') }}
            <textarea name="ekus" rows="3" spellcheck="false" [value]="profile().extendedKeyUsages"
                      (input)="setProfile('extendedKeyUsages', value($event))"></textarea>
            <span class="cp-presets">
              @for (eku of knownEkus; track eku.oid) {
                <button type="button" class="row-action" (click)="addEku(eku.oid)">+ {{ eku.label }}</button>
              }
            </span>
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="profile().includeUpnSan" (change)="setProfileFlag('includeUpnSan', $event)" />
            {{ i18n.t('cpUpn') }}
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="profile().includeSidExtension" (change)="setProfileFlag('includeSidExtension', $event)" />
            {{ i18n.t('cpSid') }}
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="profile().isEnabled" (change)="setProfileFlag('isEnabled', $event)" />
            {{ i18n.t('ppEnabled') }}
          </label>
          <button class="primary" type="submit" [disabled]="busy() || !instances().length">{{ i18n.t('ppSave') }}</button>
          @if (editingProfile()) {
            <button type="button" (click)="cancelProfile()">{{ i18n.t('ppCancel') }}</button>
          }
        </form>
      </article>
    }
  `,
  styles: [
    `
      .cp-heading {
        margin: 1.5rem 0 0.75rem;
        font-size: 1.05rem;
      }
      .cp-message {
        margin: 0 0 1rem;
        color: var(--bl-ok);
      }
      .cp-error {
        margin: 0 0 1rem;
      }
      .cp-grid {
        display: grid;
        gap: 12px;
      }
      .cp-facts {
        display: grid;
        grid-template-columns: max-content 1fr;
        gap: 6px 16px;
        margin: 0;
      }
      .cp-facts dt {
        color: var(--bl-text-muted);
        font-size: 13px;
      }
      .cp-facts dd {
        margin: 0;
        overflow-wrap: anywhere;
      }
      .cp-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .cp-tested {
        margin: 0;
        color: var(--bl-ok);
      }
      .cp-checks {
        display: flex;
        flex-wrap: wrap;
        gap: 4px 14px;
        border: 1px solid var(--bl-border);
        border-radius: 8px;
        padding: 6px 10px;
      }
      .cp-wide {
        grid-column: 1 / -1;
      }
      .cp-presets {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 6px;
      }
      .mono {
        font-family: Consolas, 'Cascadia Mono', monospace;
      }
    `,
  ],
})
export class CaProfiles {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthStore);
  protected readonly i18n = inject(I18n);

  protected readonly knownEkus = KNOWN_EKUS;
  protected readonly admin = computed(() => this.auth.role() === 'Administrator');
  protected readonly instances = signal<CaInstance[]>([]);
  protected readonly profiles = signal<Profile[]>([]);
  protected readonly choices = signal<Choices>({ slots: [], keyAlgorithms: [], pinPolicies: [], touchPolicies: [] });
  protected readonly busy = signal(false);
  protected readonly message = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly tested = signal<Record<string, { text: string; error: boolean }>>({});

  protected readonly ca = signal<CaDraft>({ ...EMPTY_CA });
  protected readonly editingCa = signal<string | null>(null);
  protected readonly profile = signal<ProfileDraft>({ ...EMPTY_PROFILE });
  protected readonly editingProfile = signal<string | null>(null);

  protected readonly selectedCaIsAdcs = computed(
    () => this.instances().find((c) => c.id === this.profile().caInstanceId)?.backend === 'Adcs',
  );

  constructor() {
    void this.load();
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  }

  protected ekuLabels(oids: string[]): string {
    return oids.map((o) => KNOWN_EKUS.find((k) => k.oid === o)?.label ?? o).join(', ');
  }

  protected async load(): Promise<void> {
    try {
      const [instances, catalogue] = await Promise.all([
        firstValueFrom(this.http.get<CaInstance[]>('/api/ca-instances')),
        firstValueFrom(this.http.get<{ profiles: Profile[]; choices: Choices }>('/api/certificate-profiles')),
      ]);
      this.instances.set(instances);
      this.profiles.set(catalogue.profiles);
      this.choices.set(catalogue.choices);
      if (!this.profile().caInstanceId && instances.length) {
        this.profile.update((d) => ({ ...d, caInstanceId: instances[0].id }));
      }
    } catch (e) {
      this.error.set(this.explain(e));
    }
  }

  // ------------------------------------------------------------------ CAs

  protected setCa(key: keyof CaDraft, value: string): void {
    this.ca.update((d) => ({ ...d, [key]: value }));
  }

  protected setCaFlag(key: 'isEnabled' | 'allowRevocation', event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.ca.update((d) => ({ ...d, [key]: checked }));
  }

  protected toggleAlgorithm(alg: string): void {
    this.ca.update((d) => ({
      ...d,
      keyAlgorithms: d.keyAlgorithms.includes(alg) ? d.keyAlgorithms.filter((a) => a !== alg) : [...d.keyAlgorithms, alg],
    }));
  }

  protected editCa(ca: CaInstance): void {
    const a = ca.adcs;
    this.editingCa.set(ca.id);
    this.ca.set({
      name: ca.name,
      backend: ca.backend,
      isEnabled: ca.isEnabled,
      transport: a?.transport ?? 'ConnectorPolls',
      caConfig: a?.caConfig ?? '',
      connectorUrl: a?.connectorUrl ?? '',
      serverFingerprint: a?.serverFingerprint ?? '',
      clientCertificatePath: a?.clientCertificatePath ?? '',
      clientCertificatePasswordFile: a?.clientCertificatePasswordFile ?? '',
      allowRevocation: a?.allowRevocation ?? true,
      keyAlgorithms: [...(a?.keyAlgorithms ?? [])],
      builtInDirectory: ca.builtInDirectory ?? '',
    });
  }

  protected cancelCa(): void {
    this.editingCa.set(null);
    this.ca.set({ ...EMPTY_CA });
  }

  protected async saveCa(event: Event): Promise<void> {
    event.preventDefault();
    const d = this.ca();
    const body = {
      name: d.name,
      backend: d.backend,
      isEnabled: d.isEnabled,
      builtInDirectory: d.builtInDirectory || null,
      adcs:
        d.backend === 'Adcs'
          ? {
              transport: d.transport,
              caConfig: d.caConfig || null,
              connectorUrl: d.connectorUrl || null,
              serverFingerprint: d.serverFingerprint || null,
              clientCertificatePath: d.clientCertificatePath || null,
              clientCertificatePasswordFile: d.clientCertificatePasswordFile || null,
              timeoutSeconds: null,
              allowRevocation: d.allowRevocation,
              keyAlgorithms: d.keyAlgorithms,
            }
          : null,
    };
    const id = this.editingCa();
    await this.run(
      () =>
        firstValueFrom(
          id ? this.http.put(`/api/ca-instances/${id}`, body) : this.http.post('/api/ca-instances', body),
        ),
      this.i18n.t('cpSaved'),
    );
    if (!this.error()) this.cancelCa();
  }

  protected async testCa(ca: CaInstance): Promise<void> {
    this.busy.set(true);
    try {
      const result = await firstValueFrom(
        this.http.post<{ backend: string; canIssueLogonCredentials: boolean; algorithms: string[] }>(
          `/api/ca-instances/${ca.id}/test`,
          {},
        ),
      );
      this.tested.update((t) => ({
        ...t,
        [ca.id]: {
          text: `${this.i18n.t('cpTestOk')} ${result.algorithms.join(', ')}${result.canIssueLogonCredentials ? ' · logon' : ''}`,
          error: false,
        },
      }));
    } catch (e) {
      this.tested.update((t) => ({ ...t, [ca.id]: { text: this.explain(e), error: true } }));
    } finally {
      this.busy.set(false);
    }
  }

  protected async removeCa(ca: CaInstance): Promise<void> {
    if (!confirm(`${this.i18n.t('cpConfirmDelete')} ${ca.name}?`)) return;
    await this.run(() => firstValueFrom(this.http.delete(`/api/ca-instances/${ca.id}`)), this.i18n.t('cpDeleted'));
  }

  // ------------------------------------------------------------------ profiles

  protected setProfile(key: keyof ProfileDraft, value: string): void {
    this.profile.update((d) => ({ ...d, [key]: value }));
  }

  protected setProfileFlag(key: 'includeUpnSan' | 'includeSidExtension' | 'isEnabled', event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.profile.update((d) => ({ ...d, [key]: checked }));
  }

  protected addEku(oid: string): void {
    this.profile.update((d) => {
      const lines = d.extendedKeyUsages.split('\n').map((l) => l.trim()).filter(Boolean);
      return lines.includes(oid) ? d : { ...d, extendedKeyUsages: [...lines, oid].join('\n') };
    });
  }

  protected editProfile(p: Profile): void {
    this.editingProfile.set(p.id);
    this.profile.set({
      name: p.name,
      description: p.description ?? '',
      caInstanceId: p.caInstanceId,
      slotId: p.slotId,
      keyAlgorithm: p.keyAlgorithm,
      validityDays: String(p.validityDays),
      extendedKeyUsages: p.extendedKeyUsages.join('\n'),
      includeUpnSan: p.includeUpnSan,
      includeSidExtension: p.includeSidExtension,
      adcsTemplateName: p.adcsTemplateName ?? '',
      requiredPinPolicy: p.requiredPinPolicy ?? '',
      requiredTouchPolicy: p.requiredTouchPolicy ?? '',
      isEnabled: p.isEnabled,
    });
  }

  protected cancelProfile(): void {
    this.editingProfile.set(null);
    this.profile.set({ ...EMPTY_PROFILE, caInstanceId: this.instances()[0]?.id ?? '' });
  }

  protected async saveProfile(event: Event): Promise<void> {
    event.preventDefault();
    const d = this.profile();
    const body = {
      name: d.name,
      description: d.description || null,
      caInstanceId: d.caInstanceId,
      slotId: d.slotId,
      keyAlgorithm: d.keyAlgorithm,
      validityDays: Number(d.validityDays),
      extendedKeyUsages: d.extendedKeyUsages.split('\n').map((l) => l.trim()).filter(Boolean),
      includeUpnSan: d.includeUpnSan,
      includeSidExtension: d.includeSidExtension,
      adcsTemplateName: this.selectedCaIsAdcs() ? d.adcsTemplateName || null : null,
      requiredPinPolicy: d.requiredPinPolicy || null,
      requiredTouchPolicy: d.requiredTouchPolicy || null,
      isEnabled: d.isEnabled,
    };
    const id = this.editingProfile();
    await this.run(
      () =>
        firstValueFrom(
          id
            ? this.http.put(`/api/certificate-profiles/${id}`, body)
            : this.http.post('/api/certificate-profiles', body),
        ),
      this.i18n.t('cpSaved'),
    );
    if (!this.error()) this.cancelProfile();
  }

  protected async removeProfile(p: Profile): Promise<void> {
    if (!confirm(`${this.i18n.t('cpConfirmDelete')} ${p.name}?`)) return;
    await this.run(() => firstValueFrom(this.http.delete(`/api/certificate-profiles/${p.id}`)), this.i18n.t('cpDeleted'));
  }

  // ------------------------------------------------------------------ shared

  private async run(action: () => Promise<unknown>, success: string): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      this.message.set(success);
      await this.load();
    } catch (e) {
      this.error.set(this.explain(e));
    } finally {
      this.busy.set(false);
    }
  }

  /** The server's sentence - which rule refused, said by the rule - rather than a status code. */
  private explain(e: unknown): string {
    if (e instanceof HttpErrorResponse) {
      const body = e.error as { error?: string } | null;
      return body?.error ?? `${e.status} ${e.statusText}`;
    }
    return e instanceof Error ? e.message : String(e);
  }
}

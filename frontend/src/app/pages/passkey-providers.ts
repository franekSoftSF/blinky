import { Component, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { firstValueFrom } from 'rxjs';
import { I18n } from '../core/i18n';
import { AuthStore } from '../core/auth.store';

type Kind = 'Entra' | 'Okta';
type CredentialKind = 'Certificate' | 'ClientSecret' | 'PrivateKey' | 'ApiToken';

interface Provider {
  id: string;
  name: string;
  kind: Kind;
  isEnabled: boolean;
  tenantId: string | null;
  clientId: string | null;
  orgUrl: string | null;
  keyId: string | null;
  authority: string | null;
  graphUrl: string | null;
  challengeMinutes: number;
  credentialKind: CredentialKind | null;
  credentialSet: boolean;
  credentialHint: string | null;
  publicMaterial: string | null;
  credentialExpiresAt: string | null;
  credentialSetAt: string | null;
  credentialSetBy: string | null;
  hasRegisteredPasskeys: boolean;
  problem: string | null;
}

interface Draft {
  name: string;
  kind: Kind;
  isEnabled: boolean;
  tenantId: string;
  clientId: string;
  orgUrl: string;
  keyId: string;
  challengeMinutes: string;
  secretValue: string;
  secretId: string;
  secretExpires: string;
}

const EMPTY: Draft = {
  name: '', kind: 'Entra', isEnabled: true, tenantId: '', clientId: '', orgUrl: '', keyId: '', challengeMinutes: '10',
  secretValue: '', secretId: '', secretExpires: '',
};

/**
 * Passkey providers: where a passkey is registered, configured here and kept in
 * the database (0107) - never in the server's .env.
 *
 * The credential Blinky reaches the provider with is generated on the server by
 * default: the key is made and sealed there, and this page shows only its public
 * half - the certificate to upload to the Entra app, the JWK to add to the Okta
 * service app. Importing one is possible and goes one way: it is sealed on
 * arrival and never sent back.
 */
@Component({
  selector: 'app-passkey-providers',
  imports: [DatePipe],
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">{{ i18n.t('administration') }}</p>
        <h1>{{ i18n.t('pkProviders') }}</h1>
        <p>{{ i18n.t('ppLede') }}</p>
      </div>
    </section>

    @if (!admin()) {
      <p class="notice">{{ i18n.t('ppAdminOnly') }}</p>
    }

    @if (message(); as text) {
      <p class="pp-message" role="status">{{ text }}</p>
    }
    @if (error(); as text) {
      <p class="inline-error pp-error" role="alert">{{ text }}</p>
    }

    @for (p of providers(); track p.id) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">{{ p.kind === 'Entra' ? 'E' : 'O' }}</div>
          <div>
            <h2>{{ p.name }}</h2>
            <p>{{ p.kind === 'Entra' ? 'Microsoft Entra ID' : 'Okta' }} · {{ p.isEnabled ? i18n.t('ppEnabled') : i18n.t('ppDisabled') }}</p>
          </div>
          @if (p.problem) {
            <span class="pk-drift pp-problem">{{ i18n.t('ppNotUsable') }}</span>
          } @else if (p.isEnabled && p.credentialSet) {
            <span class="pill">{{ i18n.t('ppReady') }}</span>
          }
        </header>

        <div class="setting-body pp-grid">
          <dl class="pp-facts">
            @if (p.kind === 'Entra') {
              <dt>{{ i18n.t('ppTenant') }}</dt><dd>{{ p.tenantId }}</dd>
              <dt>{{ i18n.t('ppClient') }}</dt><dd class="mono">{{ p.clientId }}</dd>
            } @else {
              <dt>{{ i18n.t('ppOrg') }}</dt><dd>{{ p.orgUrl }}</dd>
              <dt>{{ i18n.t('ppClient') }}</dt><dd class="mono">{{ p.clientId || '—' }}</dd>
              <dt>kid</dt><dd class="mono">{{ p.keyId || '—' }}</dd>
            }
            <dt>{{ i18n.t('ppChallenge') }}</dt><dd>{{ p.challengeMinutes }} min</dd>
            <dt>{{ i18n.t('ppCredential') }}</dt>
            <dd>
              @if (p.credentialSet) {
                {{ credentialLabel(p.credentialKind) }} ·
                @if (p.credentialHint === 'set') { {{ i18n.t('ppSecretSet') }} } @else { <span class="mono">{{ p.credentialHint }}</span> }
                @if (p.credentialExpiresAt) {
                  · <span [class.warning-text]="expiresSoon(p)">{{ i18n.t('ppExpires') }} {{ p.credentialExpiresAt | date: 'mediumDate' }}</span>
                }
                <small class="block muted">{{ p.credentialSetBy }}, {{ p.credentialSetAt | date: 'short' }}</small>
              } @else {
                <span class="warning-text">{{ i18n.t('ppNoCredential') }}</span>
              }
            </dd>
          </dl>

          @if (p.problem) {
            <p class="inline-error pp-inline">{{ p.problem }}</p>
          }

          @if (p.publicMaterial) {
            <details class="pp-public">
              <summary>{{ p.kind === 'Entra' ? i18n.t('ppPublicEntra') : i18n.t('ppPublicOkta') }}</summary>
              <pre>{{ p.publicMaterial }}</pre>
              <button type="button" (click)="copy(p.publicMaterial)">{{ i18n.t('ppCopy') }}</button>
            </details>
          }

          @if (admin()) {
            <div class="pp-actions">
              <button type="button" [disabled]="busy()" (click)="edit(p)">{{ i18n.t('ppEdit') }}</button>
              <button type="button" [disabled]="busy()" (click)="generate(p)">{{ i18n.t('ppGenerate') }}</button>
              <button type="button" [disabled]="busy()" (click)="openImport(p)">
                {{ i18n.t('ppImport') }}
              </button>
              <button type="button" [disabled]="busy() || !p.credentialSet" (click)="test(p)">{{ i18n.t('ppTest') }}</button>
              <button class="row-action danger" type="button" [disabled]="busy() || p.hasRegisteredPasskeys"
                      [title]="p.hasRegisteredPasskeys ? i18n.t('ppInUse') : ''" (click)="remove(p)">
                {{ i18n.t('ppDelete') }}
              </button>
            </div>
          }

          @if (importing() === p.id) {
            <form class="pp-import" (submit)="importCredential($event, p)">
              <label>
                {{ i18n.t('ppCredentialKind') }}
                <select name="kind" [value]="importKind()" (change)="importKind.set($any(value($event)))">
                  @if (p.kind === 'Entra') {
                    <option value="Certificate">{{ credentialLabel('Certificate') }}</option>
                    <option value="ClientSecret">{{ credentialLabel('ClientSecret') }}</option>
                  } @else {
                    <option value="PrivateKey">{{ credentialLabel('PrivateKey') }}</option>
                    <option value="ApiToken">{{ credentialLabel('ApiToken') }}</option>
                  }
                </select>
              </label>
              <label>
                {{ i18n.t('ppCredentialValue') }}
                <textarea name="value" rows="5" spellcheck="false" autocomplete="off"
                          [value]="importValue()" (input)="importValue.set(value($event))"></textarea>
              </label>
              @if (importKind() === 'Certificate') {
                <label>
                  {{ i18n.t('ppPfxPassword') }}
                  <input name="password" type="password" autocomplete="off"
                         [value]="importPassword()" (input)="importPassword.set(value($event))" />
                </label>
              }
              <button class="primary" type="submit" [disabled]="busy() || !importValue().trim()">{{ i18n.t('ppSave') }}</button>
            </form>
          }
        </div>
      </article>
    } @empty {
      <article class="panel">
        <div class="empty">
          <span>⚿</span>
          <strong>{{ i18n.t('ppNone') }}</strong>
          <p>{{ i18n.t('ppNoneLede') }}</p>
        </div>
      </article>
    }

    @if (admin()) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">{{ editing() ? '✎' : '+' }}</div>
          <div>
            <h2>{{ editing() ? i18n.t('ppEditing') + ' ' + draft().name : i18n.t('ppNew') }}</h2>
            <p>{{ i18n.t('ppNewLede') }}</p>
          </div>
        </header>
        <form class="probe-form pk-form" (submit)="save($event)">
          <label>
            {{ i18n.t('ppKind') }}
            <select name="kind" [value]="draft().kind" [disabled]="!!editing()" (change)="set('kind', value($event))">
              <option value="Entra">Microsoft Entra ID</option>
              <option value="Okta">Okta</option>
            </select>
          </label>
          <label>
            {{ i18n.t('ppName') }}
            <input name="name" [value]="draft().name" [readOnly]="!!editing()" placeholder="entra-prod"
                   (input)="set('name', value($event))" />
          </label>
          @if (draft().kind === 'Entra') {
            <label>
              {{ i18n.t('ppTenant') }}
              <input name="tenant" [value]="draft().tenantId" (input)="set('tenantId', value($event))" />
            </label>
            <label>
              {{ i18n.t('ppClient') }}
              <input name="client" [value]="draft().clientId" (input)="set('clientId', value($event))" />
            </label>
            <!-- The three fields Entra shows under Certificates & secrets. The
                 value is sent once and sealed; leaving it blank on an edit keeps
                 the secret that is there. -->
            <label>
              {{ i18n.t('ppSecretValue') }}
              <input name="secretValue" type="password" autocomplete="off" [value]="draft().secretValue"
                     [placeholder]="editing() ? i18n.t('ppSecretKeep') : ''" (input)="set('secretValue', value($event))" />
            </label>
            <label>
              {{ i18n.t('ppSecretId') }}
              <input name="secretId" autocomplete="off" [value]="draft().secretId" (input)="set('secretId', value($event))" />
            </label>
            <label>
              {{ i18n.t('ppSecretExpires') }}
              <input name="secretExpires" type="date" [value]="draft().secretExpires"
                     (input)="set('secretExpires', value($event))" />
            </label>
          } @else {
            <label>
              {{ i18n.t('ppOrg') }}
              <input name="org" [value]="draft().orgUrl" placeholder="https://acme.okta.com"
                     (input)="set('orgUrl', value($event))" />
            </label>
            <label>
              {{ i18n.t('ppClient') }}
              <input name="client" [value]="draft().clientId" (input)="set('clientId', value($event))" />
            </label>
          }
          <label>
            {{ i18n.t('ppChallenge') }}
            <input name="minutes" inputmode="numeric" [value]="draft().challengeMinutes"
                   (input)="set('challengeMinutes', value($event))" />
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="draft().isEnabled" (change)="setEnabled($event)" />
            {{ i18n.t('ppEnabled') }}
          </label>
          <button class="primary" type="submit" [disabled]="busy()">{{ i18n.t('ppSave') }}</button>
          @if (editing()) {
            <button type="button" (click)="cancel()">{{ i18n.t('ppCancel') }}</button>
          }
        </form>
        @if (draft().kind === 'Entra') {
          <div class="setting-body pp-help">
            <h3>{{ i18n.t('ppEntraHelp') }}</h3>
            <ol>
              <li>{{ i18n.t('ppEntraStep1') }}</li>
              <li>{{ i18n.t('ppEntraStep2') }} <code>UserAuthenticationMethod.ReadWrite.All</code>, <code>User.Read.All</code> — {{ i18n.t('ppEntraStep2b') }}</li>
              <li>{{ i18n.t('ppEntraStep3') }}</li>
              <li>{{ i18n.t('ppEntraStep4') }}</li>
            </ol>
          </div>
        }
      </article>
    }
  `,
  styles: [
    `
      .pp-help {
        border-top: 1px solid var(--bl-border);
      }
      .pp-help ol {
        margin: 0.5rem 0 0;
        padding-left: 1.2rem;
        display: grid;
        gap: 6px;
        color: var(--bl-text-body);
        font-size: 13px;
      }
      .pp-help code {
        font-family: Consolas, 'Cascadia Mono', monospace;
        color: var(--bl-accent-text);
      }
      .pp-message {
        margin: 0 0 1rem;
        color: var(--bl-ok);
      }
      .pp-error {
        margin: 0 0 1rem;
      }
      .pp-grid {
        display: grid;
        gap: 12px;
      }
      .pp-facts {
        display: grid;
        grid-template-columns: max-content 1fr;
        gap: 6px 16px;
        margin: 0;
      }
      .pp-facts dt {
        color: var(--bl-text-muted);
        font-size: 13px;
      }
      .pp-facts dd {
        margin: 0;
        overflow-wrap: anywhere;
      }
      .pp-inline {
        margin: 0;
      }
      .pp-public pre {
        margin: 8px 0;
        padding: 10px 12px;
        max-height: 220px;
        overflow: auto;
        background: var(--bl-background);
        border: 1px solid var(--bl-border);
        border-radius: 8px;
        font-size: 12px;
      }
      .pp-public summary {
        cursor: pointer;
        color: var(--bl-accent-text);
      }
      .pp-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .pp-import {
        display: grid;
        gap: 10px;
        max-width: 640px;
      }
      .pp-import label {
        display: grid;
        gap: 6px;
        color: var(--bl-text-muted);
        font-size: 13px;
      }
      .pp-import textarea {
        font-family: Consolas, 'Cascadia Mono', monospace;
        font-size: 12px;
      }
      .pk-form {
        flex-wrap: wrap;
      }
      .pk-form label {
        flex: 1 1 200px;
      }
      .pk-form input,
      .pk-form select {
        min-width: 0;
        width: 100%;
      }
      .pk-form label.pk-check {
        flex: 0 1 auto;
        flex-direction: row;
        align-items: center;
        gap: 8px;
        color: var(--bl-text);
      }
      .pk-form label.pk-check input {
        width: auto;
      }
      .pk-drift {
        display: inline-flex;
        padding: 2px 8px;
        border: 1px solid var(--bl-danger-border);
        border-radius: 6px;
        background: var(--bl-danger-soft);
        color: var(--bl-danger);
        font-size: 13px;
        font-weight: 600;
      }
      .warning-text {
        color: var(--bl-warning);
      }
      .mono {
        font-family: Consolas, 'Cascadia Mono', monospace;
        font-size: 13px;
      }
      .block {
        display: block;
      }
    `,
  ],
})
export class PasskeyProviders {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthStore);
  protected readonly i18n = inject(I18n);

  protected readonly providers = signal<Provider[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly message = signal<string | null>(null);

  protected readonly draft = signal<Draft>({ ...EMPTY });
  protected readonly editing = signal<string | null>(null);

  protected readonly importing = signal<string | null>(null);
  protected readonly importKind = signal<CredentialKind>('Certificate');
  protected readonly importValue = signal('');
  protected readonly importPassword = signal('');

  protected readonly admin = computed(() => this.auth.role() === 'Administrator');

  constructor() {
    void this.load();
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  }

  protected set(field: keyof Draft, value: string): void {
    this.draft.update((d) => ({ ...d, [field]: value }));
  }

  protected setEnabled(event: Event): void {
    const enabled = (event.target as HTMLInputElement).checked;
    this.draft.update((d) => ({ ...d, isEnabled: enabled }));
  }

  /** Thirty days out: long enough to make a new secret in the portal before this one stops. */
  protected expiresSoon(p: Provider): boolean {
    return !!p.credentialExpiresAt && new Date(p.credentialExpiresAt).getTime() - Date.now() < 30 * 86_400_000;
  }

  protected credentialLabel(kind: CredentialKind | null): string {
    switch (kind) {
      case 'Certificate': return this.i18n.t('ppCertificate');
      case 'ClientSecret': return this.i18n.t('ppClientSecret');
      case 'PrivateKey': return this.i18n.t('ppPrivateKey');
      case 'ApiToken': return this.i18n.t('ppApiToken');
      default: return '—';
    }
  }

  protected openImport(p: Provider): void {
    this.importing.set(this.importing() === p.id ? null : p.id);
    this.importKind.set(p.kind === 'Entra' ? 'Certificate' : 'PrivateKey');
    this.importValue.set('');
    this.importPassword.set('');
  }

  protected edit(p: Provider): void {
    this.editing.set(p.id);
    this.draft.set({
      name: p.name, kind: p.kind, isEnabled: p.isEnabled, tenantId: p.tenantId ?? '', clientId: p.clientId ?? '',
      orgUrl: p.orgUrl ?? '', keyId: p.keyId ?? '', challengeMinutes: String(p.challengeMinutes),
      secretValue: '', secretId: '', secretExpires: '',
    });
  }

  protected cancel(): void {
    this.editing.set(null);
    this.draft.set({ ...EMPTY });
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    const d = this.draft();
    const body = {
      name: d.name.trim(),
      kind: d.kind,
      isEnabled: d.isEnabled,
      tenantId: d.tenantId,
      clientId: d.clientId,
      orgUrl: d.orgUrl,
      keyId: d.keyId,
      challengeMinutes: Number.parseInt(d.challengeMinutes, 10) || 10,
    };
    const id = this.editing();

    await this.run(async () => {
      const saved = id
        ? await firstValueFrom(this.http.put<Provider>(`/api/passkeys/providers/${id}`, body))
        : await firstValueFrom(this.http.post<Provider>('/api/passkeys/providers', body));

      // The secret goes in its own request, to the route that seals it, and the
      // field is emptied as soon as that has answered.
      if (d.kind === 'Entra' && d.secretValue.trim()) {
        await firstValueFrom(this.http.post(`/api/passkeys/providers/${saved.id}/credential`, {
          kind: 'ClientSecret',
          value: d.secretValue,
          label: d.secretId.trim() || null,
          expiresAt: d.secretExpires ? `${d.secretExpires}T00:00:00Z` : null,
        }));
      }

      this.cancel();
      return this.i18n.t('ppSaved');
    });
  }

  protected async generate(p: Provider): Promise<void> {
    if (p.credentialSet && !window.confirm(this.i18n.t('ppReplaceConfirm'))) return;

    await this.run(async () => {
      await firstValueFrom(this.http.post(`/api/passkeys/providers/${p.id}/generate-credential`, {}));
      return p.kind === 'Entra' ? this.i18n.t('ppGeneratedEntra') : this.i18n.t('ppGeneratedOkta');
    });
  }

  protected async importCredential(event: Event, p: Provider): Promise<void> {
    event.preventDefault();

    await this.run(async () => {
      await firstValueFrom(this.http.post(`/api/passkeys/providers/${p.id}/credential`, {
        kind: this.importKind(),
        value: this.importValue(),
        password: this.importPassword() || null,
      }));

      // Gone from the page as soon as the server has it.
      this.importValue.set('');
      this.importPassword.set('');
      this.importing.set(null);
      return this.i18n.t('ppImported');
    });
  }

  protected async test(p: Provider): Promise<void> {
    await this.run(async () => {
      const answer = await firstValueFrom(
        this.http.post<{ message: string }>(`/api/passkeys/providers/${p.id}/test`, {}));
      return answer.message;
    });
  }

  protected async remove(p: Provider): Promise<void> {
    if (!window.confirm(this.i18n.t('ppDeleteConfirm'))) return;

    await this.run(async () => {
      await firstValueFrom(this.http.delete(`/api/passkeys/providers/${p.id}`));
      return this.i18n.t('ppDeleted');
    });
  }

  protected async copy(text: string): Promise<void> {
    await navigator.clipboard.writeText(text);
    this.message.set(this.i18n.t('ppCopied'));
  }

  private async load(): Promise<void> {
    try {
      this.providers.set(await firstValueFrom(this.http.get<Provider[]>('/api/passkeys/providers')));
    } catch (error) {
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    }
  }

  private async run(action: () => Promise<string>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);

    try {
      this.message.set(await action());
      await this.load();
    } catch (error) {
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    } finally {
      this.busy.set(false);
    }
  }
}

function describe(error: unknown, fallback: string): string {
  const body = (error as { error?: { error?: string } })?.error;

  return body?.error ?? fallback;
}

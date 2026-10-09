import { Component, OnDestroy, computed, inject, signal, viewChild } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { firstValueFrom } from 'rxjs';
import { I18n, MessageKey } from '../core/i18n';
import { ConsoleStore } from '../core/console.store';
import { EnrolDialog } from '../enrol/enrol-dialog';

interface Capabilities {
  supportsRegistration: boolean;
  prepareOnly: boolean;
  pinDeliveryByProvider: boolean;
  acceptsDisplayName: boolean;
  maxDisplayNameLength: number | null;
}

interface Directories {
  directories: { name: string; capabilities: Capabilities }[];
  analysisOnly: { name: string; reason: string }[];
}

interface ProviderUser {
  id: string;
  login: string;
  displayName: string;
  email: string;
}

type Drift = 'InSync' | 'MissingAtProvider' | 'StillAtProvider' | 'ProviderOnly';

interface Listing {
  id: string | null;
  methodId: string | null;
  name: string | null;
  state: string | null;
  tokenSerial: number | null;
  aaguid: string | null;
  createdAt: string | null;
  drift: Drift;
  providerStatus: string | null;
}

interface Status {
  id: string;
  directory: string;
  login: string;
  state: string;
  jobState: string | null;
  tokenSerial: number | null;
  keyName: string | null;
  pinSetByAgent: boolean;
  methodId: string | null;
  failureReason: string | null;
  registeredAt: string | null;
}

/** The ceremony's steps as the row's states say them, in order. */
const STEPS: { state: string; label: MessageKey }[] = [
  { state: 'Requested', label: 'pkStepRequested' },
  { state: 'KeyReady', label: 'pkStepKeyReady' },
  { state: 'ChallengeIssued', label: 'pkStepChallenge' },
  { state: 'Provisioned', label: 'pkStepProvisioned' },
  { state: 'Registered', label: 'pkStepRegistered' },
];

const FINAL = ['Registered', 'Failed', 'Revoked'];

/**
 * Passkeys: a FIDO2 credential registered at Entra or Okta on somebody's behalf,
 * on a key plugged into a workstation (0078).
 *
 * The console never sees a PIN. A provisional one is generated on the
 * workstation and shown there, in the agent's window, once - the API has no
 * field for it (0074) and so neither does this page; what it can say is whether
 * one was set.
 *
 * The list is the database and the provider side by side. Where they disagree it
 * says so and does not choose: a method deleted at the provider, or a key the
 * user enrolled alone, is the operator's to judge.
 */
@Component({
  selector: 'app-passkeys',
  imports: [DatePipe, EnrolDialog],
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">FIDO2</p>
        <h1>{{ i18n.t('passkeys') }}</h1>
        <p>{{ i18n.t('pkLede') }}</p>
      </div>
    </section>

    <article class="panel setting-section">
      <header>
        <div class="section-number">1</div>
        <div>
          <h2>{{ i18n.t('pkWho') }}</h2>
          <p>{{ i18n.t('pkWhoLede') }}</p>
        </div>
      </header>

      @if (loaded() && configured().length === 0) {
        <div class="setting-body">
          <p class="notice">{{ i18n.t('pkNoProvider') }}</p>
        </div>
      }

      <form class="probe-form" (submit)="find($event)">
        <label>
          {{ i18n.t('pkProvider') }}
          <select name="directory" [value]="directory()" (change)="pick(value($event))">
            @for (d of configured(); track d.name) {
              <option [value]="d.name" [selected]="d.name === directory()">{{ d.name }}</option>
            }
            @for (d of analysisOnly(); track d.name) {
              <option disabled>{{ d.name }} — {{ i18n.t('pkUnavailable') }}</option>
            }
          </select>
        </label>
        <label>
          {{ i18n.t('pkUser') }}
          <input name="user" autocomplete="off" [value]="identifier()" (input)="identifier.set(value($event))"
                 placeholder="jan.kowalski@example.com" />
        </label>
        <button class="primary" type="submit" [disabled]="busy() || !directory() || !identifier().trim()">
          {{ busy() ? i18n.t('checking') : i18n.t('pkFind') }}
        </button>
      </form>

      @for (d of analysisOnly(); track d.name) {
        <p class="pk-reason"><strong>{{ d.name }}:</strong> {{ d.reason }}</p>
      }

      @if (error(); as message) {
        <p class="inline-error" role="alert">{{ message }}</p>
      }
    </article>

    @if (user(); as person) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">2</div>
          <div>
            <h2>{{ person.displayName || person.login }}</h2>
            <p>{{ person.login }} · {{ directory() }}</p>
          </div>
          <button type="button" (click)="list()">{{ i18n.t('refresh') }}</button>
        </header>

        @if (listing().length === 0) {
          <div class="empty">
            <span>◇</span>
            <strong>{{ i18n.t('pkNone') }}</strong>
            <p>{{ i18n.t('pkNoneLede') }}</p>
          </div>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ i18n.t('pkKey') }}</th>
                  <th>{{ i18n.t('state') }}</th>
                  <th>{{ i18n.t('pkSerial') }}</th>
                  <th>{{ i18n.t('created') }}</th>
                  <th>{{ i18n.t('pkDrift') }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (row of listing(); track row.id ?? row.methodId) {
                  <tr>
                    <td>
                      <strong>{{ row.name || '—' }}</strong>
                      @if (row.methodId) {
                        <small class="block mono">{{ row.methodId }}</small>
                      }
                    </td>
                    <td>
                      @if (row.state) {
                        <em class="state" [attr.data-state]="row.state">{{ row.state }}</em>
                      } @else {
                        <span class="muted">{{ row.providerStatus ?? '—' }}</span>
                      }
                    </td>
                    <td>{{ row.tokenSerial ?? '—' }}</td>
                    <td>{{ row.createdAt ? (row.createdAt | date: 'short') : '—' }}</td>
                    <td>
                      @if (row.drift !== 'InSync') {
                        <span class="pk-drift" [attr.data-drift]="row.drift">{{ i18n.t(driftLabel(row.drift)) }}</span>
                      }
                    </td>
                    <td>
                      @if (row.id && row.state === 'Registered') {
                        <button class="row-action danger" type="button" [disabled]="busy()" (click)="revoke(row.id)">
                          {{ i18n.t('revoke') }}
                        </button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </article>

      <!-- The same key carries a PIV certificate for Windows sign-in and the
           passkey for the cloud; issuing both for one person belongs on one page.
           The issuance itself is 0052's dialog, unchanged: token, slot, agent,
           profile, and the person found in the directory, starting from this
           user's login rather than trusting it. -->
      <article class="panel setting-section">
        <header>
          <div class="section-number">▣</div>
          <div>
            <h2>{{ i18n.t('pkCard') }}</h2>
            <p>{{ i18n.t('pkCardLede') }}</p>
          </div>
        </header>
        @if (tokens().length === 0) {
          <div class="setting-body"><p>{{ i18n.t('pkCardNoTokens') }}</p></div>
        } @else {
          <form class="probe-form pk-form" (submit)="openCard($event)">
            <label>
              {{ i18n.t('pkCardToken') }}
              <select name="cardToken" [value]="cardSerial()" (change)="cardSerial.set(value($event))">
                <option value="">{{ i18n.t('pkCardChoose') }}</option>
                @for (t of tokens(); track t.serial) {
                  <option [value]="t.serial" [selected]="String(t.serial) === cardSerial()">
                    {{ t.serial }} · {{ t.formFactor ?? 'YubiKey' }} · {{ t.state }}{{ agentName(t.lastSeenAgentId) }}
                  </option>
                }
              </select>
            </label>
            <button class="primary" type="submit" [disabled]="!cardSerial()">{{ i18n.t('enrolOpen') }}</button>
          </form>
        }
        @if (cardIssued()) {
          <p class="pk-reason pk-done">{{ i18n.t('pkCardIssued') }}</p>
        }
      </article>

      @if (cardToken(); as t) {
        <app-enrol-dialog
          [serial]="t.serial"
          [lastSeenAgentId]="t.lastSeenAgentId"
          [initialQuery]="person.login"
          (closed)="cardClosed($event)"
        />
      }

      <article class="panel setting-section">
        <header>
          <div class="section-number">3</div>
          <div>
            <h2>{{ i18n.t('pkNew') }}</h2>
            <p>{{ i18n.t('pkNewLede') }}</p>
          </div>
        </header>
        <form class="probe-form pk-form" (submit)="provision($event)">
          <label>
            {{ i18n.t('pkAgent') }}
            <select name="agent" [value]="agentId()" (change)="agentId.set(value($event))">
              <option value="">{{ i18n.t('pkChooseAgent') }}</option>
              @for (agent of agents(); track agent.id) {
                <option [value]="agent.id" [selected]="agent.id === agentId()">{{ agent.hostname }}</option>
              }
            </select>
          </label>
          <label>
            {{ i18n.t('pkSerialOptional') }}
            <input name="serial" inputmode="numeric" [value]="serial()" (input)="serial.set(value($event))" />
          </label>
          <label>
            {{ i18n.t('pkPinMode') }}
            <select name="pinMode" [value]="pinMode()" (change)="pinMode.set(value($event))">
              <option value="ProvisionalRandom">{{ i18n.t('pkPinGenerated') }}</option>
              <option value="OperatorSets">{{ i18n.t('pkPinOperator') }}</option>
              @if (capabilities()?.pinDeliveryByProvider) {
                <option value="ProviderDelivers">{{ i18n.t('pkPinProvider') }}</option>
              }
            </select>
          </label>
          <label>
            {{ i18n.t('pkMinPin') }}
            <input name="minPin" inputmode="numeric" [value]="minPin()" (input)="minPin.set(value($event))" />
          </label>
          <label>
            {{ i18n.t('pkKeyName') }}
            <input name="keyName" [value]="keyName()" (input)="keyName.set(value($event))" />
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="forceChange()" (change)="forceChange.set(checked($event))" />
            {{ i18n.t('pkForceChange') }}
          </label>
          <label class="pk-check">
            <input type="checkbox" [checked]="appendSerial()" (change)="appendSerial.set(checked($event))" />
            {{ i18n.t('pkAppendSerial') }}
          </label>
          <button class="primary" type="submit" [disabled]="busy() || !agentId() || running()">
            {{ i18n.t('pkStart') }}
          </button>
        </form>
      </article>
    }

    @if (status(); as s) {
      <article class="panel setting-section" aria-live="polite">
        <header>
          <div class="section-number">◷</div>
          <div>
            <h2>{{ i18n.t('pkCeremony') }}</h2>
            <p>{{ s.login }} · {{ s.directory }}{{ s.jobState ? ' · ' + s.jobState : '' }}</p>
          </div>
        </header>
        <div class="setting-body">
          <ol class="pk-steps">
            @for (step of steps; track step.state; let i = $index) {
              <li [attr.data-step]="stepState(i, s.state)">{{ i18n.t(step.label) }}</li>
            }
          </ol>

          @if (s.state === 'Failed') {
            <p class="inline-error pk-inline">{{ s.failureReason }}</p>
          }

          @if (s.state === 'Registered') {
            <p class="pk-done">
              {{ i18n.t('pkRegisteredAs') }} <strong>{{ s.keyName }}</strong>
              @if (s.tokenSerial) { ({{ s.tokenSerial }}) }
            </p>
          }

          <!-- Whether, never what: the PIN was on the workstation's screen and
               is nowhere this page could reach. -->
          @if (s.pinSetByAgent) {
            <p class="pk-pin">{{ i18n.t('pkPinShownThere') }}</p>
          }
        </div>
      </article>
    }
  `,
  styles: [
    `
      .pk-reason {
        margin: 0 1.2rem 1rem;
        color: var(--bl-text-muted);
        font-size: 13px;
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
      .pk-steps {
        display: grid;
        gap: 8px;
        margin: 0 0 1rem;
        padding-left: 1.4rem;
      }
      .pk-steps li {
        color: var(--bl-text-muted);
      }
      .pk-steps li[data-step='done'] {
        color: var(--bl-text);
      }
      .pk-steps li[data-step='done']::marker {
        content: '✓  ';
        color: var(--bl-ok);
      }
      .pk-steps li[data-step='current'] {
        color: var(--bl-accent-text);
        font-weight: 600;
      }
      .pk-steps li[data-step='current']::marker {
        content: '▸  ';
      }
      .pk-inline {
        margin: 0 0 1rem;
      }
      .pk-done {
        color: var(--bl-ok) !important;
      }
      .pk-pin {
        margin-top: 0.5rem !important;
      }
      .pk-drift {
        display: inline-flex;
        padding: 2px 8px;
        border: 1px solid var(--bl-warning-border);
        border-radius: 6px;
        background: var(--bl-warning-soft);
        color: var(--bl-warning);
        font-size: 13px;
        font-weight: 600;
        white-space: nowrap;
      }
      .pk-drift[data-drift='MissingAtProvider'],
      .pk-drift[data-drift='StillAtProvider'] {
        border-color: var(--bl-danger-border);
        background: var(--bl-danger-soft);
        color: var(--bl-danger);
      }
      .mono {
        font-family: Consolas, 'Cascadia Mono', monospace;
        font-size: 12px;
        color: var(--bl-text-muted);
      }
      .block {
        display: block;
      }
    `,
  ],
})
export class Passkeys implements OnDestroy {
  private readonly http = inject(HttpClient);
  private readonly console = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly steps = STEPS;

  protected readonly loaded = signal(false);
  protected readonly configured = signal<Directories['directories']>([]);
  protected readonly analysisOnly = signal<Directories['analysisOnly']>([]);
  protected readonly directory = signal('');
  protected readonly identifier = signal('');
  protected readonly user = signal<ProviderUser | null>(null);
  protected readonly listing = signal<Listing[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly agentId = signal('');
  protected readonly serial = signal('');
  protected readonly pinMode = signal('ProvisionalRandom');
  protected readonly minPin = signal('6');
  protected readonly keyName = signal('YubiKey');
  protected readonly forceChange = signal(true);
  protected readonly appendSerial = signal(true);

  protected readonly status = signal<Status | null>(null);

  protected readonly cardSerial = signal('');
  protected readonly cardIssued = signal(false);
  protected readonly String = String;
  private readonly enrolDialog = viewChild(EnrolDialog);

  /** Tokens the inventory knows, the one most recently seen first. */
  protected readonly tokens = computed(() =>
    [...this.console.snapshot().tokens].sort((a, b) => (b.lastSeenAt ?? '').localeCompare(a.lastSeenAt ?? '')));
  protected readonly cardToken = computed(
    () => this.tokens().find((t) => String(t.serial) === this.cardSerial()) ?? null);
  private poll: ReturnType<typeof setInterval> | null = null;

  protected readonly capabilities = computed(
    () => this.configured().find((d) => d.name === this.directory())?.capabilities ?? null);
  protected readonly agents = computed(() => this.console.snapshot().agents.filter((a) => a.state === 'Enrolled'));
  protected readonly running = computed(() => {
    const s = this.status();
    return s !== null && !FINAL.includes(s.state);
  });

  constructor() {
    void this.loadDirectories();

    if (this.console.snapshot().agents.length === 0) {
      void this.console.load();
    }
  }

  ngOnDestroy(): void {
    this.stopPolling();
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  protected checked(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }

  protected agentName(id: string | null | undefined): string {
    const agent = id ? this.console.snapshot().agents.find((a) => a.id === id) : undefined;
    return agent ? ` · ${agent.hostname}` : '';
  }

  /** Opens 0052's dialog once Angular has drawn it for the chosen token. */
  protected openCard(event: Event): void {
    event.preventDefault();
    this.cardIssued.set(false);
    setTimeout(() => void this.enrolDialog()?.open('9A'));
  }

  protected cardClosed(succeeded: boolean): void {
    this.cardIssued.set(succeeded);
    void this.console.load(true);
  }

  protected pick(name: string): void {
    this.directory.set(name);
    this.user.set(null);
    this.listing.set([]);
  }

  protected driftLabel(drift: Drift): MessageKey {
    return drift === 'MissingAtProvider' ? 'pkDriftMissing'
      : drift === 'StillAtProvider' ? 'pkDriftStill'
      : 'pkDriftProviderOnly';
  }

  /** Before, at, or after the row's state - a failed row stops where it was. */
  protected stepState(index: number, state: string): 'done' | 'current' | 'todo' {
    const at = STEPS.findIndex((s) => s.state === state);

    if (state === 'Registered' || state === 'Revoked') return 'done';
    if (at < 0) return 'todo';
    return index < at ? 'done' : index === at ? 'current' : 'todo';
  }

  protected async find(event: Event): Promise<void> {
    event.preventDefault();
    await this.list();
  }

  protected async list(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);

    try {
      const answer = await firstValueFrom(this.http.get<{ user: ProviderUser; passkeys: Listing[] }>(
        '/api/passkeys', { params: { directory: this.directory(), user: this.identifier().trim() } }));

      this.user.set(answer.user);
      this.listing.set(answer.passkeys);
    } catch (error) {
      this.user.set(null);
      this.listing.set([]);
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    } finally {
      this.busy.set(false);
    }
  }

  protected async provision(event: Event): Promise<void> {
    event.preventDefault();

    const person = this.user();
    if (!person) return;

    this.busy.set(true);
    this.error.set(null);

    try {
      const serial = Number.parseInt(this.serial().trim(), 10);
      const minPin = Number.parseInt(this.minPin().trim(), 10);

      const created = await firstValueFrom(this.http.post<{ passkey: string }>('/api/jobs/fido2', {
        directory: this.directory(),
        user: person.id,
        agentId: this.agentId(),
        tokenSerial: Number.isFinite(serial) ? serial : null,
        pinMode: this.pinMode(),
        minPinLength: Number.isFinite(minPin) ? minPin : 6,
        forceChangePin: this.forceChange(),
        keyName: this.keyName().trim() || null,
        appendSerial: this.appendSerial(),
        // A new attempt is a new job: the same request twice would return the
        // first one, finished or not.
        reason: new Date().toISOString(),
      }));

      if (Number.isFinite(serial) && !this.cardSerial()) {
        this.cardSerial.set(String(serial));
      }

      await this.follow(created.passkey);
    } catch (error) {
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    } finally {
      this.busy.set(false);
    }
  }

  protected async revoke(id: string): Promise<void> {
    const reason = window.prompt(this.i18n.t('pkRevokeReason'), this.i18n.t('pkRevokeDefault'));
    if (!reason?.trim()) return;

    this.busy.set(true);
    this.error.set(null);

    try {
      await firstValueFrom(this.http.post(`/api/passkeys/${id}/revoke`, { reason: reason.trim() }));
      await this.list();
    } catch (error) {
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    } finally {
      this.busy.set(false);
    }
  }

  private async loadDirectories(): Promise<void> {
    try {
      const answer = await firstValueFrom(this.http.get<Directories>('/api/passkeys/directories'));

      this.configured.set(answer.directories);
      this.analysisOnly.set(answer.analysisOnly);

      if (!this.directory() && answer.directories.length > 0) {
        this.directory.set(answer.directories[0].name);
      }
    } catch (error) {
      this.error.set(describe(error, this.i18n.t('operationFailed')));
    } finally {
      this.loaded.set(true);
    }
  }

  /** Every two seconds until the row is final - a touch takes a person, not a server. */
  private async follow(id: string): Promise<void> {
    this.stopPolling();
    await this.refreshStatus(id);

    this.poll = setInterval(() => void this.refreshStatus(id), 2000);
  }

  private async refreshStatus(id: string): Promise<void> {
    try {
      const status = await firstValueFrom(this.http.get<Status>(`/api/passkeys/${id}`));
      this.status.set(status);

      if (FINAL.includes(status.state)) {
        this.stopPolling();
        await this.list();
      }
    } catch {
      // One lost poll is not a failed ceremony; the next one will say.
    }
  }

  private stopPolling(): void {
    if (this.poll !== null) {
      clearInterval(this.poll);
      this.poll = null;
    }
  }
}

function describe(error: unknown, fallback: string): string {
  const body = (error as { error?: { error?: string } })?.error;

  return body?.error ?? fallback;
}

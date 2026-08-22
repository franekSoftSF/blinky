import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ConsoleStore, HelpdeskView } from '../core/console.store';
import { displayFormFactor } from '../core/console-presentation';
import { I18n } from '../core/i18n';

@Component({
  selector: 'app-helpdesk',
  imports: [DatePipe, RouterLink],
  template: ` <section class="list-head">
      <div>
        <a class="back-link" routerLink="/tokens">← Tokens</a>
        <p class="eyebrow">HELP DESK</p>
        <h1>Token {{ serial }}</h1>
        <p>User, device and card applications from one live help-desk response.</p>
      </div>
      <button class="secondary-action" (click)="load()">↻ Refresh</button>
    </section>
    @if (error()) {
      <div class="notice">
        <strong>{{ error() }}</strong>
      </div>
    }
    @if (data(); as view) {
      <section class="helpdesk-grid">
        <article class="panel detail-card">
          <header>
            <div>
              <p class="eyebrow">CARDHOLDER</p>
              <h2>{{ view.cardholder?.displayName ?? 'Unassigned token' }}</h2>
            </div>
            <span class="state" [attr.data-state]="view.cardholder?.state">{{
              view.cardholder?.state ?? 'None'
            }}</span>
          </header>
          <dl>
            <div>
              <dt>UPN</dt>
              <dd>{{ view.cardholder?.upn ?? '—' }}</dd>
            </div>
            <div>
              <dt>Directory source</dt>
              <dd>{{ view.cardholder?.source ?? '—' }}</dd>
            </div>
            <div>
              <dt>Object SID</dt>
              <dd>{{ view.cardholder?.objectSid ?? '—' }}</dd>
            </div>
          </dl>
        </article>
        <article class="panel detail-card">
          <header>
            <div>
              <p class="eyebrow">DEVICE</p>
              <h2>{{ displayModel(view.device.formFactor) }}</h2>
            </div>
            <span class="state" [attr.data-state]="view.device.state">{{ view.device.state }}</span>
          </header>
          <dl>
            <div>
              <dt>Serial</dt>
              <dd>{{ view.device.serial }}</dd>
            </div>
            <div>
              <dt>Firmware</dt>
              <dd>{{ view.device.firmwareVersion ?? '—' }}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>
                {{ view.device.lastSeenAt ? (view.device.lastSeenAt | date: 'medium') : '—' }}
              </dd>
            </div>
            <div>
              <dt>Management key</dt>
              <dd>{{ view.device.managementKeyState }}</dd>
            </div>
          </dl>
        </article>
      </section>
      @if (!view.device.manageable) {
        <div class="capability-warning">
          Management key is lost. Actions that write to the card are unavailable.
        </div>
      }
      <section class="application-grid">
        <article class="application-card">
          <span>PIN</span><strong>{{ view.pin.state }}</strong
          ><small>{{ view.pin.retriesLeft ?? '—' }} retries left</small
          ><em>{{
            view.puk.unblockable && view.device.manageable
              ? 'Unblock available at the workstation'
              : 'Unblock unavailable'
          }}</em>
        </article>
        <article class="application-card">
          <span>PUK</span><strong>{{ view.puk.state }}</strong
          ><small>{{ view.puk.retriesLeft ?? '—' }} retries left</small
          ><em>{{ view.puk.unblockable ? 'Available for unblock' : 'Unblock unavailable' }}</em>
        </article>
        <article class="application-card">
          <span>BIOMETRIC</span><strong>{{ view.biometric.state }}</strong
          ><small>{{ view.biometric.attemptsLeft ?? '—' }} attempts left</small>
        </article>
      </section>
      <article class="panel list-panel">
        <header>
          <div>
            <h2>Card applications</h2>
            <p>Presence comes from physical slots; credentials below are their history.</p>
          </div>
        </header>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Slot</th>
                <th>Present state</th>
                <th>Algorithm</th>
                <th>PIN policy</th>
                <th>Touch policy</th>
              </tr>
            </thead>
            <tbody>
              @for (slot of view.slots; track slot.slotId) {
                <tr>
                  <td>
                    <strong>{{ slot.slotId }}</strong>
                  </td>
                  <td>
                    <span
                      class="state"
                      [attr.data-state]="slotState(view, slot.credentialId, slot.state)"
                      >{{ slotState(view, slot.credentialId, slot.state) }}</span
                    >
                  </td>
                  <td>{{ slot.keyAlgorithm ?? '—' }}</td>
                  <td>{{ slot.pinPolicy ?? '—' }}</td>
                  <td>{{ slot.touchPolicy ?? '—' }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </article>
      <article class="panel list-panel credential-history">
        <header>
          <div>
            <h2>Credential history</h2>
            <p>Revoked credentials remain history and are never presented as installed.</p>
          </div>
        </header>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Slot</th>
                <th>Validity</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (credential of view.credentials; track credential.id) {
                <tr>
                  <td>
                    <strong>{{ credential.subjectDn ?? '—' }}</strong
                    ><small>{{ credential.issuerDn ?? '' }}</small>
                  </td>
                  <td>{{ credential.slotId }}</td>
                  <td>
                    {{
                      credential.expired
                        ? 'Expired'
                        : credential.notAfter
                          ? (credential.notAfter | date: 'mediumDate')
                          : '—'
                    }}
                  </td>
                  <td>
                    <span class="state" [attr.data-state]="credential.state">{{
                      credential.state
                    }}</span>
                  </td>
                  <td class="row-actions">
                    <button
                      class="row-action"
                      [disabled]="
                        !view.device.manageable ||
                        credential.state === 'Revoked' ||
                        busy() === credential.id
                      "
                      (click)="suspend(credential.id)"
                    >
                      Suspend</button
                    ><button
                      class="row-action danger"
                      [disabled]="
                        !view.device.manageable ||
                        credential.state === 'Revoked' ||
                        busy() === credential.id
                      "
                      (click)="revoke(credential.id)"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </article>
      <section class="token-actions">
        <select #state>
          <option>Suspended</option>
          <option>Lost</option>
          <option>Stolen</option>
          <option>Terminated</option>
          <option>Retired</option></select
        ><button class="danger-action" [disabled]="busy() !== null" (click)="block(state.value)">
          Block token</button
        ><button
          class="secondary-action"
          [disabled]="view.device.state !== 'Suspended' || busy() !== null"
          (click)="unblock()"
        >
          Lift suspension
        </button>
      </section>
    }`,
})
export class Helpdesk {
  private readonly route = inject(ActivatedRoute);
  private readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly serial = Number(this.route.snapshot.paramMap.get('serial'));
  protected readonly data = signal<HelpdeskView | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal<string | null>(null);
  constructor() {
    void this.load();
  }
  protected displayModel(value: string | undefined): string {
    return displayFormFactor(value, this.i18n.language());
  }
  protected slotState(
    view: HelpdeskView,
    credentialId: string | null | undefined,
    state: string,
  ): string {
    return credentialId &&
      view.credentials.some((c) => c.id === credentialId && c.state === 'Revoked')
      ? 'Empty'
      : state;
  }
  protected async load(): Promise<void> {
    this.error.set(null);
    try {
      this.data.set(await this.store.helpdesk(this.serial));
    } catch {
      this.error.set('Could not load the help-desk view. Check the operator token and connection.');
    }
  }
  protected async suspend(id: string): Promise<void> {
    if (!confirm('Place this credential on hold? This action is reversible.')) return;
    await this.run(id, () => this.store.suspendCredential(id));
  }
  protected async revoke(id: string): Promise<void> {
    const reason = prompt(
      'Revocation reason (KeyCompromise, Superseded, CessationOfOperation, …):',
    );
    if (reason) await this.run(id, () => this.store.revokeCredential(id, reason, null));
  }
  protected async block(state: string): Promise<void> {
    const reversible = state === 'Suspended';
    if (
      !confirm(
        reversible
          ? 'Suspend this token? This action is reversible.'
          : `Mark this token ${state}? This action is permanent and revokes credentials.`,
      )
    )
      return;
    await this.run('token', () => this.store.blockToken(this.serial, state, null));
  }
  protected async unblock(): Promise<void> {
    if (confirm('Lift this token suspension?'))
      await this.run('token', () => this.store.unblockToken(this.serial));
  }
  private async run(id: string, action: () => Promise<unknown>): Promise<void> {
    this.busy.set(id);
    this.error.set(null);
    try {
      await action();
      await this.load();
      await this.store.load(true);
    } catch {
      this.error.set('The operation failed. No state was assumed; refresh and try again.');
    } finally {
      this.busy.set(null);
    }
  }
}

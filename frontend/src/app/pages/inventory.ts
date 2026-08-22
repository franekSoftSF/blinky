import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ConsoleStore } from '../core/console.store';
import { displayFormFactor, jobResultMessage, occupiedSlots } from '../core/console-presentation';
import { I18n } from '../core/i18n';

@Component({
  selector: 'app-inventory',
  imports: [RouterLink],
  template: ` <section class="list-head">
      <div>
        <p class="eyebrow">{{ i18n.t('inventory') }}</p>
        <h1>{{ title() }}</h1>
        <p>{{ subtitle() }}</p>
      </div>
      <div class="list-actions">
        <label class="search"
          >⌕
          <input
            [placeholder]="i18n.t('search')"
            (input)="query.set($any($event.target).value)" /></label
        ><button class="secondary-action" type="button" (click)="store.load(true)">
          ↻ {{ i18n.t('refresh') }}
        </button>
      </div>
    </section>
    @if (message()) {
      <div class="notice">
        <strong>{{ message() }}</strong>
      </div>
    }
    <article class="panel list-panel">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              @for (column of columns(); track column) {
                <th>{{ column }}</th>
              }
            </tr>
          </thead>
          <tbody>
            @for (row of rows(); track row.id) {
              <tr>
                @for (cell of row.cells; track $index) {
                  <td>
                    @if ($index === 0 && row.link) {
                      <a class="table-link" [routerLink]="row.link"
                        ><strong>{{ cell }}</strong> →</a
                      >
                    } @else if ($index === row.stateIndex) {
                      <span class="state" [attr.data-state]="cell">{{ cell }}</span>
                    } @else {
                      <span [class.job-detail]="$index === row.detailIndex">{{ cell }}</span>
                    }
                  </td>
                }
                @if (kind === 'certificates') {
                  <td class="row-actions">
                    <button
                      class="row-action"
                      [disabled]="row.state === 'Revoked' || busy() === row.id"
                      (click)="suspend(row.id)"
                    >
                      Suspend</button
                    ><button
                      class="row-action danger"
                      [disabled]="row.state === 'Revoked' || busy() === row.id"
                      (click)="revoke(row.id)"
                    >
                      Revoke
                    </button>
                  </td>
                }
              </tr>
            }
          </tbody>
        </table>
      </div>
      @if (!rows().length) {
        <div class="empty">
          <span>{{ icon() }}</span
          ><strong>{{ i18n.t('noData') }}</strong>
          <p>{{ i18n.t('noDataText') }}</p>
        </div>
      }
    </article>`,
})
export class Inventory {
  protected readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  private readonly route = inject(ActivatedRoute);
  protected readonly query = signal('');
  protected readonly busy = signal<string | null>(null);
  protected readonly message = signal<string | null>(null);
  protected readonly kind = this.route.snapshot.data['kind'] as
    'tokens' | 'certificates' | 'agents' | 'jobs';
  protected readonly title = computed(
    () =>
      ({
        tokens: this.i18n.t('pivTokens'),
        certificates: this.i18n.t('certificates'),
        agents: this.i18n.t('agentsTitle'),
        jobs: this.i18n.t('jobs'),
      })[this.kind],
  );
  protected readonly subtitle = computed(
    () =>
      ({
        tokens: this.i18n.t('tokensText'),
        certificates: this.i18n.t('certsText'),
        agents: this.i18n.t('agentsText'),
        jobs: this.i18n.t('jobsText'),
      })[this.kind],
  );
  protected readonly icon = computed(
    () => ({ tokens: '◇', certificates: '▤', agents: '⌁', jobs: '↯' })[this.kind],
  );
  protected readonly columns = computed(
    () =>
      ({
        tokens: [
          this.i18n.t('serial'),
          this.i18n.t('model'),
          'Applications',
          this.i18n.t('firmware'),
          this.i18n.t('status'),
        ],
        certificates: [
          this.i18n.t('subject'),
          this.i18n.t('tokenSlot'),
          this.i18n.t('validTo'),
          this.i18n.t('status'),
          this.i18n.t('actions'),
        ],
        agents: [
          this.i18n.t('hostname'),
          this.i18n.t('domain'),
          this.i18n.t('version'),
          this.i18n.t('lastSeen'),
          this.i18n.t('status'),
        ],
        jobs: [
          this.i18n.t('operation'),
          this.i18n.t('token'),
          this.i18n.t('attempt'),
          'Updated / result',
          this.i18n.t('status'),
        ],
      })[this.kind],
  );
  protected readonly rows = computed(() => {
    const s = this.store.snapshot();
    let rows: Array<{
      id: string;
      state: string;
      stateIndex: number;
      detailIndex?: number;
      cells: string[];
      link?: string;
    }>;
    if (this.kind === 'tokens')
      rows = s.tokens.map((x) => ({
        id: x.id,
        state: x.state,
        stateIndex: 4,
        link: `/tokens/${x.serial}`,
        cells: [
          String(x.serial),
          displayFormFactor(x.formFactor, this.i18n.language()),
          occupiedSlots(s.slots, s.credentials, x.serial)
            .map((slot) => slot.slotId)
            .join(', ') || 'Empty',
          x.firmwareVersion ?? '—',
          x.state,
        ],
      }));
    else if (this.kind === 'certificates')
      rows = s.credentials.map((x) => ({
        id: x.id,
        state: x.state,
        stateIndex: 3,
        cells: [
          x.subjectDn ?? '—',
          `${x.tokenSerial} / ${x.slotId}`,
          x.notAfter ? new Date(x.notAfter).toLocaleDateString() : '—',
          x.state,
        ],
      }));
    else if (this.kind === 'agents')
      rows = s.agents.map((x) => ({
        id: x.id,
        state: x.state,
        stateIndex: 4,
        cells: [
          x.hostname,
          x.domain,
          x.version ?? '—',
          x.lastHeartbeatAt ? new Date(x.lastHeartbeatAt).toLocaleString() : '—',
          x.state,
        ],
      }));
    else
      rows = s.jobs.map((x) => ({
        id: x.id,
        state: x.state,
        stateIndex: 4,
        detailIndex: 3,
        cells: [
          x.type,
          String(x.tokenSerial ?? '—'),
          String(x.attempt),
          `${new Date(x.updatedAt ?? x.createdAt).toLocaleString()}${x.state === 'Failed' && jobResultMessage(x.result) ? ` · ${jobResultMessage(x.result)}` : ''}`,
          x.state,
        ],
      }));
    const q = this.query().trim().toLocaleLowerCase();
    return q ? rows.filter((r) => r.cells.some((c) => c.toLocaleLowerCase().includes(q))) : rows;
  });
  protected async suspend(id: string): Promise<void> {
    if (!confirm('Suspend this credential? The API will report this hold as reversible.')) return;
    await this.run(
      id,
      () => this.store.suspendCredential(id),
      'Credential suspended. The hold is reversible.',
    );
  }
  protected async revoke(id: string): Promise<void> {
    const reason = prompt(
      'Revocation reason (for example KeyCompromise, Superseded or CessationOfOperation):',
    );
    if (!reason) return;
    await this.run(
      id,
      () => this.store.revokeCredential(id, reason, null),
      'Credential revoked permanently.',
    );
  }
  private async run(id: string, action: () => Promise<unknown>, success: string): Promise<void> {
    this.busy.set(id);
    this.message.set(null);
    try {
      await action();
      await this.store.load(true);
      this.message.set(success);
    } catch {
      this.message.set(this.i18n.t('operationFailed'));
    } finally {
      this.busy.set(null);
    }
  }
}

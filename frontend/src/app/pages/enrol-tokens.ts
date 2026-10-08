import { Component, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { firstValueFrom } from 'rxjs';
import { I18n } from '../core/i18n';

interface EnrolToken {
  id: string;
  name: string;
  purpose: string;
  expires: string | null;
  maxUses: number | null;
  uses: number;
  allowedDomain: string | null;
  createdBy: string;
  createdAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
  usable: boolean;
  spent: string | null;
}

interface CreatedToken extends EnrolToken {
  token: string;
}

/**
 * Enrolment tokens: what a machine presents to join.
 *
 * The page exists because the alternative was a value in `docker-compose.yml`
 * (0102). A token here has a term, a number of machines it may enrol and a
 * purpose, and the value is shown exactly once - there is nowhere to go and
 * read it again, which is the point.
 *
 * Made and withdrawn, never edited and never deleted: changing the limits of a
 * token somebody already holds would mean the limits say nothing, and deleting
 * one would take the record of what enrolled with it.
 */
@Component({
  selector: 'app-enrol-tokens',
  imports: [DatePipe],
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">{{ i18n.t('administration') }}</p>
        <h1>{{ i18n.t('enrolTokens') }}</h1>
        <p>{{ i18n.t('enrolTokensLede') }}</p>
      </div>
    </section>

    @if (created(); as fresh) {
      <article class="panel setting-section">
        <header>
          <div class="section-number">!</div>
          <div>
            <h2>{{ fresh.name }}</h2>
            <p>{{ i18n.t('shownOnce') }}</p>
          </div>
        </header>
        <div class="setting-body">
          <p class="secret-value"><code>{{ fresh.token }}</code></p>
          <button type="button" (click)="created.set(null)">{{ i18n.t('hide') }}</button>
        </div>
      </article>
    }

    <article class="panel setting-section">
      <header>
        <div class="section-number">+</div>
        <div>
          <h2>{{ i18n.t('newToken') }}</h2>
          <p>{{ i18n.t('newTokenLede') }}</p>
        </div>
      </header>
      <form class="setting-body probe-form" (submit)="create($event)">
        <label>
          {{ i18n.t('tokenName') }}
          <input name="name" [value]="name()" (input)="name.set(value($event))" />
        </label>
        <label>
          {{ i18n.t('tokenPurpose') }}
          <select name="purpose" [value]="purpose()" (change)="purpose.set(value($event))">
            <option value="agent">{{ i18n.t('purposeAgent') }}</option>
            <option value="connector">{{ i18n.t('purposeConnector') }}</option>
          </select>
        </label>
        <label>
          {{ i18n.t('validDays') }}
          <input name="days" inputmode="numeric" [value]="days()" (input)="days.set(value($event))" />
        </label>
        <label>
          {{ i18n.t('maxUses') }}
          <input name="uses" inputmode="numeric" [value]="uses()" (input)="uses.set(value($event))" />
        </label>
        <label>
          {{ i18n.t('allowedDomain') }}
          <input name="domain" [value]="domain()" (input)="domain.set(value($event))" />
        </label>
        <button class="primary" type="submit" [disabled]="busy() || !name().trim()">
          {{ busy() ? i18n.t('checking') : i18n.t('create') }}
        </button>
      </form>
      @if (error(); as message) {
        <p class="inline-error">{{ message }}</p>
      }
    </article>

    <article class="panel">
      <header>
        <h2>{{ i18n.t('existingTokens') }}</h2>
        <button type="button" (click)="load()">{{ i18n.t('refresh') }}</button>
      </header>
      @if (tokens().length === 0) {
        <div class="empty">
          <span>◇</span>
          <strong>{{ i18n.t('noTokens') }}</strong>
          <p>{{ i18n.t('noTokensLede') }}</p>
        </div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{{ i18n.t('tokenName') }}</th>
                <th>{{ i18n.t('tokenPurpose') }}</th>
                <th>{{ i18n.t('state') }}</th>
                <th>{{ i18n.t('usesColumn') }}</th>
                <th>{{ i18n.t('expiresColumn') }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (token of tokens(); track token.id) {
                <tr>
                  <td>
                    <strong>{{ token.name }}</strong>
                    @if (token.allowedDomain) {
                      <small class="block">{{ token.allowedDomain }}</small>
                    }
                  </td>
                  <td>{{ token.purpose === 'AdcsConnector' ? i18n.t('purposeConnector') : i18n.t('purposeAgent') }}</td>
                  <td>
                    <em class="state" [attr.data-state]="token.usable ? 'Issued' : 'Blocked'">
                      {{ token.usable ? i18n.t('usable') : (token.spent ?? '—') }}
                    </em>
                  </td>
                  <td>{{ token.uses }} / {{ token.maxUses ?? '∞' }}</td>
                  <td>{{ token.expires ? (token.expires | date: 'short') : i18n.t('never') }}</td>
                  <td>
                    @if (!token.revokedAt) {
                      <button class="row-action" type="button" (click)="revoke(token)">
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
  `,
})
export class EnrolTokens {
  private readonly http = inject(HttpClient);
  protected readonly i18n = inject(I18n);

  protected readonly tokens = signal<EnrolToken[]>([]);
  protected readonly created = signal<CreatedToken | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly name = signal('');
  protected readonly purpose = signal('agent');
  protected readonly days = signal('30');
  protected readonly uses = signal('1');
  protected readonly domain = signal('');

  protected readonly usable = computed(() => this.tokens().filter((t) => t.usable).length);

  constructor() {
    void this.load();
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  protected async load(): Promise<void> {
    try {
      this.tokens.set(await firstValueFrom(this.http.get<EnrolToken[]>('/api/enrol-tokens')));
    } catch {
      this.error.set(this.i18n.t('tokensUnavailable'));
    }
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();

    this.busy.set(true);
    this.error.set(null);

    try {
      const body = {
        name: this.name().trim(),
        purpose: this.purpose(),
        // Blank means "no limit", which has to be typed rather than defaulted
        // to: a token that never expires is a decision, not an oversight.
        validForDays: this.number(this.days()),
        maxUses: this.number(this.uses()),
        allowedDomain: this.domain().trim() || null,
      };

      this.created.set(await firstValueFrom(this.http.post<CreatedToken>('/api/enrol-tokens', body)));
      this.name.set('');
      await this.load();
    } catch (error) {
      this.error.set(describe(error));
    } finally {
      this.busy.set(false);
    }
  }

  protected async revoke(token: EnrolToken): Promise<void> {
    await firstValueFrom(
      this.http.post(`/api/enrol-tokens/${token.id}/revoke`, { reason: 'revoked from the console' }));

    await this.load();
  }

  private number(value: string): number | null {
    const parsed = Number.parseInt(value.trim(), 10);

    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  }
}

function describe(error: unknown): string {
  const body = (error as { error?: { error?: string } })?.error;

  return body?.error ?? 'Nie udało się.';
}

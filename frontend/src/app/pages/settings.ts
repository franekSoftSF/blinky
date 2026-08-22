import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import {
  ConsoleStore,
  DirectoryAccessResult,
  DirectoryConnectionResult,
  DirectoryResolveResult,
} from '../core/console.store';
import { I18n } from '../core/i18n';
import {
  directoryAccessTitle,
  directoryAccessTone,
  parseAccounts,
} from '../core/directory-presentation';

@Component({
  selector: 'app-directory-diagnostics',
  template: ` <div class="directory-page">
    <section class="settings-hero">
      <div>
        <p class="eyebrow">KATALOG I TOŻSAMOŚĆ</p>
        <h1>Diagnostyka katalogowa</h1>
        <p>Sprawdź gotowość katalogu przed wydaniem pierwszego certyfikatu.</p>
      </div>
      <div class="yubi-mark">
        <span>Y</span>
        <div><strong>YubiKey ready</strong><small>Directory & identity checks</small></div>
      </div>
    </section>

    <section class="settings-layout">
      <aside class="settings-index">
        <p>USTAWIENIA</p>
        <a href="#operator">01 <span>Dostęp operatora</span></a
        ><a href="#directory">02 <span>Integracja katalogowa</span></a
        ><a href="#about">03 <span>O aplikacji</span></a>
      </aside>
      <div class="settings-content">
        <article class="panel setting-section" id="operator">
          <header>
            <div class="section-number">01</div>
            <div>
              <h2>Dostęp operatora</h2>
              <p>Autoryzacja zapytań administracyjnych</p>
            </div>
            <span class="privacy-badge">Tylko pamięć</span>
          </header>
          <div class="setting-body operator-setting">
            <div>
              <h3>Token sesji operatora</h3>
              <p>
                Token pozostaje wyłącznie w pamięci otwartej strony. Nie zapisujemy go w
                przeglądarce, adresie ani logach.
              </p>
            </div>
            <form (submit)="save($event)">
              <label
                >Token operatora<input
                  type="password"
                  autocomplete="off"
                  [value]="token()"
                  (input)="token.set($any($event.target).value)"
                  placeholder="Wprowadź token…" /></label
              ><button class="primary" type="submit">Połącz z API</button>
            </form>
          </div>
        </article>

        <section id="directory" class="directory-heading">
          <div>
            <p class="eyebrow">INTEGRACJA KATALOGOWA</p>
            <h2>Trzy testy przed wdrożeniem</h2>
            <p>
              Każdy test odpowiada na inne pytanie. Żaden z nich nie zapisuje danych w katalogu.
            </p>
          </div>
          <span class="read-only-badge">READ-ONLY PROBES</span>
        </section>

        <article class="diagnostic-card" data-step="1">
          <header>
            <span class="diagnostic-icon">⌁</span>
            <div>
              <p>TEST 01</p>
              <h3>Połączenie z katalogiem</h3>
              <small>Czy serwer odpowiada, bind działa i Base DN istnieje?</small>
            </div>
            <button
              class="probe-button"
              [disabled]="busy() === 'connection'"
              (click)="testConnection()"
            >
              {{ busy() === 'connection' ? 'Testowanie…' : 'Uruchom test' }}
            </button>
          </header>
          @if (connection(); as result) {
            <div class="result-block" [attr.data-tone]="result.succeeded ? 'success' : 'danger'">
              <div class="result-summary">
                <span>{{ result.succeeded ? '✓' : '!' }}</span>
                <div>
                  <strong>{{
                    result.succeeded ? 'Połączenie gotowe' : 'Połączenie wymaga uwagi'
                  }}</strong>
                  <p>{{ result.detail }}</p>
                </div>
                <em>{{ result.milliseconds }} ms</em>
              </div>
              <div class="check-grid">
                <div [class.ok]="result.reachable">
                  <span>{{ result.reachable ? '✓' : '×' }}</span>
                  <div>
                    <small>SERWER</small
                    ><strong>{{ result.reachable ? 'Osiągalny' : 'Nieosiągalny' }}</strong>
                  </div>
                </div>
                <div [class.ok]="result.baseDnFound">
                  <span>{{ result.baseDnFound ? '✓' : '×' }}</span>
                  <div>
                    <small>BASE DN</small
                    ><strong>{{ result.baseDnFound ? 'Znaleziony' : 'Nie znaleziony' }}</strong>
                  </div>
                </div>
                <div [class.ok]="result.encrypted">
                  <span>{{ result.encrypted ? '✓' : '!' }}</span>
                  <div>
                    <small>TRANSPORT</small
                    ><strong>{{ result.encrypted ? 'Szyfrowany' : 'Nieszyfrowany' }}</strong>
                  </div>
                </div>
              </div>
              <dl class="result-meta">
                <div>
                  <dt>Źródło</dt>
                  <dd>{{ result.source }}</dd>
                </div>
                <div>
                  <dt>Uwierzytelniono jako</dt>
                  <dd>{{ result.boundAs || '—' }}</dd>
                </div>
              </dl>
            </div>
          }
          @if (errorFor() === 'connection') {
            <div class="inline-error">{{ errorMessage() }}</div>
          }
        </article>

        <article class="diagnostic-card" data-step="2">
          <header>
            <span class="diagnostic-icon">◉</span>
            <div>
              <p>TEST 02</p>
              <h3>Osoby do wydania</h3>
              <small>Czy planowani użytkownicy mają UPN, SID i aktywne konto?</small>
            </div>
          </header>
          <div class="probe-form two-fields">
            <label
              >Grupa katalogowa
              <input
                [value]="group()"
                (input)="group.set($any($event.target).value)"
                placeholder="CN=Card Holders,OU=Groups,DC=…"
              /><small
                >Członkostwo grup zagnieżdżonych nie jest rozwijane rekursywnie.</small
              ></label
            ><label
              >Konta
              <textarea
                [value]="accounts()"
                (input)="accounts.set($any($event.target).value)"
                placeholder="admin, jkowalski"
              ></textarea
              ><small>Oddziel przecinkiem, spacją lub nowym wierszem.</small></label
            ><button
              class="probe-button"
              [disabled]="busy() === 'resolve' || (!group().trim() && !accounts().trim())"
              (click)="testResolve()"
            >
              {{ busy() === 'resolve' ? 'Sprawdzanie…' : 'Sprawdź osoby' }}
            </button>
          </div>
          @if (resolve(); as result) {
            <div class="people-result">
              <div class="rollout-score">
                <strong
                  >{{ result.issuable }} <span>z {{ result.found }}</span></strong
                >
                <p>osób może otrzymać certyfikat</p>
                <em>{{ result.source }}</em>
              </div>
              @if (result.notFound.length) {
                <div class="not-found">
                  <strong>Nie znaleziono ({{ result.notFound.length }})</strong>
                  <p>{{ result.notFound.join(', ') }}</p>
                </div>
              }
              <div class="people-list">
                @for (user of result.users; track user.samAccountName) {
                  <div [class.blocked]="!user.issuable">
                    <span>{{ user.issuable ? '✓' : '!' }}</span>
                    <div>
                      <strong>{{ user.displayName }}</strong
                      ><small>{{ user.samAccountName }} · {{ user.upn || 'brak UPN' }}</small>
                    </div>
                    <em>{{ user.issuable ? 'Gotowy' : user.blockedBy }}</em>
                  </div>
                }
              </div>
            </div>
          }
          @if (errorFor() === 'resolve') {
            <div class="inline-error">{{ errorMessage() }}</div>
          }
        </article>

        <article class="diagnostic-card" data-step="3">
          <header>
            <span class="diagnostic-icon">⌾</span>
            <div>
              <p>TEST 03</p>
              <h3>Zakres uprawnień</h3>
              <small>Czy konto katalogowe ma tylko odczyt, czy może zrobić więcej?</small>
            </div>
          </header>
          <div class="probe-form access-form">
            <label
              >Konto osoby
              <input
                [value]="accessAccount()"
                (input)="accessAccount.set($any($event.target).value)"
                placeholder="admin"
              /><small>Uprawnienia są sprawdzane dla konkretnego obiektu osoby.</small></label
            ><button
              class="probe-button"
              [disabled]="busy() === 'access' || !accessAccount().trim()"
              (click)="testAccess()"
            >
              {{ busy() === 'access' ? 'Sprawdzanie…' : 'Sprawdź dostęp' }}
            </button>
          </div>
          @if (access(); as result) {
            <div class="access-result" [attr.data-tone]="accessTone(result)">
              <span>{{ !result.determined ? '?' : result.anythingExtra ? '↗' : '✓' }}</span>
              <div>
                <small>{{ result.subject }}</small
                ><strong>{{ accessTitle(result) }}</strong>
                <p>{{ result.detail }}</p>
                @if (result.determined && result.anythingExtra) {
                  <em>{{ result.wouldEnable }}</em>
                }
              </div>
              <ul>
                <li [class.yes]="result.userCertificate">userCertificate</li>
                <li [class.yes]="result.altSecurityIdentities">altSecurityIdentities</li>
              </ul>
            </div>
          }
          @if (errorFor() === 'access') {
            <div class="inline-error">{{ errorMessage() }}</div>
          }
        </article>

        <article class="panel about-row" id="about">
          <div>
            <span>B</span>
            <div>
              <h3>Blinky CMS</h3>
              <p>Angular 22 · API w tym samym originie · projekt open source</p>
            </div>
          </div>
          <em>v0.0.0</em>
        </article>
      </div>
    </section>
  </div>`,
})
export class DirectoryDiagnostics {
  private readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly token = signal('');
  protected readonly group = signal('');
  protected readonly accounts = signal('');
  protected readonly accessAccount = signal('');
  protected readonly busy = signal<'connection' | 'resolve' | 'access' | null>(null);
  protected readonly errorFor = signal<'connection' | 'resolve' | 'access' | null>(null);
  protected readonly errorMessage = signal('');
  protected readonly connection = signal<DirectoryConnectionResult | null>(null);
  protected readonly resolve = signal<DirectoryResolveResult | null>(null);
  protected readonly access = signal<DirectoryAccessResult | null>(null);
  protected save(event: Event): void {
    event.preventDefault();
    this.store.setOperatorToken(this.token());
    this.token.set('');
    void this.store.load(true);
  }
  protected async testConnection(): Promise<void> {
    await this.run('connection', () => this.store.testDirectory(), this.connection);
  }
  protected async testResolve(): Promise<void> {
    await this.run(
      'resolve',
      () => this.store.testDirectoryResolve(this.group().trim(), parseAccounts(this.accounts())),
      this.resolve,
    );
  }
  protected async testAccess(): Promise<void> {
    await this.run(
      'access',
      () => this.store.testDirectoryAccess(this.accessAccount().trim()),
      this.access,
    );
  }
  protected accessTone(result: DirectoryAccessResult): string {
    return directoryAccessTone(result);
  }
  protected accessTitle(result: DirectoryAccessResult): string {
    return directoryAccessTitle(result);
  }
  private async run<T>(
    kind: 'connection' | 'resolve' | 'access',
    action: () => Promise<T>,
    target: { set(value: T | null): void },
  ): Promise<void> {
    this.busy.set(kind);
    this.errorFor.set(null);
    try {
      target.set(await action());
    } catch (error) {
      target.set(null);
      this.errorFor.set(kind);
      this.errorMessage.set(this.describeError(error));
    } finally {
      this.busy.set(null);
    }
  }
  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      return error.error?.detail ?? error.error?.error ?? error.message;
    }
    return 'Nie udało się wykonać testu.';
  }
}

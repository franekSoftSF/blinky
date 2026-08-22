import { Component, inject, signal } from '@angular/core';
import { ConsoleStore } from '../core/console.store';

@Component({
  selector: 'app-operator-settings',
  template: ` <section class="settings-hero">
      <div>
        <p class="eyebrow">USTAWIENIA</p>
        <h1>Ustawienia konsoli</h1>
        <p>Dostęp operatora i informacje o lokalnej aplikacji.</p>
      </div>
      <div class="yubi-mark">
        <span>Y</span>
        <div><strong>YubiKey ready</strong><small>PIV management console</small></div>
      </div>
    </section>
    <section class="compact-settings">
      <article class="panel setting-section">
        <header>
          <div class="section-number">01</div>
          <div>
            <h2>Dostęp operatora</h2>
            <p>Autoryzacja zapytań administracyjnych</p>
          </div>
          <span class="privacy-badge">TYLKO PAMIĘĆ</span>
        </header>
        <div class="setting-body operator-setting">
          <div>
            <h3>Token sesji operatora</h3>
            <p>
              Token pozostaje wyłącznie w pamięci otwartej strony. Nie zapisujemy go w przeglądarce,
              adresie ani logach.
            </p>
            @if (message()) {
              <span class="connection-feedback" [attr.data-online]="connected()">{{
                message()
              }}</span>
            }
          </div>
          <div class="operator-connect">
            <label
              >Token operatora<input
                type="password"
                autocomplete="off"
                [value]="token()"
                (input)="token.set($any($event.target).value)"
                (keydown.enter)="connect()"
                placeholder="Wprowadź token…" /></label
            ><button
              class="primary"
              type="button"
              [disabled]="connecting() || !token().trim()"
              (click)="connect()"
            >
              {{ connecting() ? 'Łączenie…' : 'Połącz z API' }}
            </button>
          </div>
        </div>
      </article>
      <article class="panel about-row">
        <div>
          <span>B</span>
          <div>
            <h3>Blinky CMS</h3>
            <p>Angular 22 · API w tym samym originie · projekt open source</p>
          </div>
        </div>
        <em>v0.0.0</em>
      </article>
    </section>`,
})
export class OperatorSettings {
  private readonly store = inject(ConsoleStore);
  protected readonly token = signal('');
  protected readonly connecting = signal(false);
  protected readonly connected = signal(false);
  protected readonly message = signal('');
  protected async connect(): Promise<void> {
    const token = this.token().trim();
    if (!token || this.connecting()) return;
    this.connecting.set(true);
    this.message.set('');
    this.store.setOperatorToken(token);
    await this.store.load(true);
    this.connected.set(this.store.online());
    this.message.set(
      this.store.online()
        ? 'Połączono z API. Token pozostaje w pamięci tej strony.'
        : 'API odrzuciło token lub jest niedostępne. Pozostajesz na stronie ustawień.',
    );
    this.token.set('');
    this.connecting.set(false);
  }
}

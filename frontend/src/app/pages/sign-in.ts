import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AuthStore } from '../core/auth.store';

/**
 * Signing in to the console.
 *
 * One screen for the whole ceremony rather than a route per step: what changes
 * between steps is which field is in front of the person, and sending them to
 * a different address to type six digits loses the state that made the digits
 * meaningful.
 *
 * The password is kept in a signal for as long as the ceremony lasts, because
 * every step re-presents it - see the API side. It is cleared the moment a
 * session exists.
 */
@Component({
  selector: 'app-sign-in',
  template: `
    <section class="sign-in">
      <header>
        <p class="eyebrow">BLINKY CMS</p>
        <h1>Logowanie do konsoli</h1>
        <p class="lede">
          Konsola zarządza poświadczeniami na kartach. Dostęp do niej jest imienny, żeby audyt
          mógł powiedzieć, kto co zrobił.
        </p>
      </header>

      @if (auth.error(); as message) {
        <p class="sign-in-error" role="alert">{{ message }}</p>
      }

      <!-- Krok 1: kto i czym. -->
      @if (auth.stage() === 'credentials' || auth.stage() === 'totp-required') {
        <form class="sign-in-form" (submit)="submit($event)">
          <label>
            Nazwa konta
            <input
              name="username"
              autocomplete="username"
              [value]="username()"
              [readOnly]="auth.stage() === 'totp-required'"
              (input)="username.set($any($event.target).value)"
            />
          </label>

          <label>
            Hasło
            <input
              type="password"
              name="password"
              autocomplete="current-password"
              [value]="password()"
              [readOnly]="auth.stage() === 'totp-required'"
              (input)="password.set($any($event.target).value)"
            />
          </label>

          @if (auth.stage() === 'totp-required') {
            <label>
              Kod z aplikacji
              <input
                name="totp"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                placeholder="000000"
                [value]="code()"
                (input)="code.set($any($event.target).value)"
              />
            </label>
          }

          <button class="primary" type="submit" [disabled]="auth.busy() || !ready()">
            {{ auth.busy() ? 'Sprawdzanie…' : 'Zaloguj' }}
          </button>
        </form>
      }

      <!-- Krok 2a: hasło od instalatora kupuje dokładnie jedno logowanie. -->
      @if (auth.stage() === 'password-change-required') {
        <form class="sign-in-form" (submit)="changePassword($event)">
          <p class="sign-in-note">
            To konto ma hasło wygenerowane przy instalacji. Takie hasło leży w pliku, w historii
            powłoki i w pakiecie diagnostycznym, więc kupuje jedno logowanie — teraz ustaw własne.
          </p>

          <label>
            Nowe hasło
            <input
              type="password"
              name="new-password"
              autocomplete="new-password"
              [value]="newPassword()"
              (input)="newPassword.set($any($event.target).value)"
            />
          </label>

          <label>
            Powtórz nowe hasło
            <input
              type="password"
              name="repeat-password"
              autocomplete="new-password"
              [value]="repeated()"
              (input)="repeated.set($any($event.target).value)"
            />
          </label>

          <p class="sign-in-hint">
            Co najmniej dwanaście znaków. Długość jest jedyną regułą celowo: wymagania na wielką
            literę i cyfrę wypychają ludzi w stronę jednego wykrzyknika na końcu, a to mniejszy
            zbiór niż dłuższe zdanie.
          </p>

          <button class="primary" type="submit" [disabled]="auth.busy() || !passwordsAgree()">
            {{ auth.busy() ? 'Zapisywanie…' : 'Ustaw hasło' }}
          </button>
        </form>
      }

      <!-- Krok 2b: drugi składnik, wymagany od pierwszego logowania. -->
      @if (auth.stage() === 'totp-enrolment-required') {
        <div class="sign-in-form">
          @if (!auth.enrolment()) {
            <p class="sign-in-note">
              To konto nie ma jeszcze drugiego składnika. Drugi składnik, który można dodać
              później, to drugi składnik, którego nikt nie ma — więc wpinamy go teraz.
            </p>
            <button class="primary" type="button" [disabled]="auth.busy()" (click)="enrol()">
              {{ auth.busy() ? 'Przygotowywanie…' : 'Pokaż sekret' }}
            </button>
          } @else {
            <p class="sign-in-note">
              Wprowadź ten sekret do aplikacji uwierzytelniającej, a potem przepisz kod, który
              ona pokaże. Sekret staje się drugim składnikiem dopiero po pierwszym użyciu.
            </p>

            <label>
              Sekret
              <input readonly [value]="auth.enrolment()!.secret" (focus)="selectAll($event)" />
            </label>

            <label>
              Adres otpauth
              <input readonly [value]="auth.enrolment()!.uri" (focus)="selectAll($event)" />
            </label>

            <label>
              Kod z aplikacji
              <input
                name="totp"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                placeholder="000000"
                [value]="code()"
                (input)="code.set($any($event.target).value)"
              />
            </label>

            <button
              class="primary"
              type="button"
              [disabled]="auth.busy() || code().trim().length !== 6"
              (click)="submit()"
            >
              {{ auth.busy() ? 'Sprawdzanie…' : 'Potwierdź i zaloguj' }}
            </button>
          }
        </div>
      }
    </section>
  `,
  styles: [
    `
      .sign-in {
        max-width: 34rem;
        margin: 3rem auto;
        display: grid;
        gap: 1.5rem;
      }
      .sign-in h1 {
        margin: 0.25rem 0 0.5rem;
      }
      .lede {
        margin: 0;
        opacity: 0.75;
      }
      .sign-in-form {
        display: grid;
        gap: 1rem;
      }
      .sign-in-form label {
        display: grid;
        gap: 0.35rem;
      }
      .sign-in-form input {
        width: 100%;
      }
      .sign-in-note,
      .sign-in-hint {
        margin: 0;
        opacity: 0.8;
      }
      .sign-in-hint {
        font-size: 0.85rem;
      }
      .sign-in-error {
        margin: 0;
        padding: 0.75rem 1rem;
        border-left: 3px solid currentColor;
        color: #b3261e;
      }
    `,
  ],
})
export class SignIn implements OnInit {
  readonly auth = inject(AuthStore);
  private readonly router = inject(Router);

  readonly username = signal('');
  readonly password = signal('');
  readonly code = signal('');
  readonly newPassword = signal('');
  readonly repeated = signal('');

  /**
   * Takes credentials back out of the address bar.
   *
   * They should never arrive there, and for one build they did: the form was
   * bound with (ngSubmit) and nothing imported FormsModule, so the event never
   * fired and the browser submitted the form itself - as a GET, with the fields
   * as query parameters. A password in a URL is a password in the browser
   * history, in the proxy's access log, in the WAF's log and in the Referer
   * header of the next request.
   *
   * The bug is fixed above. This stays because the history entry survives the
   * fix, and because the next person to write a form here will make the same
   * mistake.
   */
  ngOnInit(): void {
    if (!location.search) return;

    const scrubbed = location.pathname + location.hash;
    history.replaceState(history.state, '', scrubbed);
  }

  ready(): boolean {
    if (!this.username().trim() || !this.password()) return false;
    return this.auth.stage() !== 'totp-required' || this.code().trim().length === 6;
  }

  passwordsAgree(): boolean {
    return this.newPassword().length >= 12 && this.newPassword() === this.repeated();
  }

  async submit(event?: Event): Promise<void> {
    event?.preventDefault();

    await this.auth.signIn(this.username().trim(), this.password(), this.code().trim() || undefined);

    if (this.auth.signedIn()) {
      // Nothing is kept once there is a session to keep instead.
      this.password.set('');
      this.code.set('');
      await this.router.navigateByUrl('/');
    }
  }

  async enrol(): Promise<void> {
    await this.auth.beginTotpEnrolment(this.username().trim(), this.password());
  }

  async changePassword(event?: Event): Promise<void> {
    event?.preventDefault();

    await this.auth.changePassword(this.username().trim(), this.password(), this.newPassword());

    // The new one becomes what the next step presents, because the ceremony
    // carries the password at every step.
    if (!this.auth.error()) {
      this.password.set(this.newPassword());
      this.newPassword.set('');
      this.repeated.set('');
      await this.submit();
    }
  }

  selectAll(event: Event): void {
    (event.target as HTMLInputElement).select();
  }
}

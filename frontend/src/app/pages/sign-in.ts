import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AuthStore } from '../core/auth.store';
import { I18n } from '../core/i18n';
import { toDataURL } from 'qrcode';

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
    <!-- A card in the middle of the page, as BlinkyLite's sign-in is: the two
         consoles are one family and the first screen is where that shows. -->
    <section class="sign-in">
     <div class="sign-in-card">
      <!-- The shell's language switch lives behind the sign-in, which is
           exactly where somebody who cannot read this page cannot reach it. -->
      <select
        class="sign-in-language"
        [value]="i18n.language()"
        (change)="i18n.use($any($event.target).value)"
        [attr.aria-label]="i18n.t('language')"
      >
        <option value="pl" [selected]="i18n.language() === 'pl'">polski</option>
        <option value="en" [selected]="i18n.language() === 'en'">English</option>
      </select>

      <header>
        <!-- The mark rather than the name in capitals: this is the first
             screen of the product, and it is where the mark is worth the
             space (brand/). -->
        <div class="sign-in-brand">
          <img class="mark" src="/brand/blinkycms-mark.svg" alt="" />
          <span>
            <span class="wordmark">Blinky<span class="cms">CMS</span></span>
            <small>{{ i18n.t('credentialConsole') }}</small>
          </span>
        </div>
        <h1>{{ i18n.t('signInTitle') }}</h1>
        <p class="lede">{{ i18n.t('signInLede') }}</p>
      </header>

      @if (auth.error(); as message) {
        <p class="sign-in-error" role="alert">{{ message }}</p>
      }

      @if (auth.stage() === 'credentials' || auth.stage() === 'totp-required') {
        <form class="sign-in-form" (submit)="submit($event)">
          <label>
            {{ i18n.t('accountName') }}
            <input
              name="username"
              autocomplete="username"
              [value]="username()"
              [readOnly]="auth.stage() === 'totp-required'"
              (input)="username.set($any($event.target).value)"
            />
          </label>

          <label>
            {{ i18n.t('passwordLabel') }}
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
              {{ i18n.t('codeLabel') }}
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
            {{ auth.busy() ? i18n.t('checking') : i18n.t('signInAction') }}
          </button>
        </form>
      }

      @if (auth.stage() === 'password-change-required') {
        <form class="sign-in-form" (submit)="changePassword($event)">
          <p class="sign-in-note">{{ i18n.t('bootstrapNote') }}</p>

          <label>
            {{ i18n.t('newPassword') }}
            <input
              type="password"
              name="new-password"
              autocomplete="new-password"
              [value]="newPassword()"
              (input)="newPassword.set($any($event.target).value)"
            />
          </label>

          <label>
            {{ i18n.t('repeatPassword') }}
            <input
              type="password"
              name="repeat-password"
              autocomplete="new-password"
              [value]="repeated()"
              (input)="repeated.set($any($event.target).value)"
            />
          </label>

          <p class="sign-in-hint">{{ i18n.t('passwordRule') }}</p>

          <button class="primary" type="submit" [disabled]="auth.busy() || !passwordsAgree()">
            {{ auth.busy() ? i18n.t('saving') : i18n.t('setPassword') }}
          </button>
        </form>
      }

      @if (auth.stage() === 'totp-enrolment-required') {
        <div class="sign-in-form">
          @if (!auth.enrolment()) {
            <p class="sign-in-note">{{ i18n.t('totpNeeded') }}</p>
            <button class="primary" type="button" [disabled]="auth.busy()" (click)="enrol()">
              {{ auth.busy() ? i18n.t('preparing') : i18n.t('showSecret') }}
            </button>
          } @else {
            <p class="sign-in-note">{{ i18n.t('scanNote') }}</p>

            @if (qr(); as image) {
              <figure class="qr">
                <img [src]="image" alt="" />
              </figure>
            }

            <!-- The secret stays reachable underneath. A QR code is nothing to
                 anybody using a screen reader, and unusable on the machine that
                 is also the telephone. -->
            <details>
              <summary>{{ i18n.t('cannotScan') }}</summary>
              <label>
                {{ i18n.t('secretLabel') }}
                <input readonly [value]="auth.enrolment()!.secret" (focus)="selectAll($event)" />
              </label>
            </details>

            <label>
              {{ i18n.t('codeLabel') }}
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
              {{ auth.busy() ? i18n.t('checking') : i18n.t('confirmAndSignIn') }}
            </button>
          }
        </div>
      }
     </div>
    </section>
  `,
  styles: [
    `
      .sign-in {
        display: grid;
        place-items: center;
        min-height: 100vh;
        padding: 16px;
      }
      .sign-in-card {
        position: relative;
        display: grid;
        gap: 20px;
        width: min(420px, 100%);
        padding: 32px;
        background: var(--bl-surface);
        border: 1px solid var(--bl-border);
        border-radius: 14px;
      }
      .sign-in-language {
        position: absolute;
        top: 16px;
        right: 16px;
        padding: 6px 10px;
        font-size: 13px;
      }
      .sign-in-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 24px;
      }
      .sign-in-brand .mark {
        display: block;
        flex: none;
        width: 64px;
        height: 64px;
      }
      .sign-in-brand small {
        display: block;
        color: var(--bl-text-muted);
        font-size: 13px;
      }
      .wordmark {
        display: block;
        font-size: 26px;
        line-height: 1.1;
        font-weight: 700;
        letter-spacing: -0.3px;
      }
      .wordmark .cms {
        color: var(--bl-accent-text);
      }
      .sign-in h1 {
        margin: 0 0 6px;
        font-size: 22px;
      }
      .lede {
        margin: 0;
        color: var(--bl-text-muted);
      }
      .sign-in-form {
        display: grid;
        gap: 1rem;
      }
      .sign-in-form label {
        display: grid;
        gap: 6px;
      }
      /* The fields the console draws everywhere else. Left to the browser they
         came out light grey on navy, which is the one part of this screen a
         person has to type into. */
      .sign-in-form input,
      details input {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--bl-border);
        border-radius: 8px;
        background: var(--bl-field);
        color: var(--bl-text);
      }
      .sign-in-form input[readonly] {
        opacity: 0.6;
      }
      .qr {
        margin: 0;
        display: grid;
        justify-items: center;
      }
      .qr img {
        width: 13rem;
        height: 13rem;
        /* The quiet zone the code needs, and the white ground it needs more: a
           scanner reading this on a dark theme finds no contrast at all. */
        background: #fff;
        padding: 0.75rem;
        border-radius: 4px;
      }
      details summary {
        cursor: pointer;
        opacity: 0.8;
        font-size: 0.85rem;
      }
      details label {
        display: grid;
        gap: 0.35rem;
        margin-top: 0.75rem;
      }
      .sign-in-note,
      .sign-in-hint {
        margin: 0;
        color: var(--bl-text-muted);
      }
      .sign-in-hint {
        font-size: 0.85rem;
      }
      /* #b3261e on this background is a dark red on a dark navy: the console's
         failure colour is lighter for exactly that reason. */
      .sign-in-error {
        margin: 0;
        padding: 0.75rem 1rem;
        border-left: 3px solid currentColor;
        color: var(--bl-danger);
      }
    `,
  ],
})
export class SignIn implements OnInit {
  readonly auth = inject(AuthStore);
  readonly i18n = inject(I18n);
  private readonly router = inject(Router);

  readonly username = signal('');
  readonly password = signal('');
  readonly code = signal('');
  readonly newPassword = signal('');
  readonly repeated = signal('');

  /** The otpauth URI as a picture, drawn here and never fetched. */
  readonly qr = signal<string | null>(null);

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

    history.replaceState(history.state, '', location.pathname + location.hash);
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
      this.qr.set(null);
      await this.router.navigateByUrl('/');
    }
  }

  async enrol(): Promise<void> {
    await this.auth.beginTotpEnrolment(this.username().trim(), this.password());

    const enrolment = this.auth.enrolment();
    if (!enrolment) return;

    // Drawn in the page, from the URI the API returned. Nothing is sent
    // anywhere to render it: a shared secret handed to a QR service is a
    // shared secret somebody else has.
    this.qr.set(
      await toDataURL(enrolment.uri, { margin: 1, width: 512, errorCorrectionLevel: 'M' }),
    );
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

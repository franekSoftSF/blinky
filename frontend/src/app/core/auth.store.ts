import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { readCookie } from './credentials.interceptor';
import { firstValueFrom } from 'rxjs';

/**
 * Where the sign-in ceremony currently stands.
 *
 * The names come from the API, which answers with what is missing rather than
 * only that something failed - a console that can say "now the six digits" is
 * a console somebody can follow.
 */
export type SignInStage =
  | 'credentials'
  | 'password-change-required'
  | 'totp-enrolment-required'
  | 'totp-required'
  | 'signed-in';

const CSRF_COOKIE = 'blinky_csrf';

interface SignInResponse {
  outcome: string;
  expires?: string;
  operatorName?: string;
  role?: string;
}

interface EnrolResponse {
  secret: string;
  uri: string;
}

/**
 * There is no token in here any more (0101).
 *
 * It used to live in `sessionStorage` and travel as `Authorization: Bearer`,
 * which meant every script on the page could read the one thing that lets
 * somebody revoke credentials and disclose PUKs. It is now a cookie the
 * browser will not show JavaScript, attached by the browser itself; what this
 * store keeps is who the person is, which is only enough to draw the shell.
 *
 * `blinky_csrf` is the readable half of double-submit and has the same
 * lifetime as the session, so its presence is what lets a refreshed page show
 * the console rather than the sign-in screen for as long as it takes to ask
 * the server. A stale one costs one 401 and a redirect, which is what
 * `forget()` is for.
 */
@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly http = inject(HttpClient);

  private readonly session = signal<boolean>(readCookie(CSRF_COOKIE) !== null);

  readonly stage = signal<SignInStage>(
    readCookie(CSRF_COOKIE) !== null ? 'signed-in' : 'credentials');
  readonly operatorName = signal<string | null>(null);
  readonly role = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  /** The secret and URI, shown once while a second factor is being enrolled. */
  readonly enrolment = signal<EnrolResponse | null>(null);

  readonly signedIn = computed(() => this.session());

  /**
   * Asks the server who this browser is, once, at startup.
   *
   * The cookie says a session existed when the page was last loaded; only the
   * server knows whether it still does, and whether it has been ended from
   * somewhere else in the meantime.
   */
  async restore(): Promise<void> {
    if (!this.session()) {
      return;
    }

    try {
      const me = await firstValueFrom(
        this.http.get<{ operatorName?: string; displayName?: string; role?: string }>('/api/auth/me'));

      this.operatorName.set(me.displayName ?? me.operatorName ?? null);
      this.role.set(me.role ?? null);
    } catch {
      this.forget();
    }
  }

  /**
   * The first step, and also the last: the same call finishes the ceremony once
   * a code is supplied. The password travels with it every time rather than
   * being exchanged for a half-finished ticket, which is what keeps one kind of
   * token in this system instead of two.
   */
  async signIn(username: string, password: string, totpCode?: string): Promise<void> {
    await this.run(async () => {
      const body: Record<string, string> = { username, password };
      if (totpCode) body['totpCode'] = totpCode;

      const response = await firstValueFrom(
        this.http.post<SignInResponse>('/api/auth/sign-in', body),
      );

      switch (response.outcome) {
        case 'signed-in':
          this.accept(response);
          break;
        case 'password-change-required':
        case 'totp-enrolment-required':
        case 'totp-required':
          this.stage.set(response.outcome);
          break;
        default:
          this.error.set(`Nieznana odpowiedź: ${response.outcome}`);
      }
    });
  }

  /** Asks for the secret to put into an authenticator. */
  async beginTotpEnrolment(username: string, password: string): Promise<void> {
    await this.run(async () => {
      this.enrolment.set(
        await firstValueFrom(
          this.http.post<EnrolResponse>('/api/auth/totp/enrol', { username, password }),
        ),
      );
    });
  }

  async changePassword(
    username: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(
        this.http.post('/api/auth/password', { username, currentPassword, newPassword }),
      );

      // Back to the beginning deliberately. The change ended every session the
      // old password founded, including any this browser held.
      this.stage.set('credentials');
    });
  }

  async signOut(): Promise<void> {
    try {
      await firstValueFrom(this.http.post('/api/auth/sign-out', {}));
    } catch {
      // The server may have ended it already, which is the same outcome.
    }

    this.forget();
  }

  /** Ends every session for this account, this one included. */
  async signOutEverywhere(): Promise<void> {
    await firstValueFrom(this.http.post('/api/auth/sessions/revoke-all', {}));
    this.forget();
  }

  /** Called when any request comes back 401, so a withdrawn session shows. */
  forget(): void {
    this.session.set(false);
    this.operatorName.set(null);
    this.role.set(null);
    this.enrolment.set(null);
    this.stage.set('credentials');
  }

  private accept(response: SignInResponse): void {
    // The session arrived as a cookie with this response; there is nothing to
    // store, and the readable half tells a later page load it was here.
    this.session.set(true);
    this.operatorName.set(response.operatorName ?? null);
    this.role.set(response.role ?? null);
    this.enrolment.set(null);
    this.stage.set('signed-in');
  }

  private async run(work: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);

    try {
      await work();
    } catch (error) {
      this.error.set(describe(error));
    } finally {
      this.busy.set(false);
    }
  }
}



/**
 * The server's own sentence where it sent one.
 *
 * It explains things this page cannot know - that an account is locked and
 * until when, or why a password was refused - and replacing that with "sign-in
 * failed" would throw away the only useful part of the response.
 */
function describe(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    const body = error.error as { error?: string; detail?: string; until?: string } | null;

    if (body?.error) {
      const until = body.until ? ` (do ${new Date(body.until).toLocaleTimeString()})` : '';
      return body.detail ? `${body.error}${until} — ${body.detail}` : `${body.error}${until}`;
    }

    if (error.status === 0) return 'Brak połączenia z API.';
  }

  return error instanceof Error ? error.message : 'Nie udało się zalogować.';
}

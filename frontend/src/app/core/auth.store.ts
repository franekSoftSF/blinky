import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
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

interface SignInResponse {
  outcome: string;
  token?: string;
  expires?: string;
  operatorName?: string;
  role?: string;
}

interface EnrolResponse {
  secret: string;
  uri: string;
}

/**
 * The session token lives in `sessionStorage`, which is a change of stance from
 * the shared operator token and deserves its reason.
 *
 * That token was kept in memory only, because it was one secret shared by
 * everybody, it never expired and nothing could withdraw it - anything that
 * outlived the tab was a liability. A session token is the opposite on all
 * three counts: it belongs to one person, it dies of idleness and of age, and
 * an administrator can end it from the server in the second they decide to.
 * Those are exactly the properties that make surviving a page refresh
 * acceptable, and being logged out by F5 is how an administrative console
 * teaches people to leave themselves signed in somewhere else.
 */
const STORAGE_KEY = 'blinky.session';

@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly http = inject(HttpClient);

  private readonly token = signal<string>(readStoredToken());

  readonly stage = signal<SignInStage>(readStoredToken() ? 'signed-in' : 'credentials');
  readonly operatorName = signal<string | null>(null);
  readonly role = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  /** The secret and URI, shown once while a second factor is being enrolled. */
  readonly enrolment = signal<EnrolResponse | null>(null);

  readonly signedIn = computed(() => this.token().length > 0);

  /** For every other request the console makes. */
  authorization(): HttpHeaders | undefined {
    const token = this.token();
    return token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;
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
    const headers = this.authorization();

    if (headers) {
      try {
        await firstValueFrom(this.http.post('/api/auth/sign-out', {}, { headers }));
      } catch {
        // The server may have ended it already, which is the same outcome.
      }
    }

    this.forget();
  }

  /** Ends every session for this account, this one included. */
  async signOutEverywhere(): Promise<void> {
    const headers = this.authorization();

    if (headers) {
      await firstValueFrom(this.http.post('/api/auth/sessions/revoke-all', {}, { headers }));
    }

    this.forget();
  }

  /** Called when any request comes back 401, so a withdrawn session shows. */
  forget(): void {
    this.token.set('');
    this.operatorName.set(null);
    this.role.set(null);
    this.enrolment.set(null);
    this.stage.set('credentials');

    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // A browser with storage disabled simply keeps nothing.
    }
  }

  private accept(response: SignInResponse): void {
    this.token.set(response.token ?? '');
    this.operatorName.set(response.operatorName ?? null);
    this.role.set(response.role ?? null);
    this.enrolment.set(null);
    this.stage.set('signed-in');

    try {
      sessionStorage.setItem(STORAGE_KEY, response.token ?? '');
    } catch {
      // Not fatal: the session simply does not survive a refresh.
    }
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

function readStoredToken(): string {
  try {
    return sessionStorage.getItem(STORAGE_KEY) ?? '';
  } catch {
    return '';
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

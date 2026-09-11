import { Component, computed, effect, inject, signal } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';
import { AuthStore } from './core/auth.store';
import { ConsoleStore } from './core/console.store';
import { I18n } from './core/i18n';
import { Theme } from './core/theme';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  private readonly router = inject(Router);
  private readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly theme = inject(Theme);
  protected readonly auth = inject(AuthStore);

  /**
   * Whether to draw the console around the page at all.
   *
   * Somebody who is not signed in was being shown the whole navigation tree
   * with a sign-in form inside it - a menu of pages they cannot open, in front
   * of the one thing they can do. The shell is for people who are past the
   * door.
   */
  protected readonly signedIn = this.auth.signedIn;

  /** Reachable from every page, because that is where somebody leaving is. */
  protected async signOut(): Promise<void> {
    await this.auth.signOut();
    await this.router.navigateByUrl('/sign-in');
  }
  protected readonly menuOpen = signal(false);
  protected readonly administrationOpen = signal(true);
  protected readonly apiOnline = this.store.online;
  protected readonly environment = computed(() =>
    location.hostname === 'localhost' ? this.i18n.t('local') : location.hostname,
  );
  protected readonly navigation = computed(() => [
    { path: '/', label: this.i18n.t('overview'), icon: '◫' },
    { path: '/tokens', label: this.i18n.t('tokens'), icon: '◇' },
    { path: '/certificates', label: this.i18n.t('certificates'), icon: '▤' },
    { path: '/agents', label: this.i18n.t('agents'), icon: '⌁' },
    { path: '/jobs', label: this.i18n.t('jobs'), icon: '↯' },
  ]);
  protected readonly administration = computed(() => [
    { path: '/directory', label: this.i18n.t('directory'), icon: '⌁' },
    { path: '/system', label: this.i18n.t('deployment'), icon: '◆' },
    { path: '/settings', label: this.i18n.t('settings'), icon: '⚙' },
  ]);
  private readonly currentUrl = signal(this.router.url);
  protected readonly section = computed(
    () =>
      [...this.navigation(), ...this.administration()].find((n) => n.path === this.currentUrl())
        ?.label ?? 'Blinky',
  );

  constructor() {
    this.router.events
      .pipe(filter((e) => e instanceof NavigationEnd))
      .subscribe((e) => this.currentUrl.set((e as NavigationEnd).urlAfterRedirects));
    // Loaded when there is a session, not once at startup.
    //
    // The constructor runs before anybody has signed in, so the single call
    // that used to be here always ran unauthenticated, always came back 401,
    // and left "API data unavailable" on the screen for the rest of the
    // session - including after somebody signed in, because nothing ever asked
    // again. The console looked broken while its own logs showed a live
    // session doing nothing.
    effect(() => {
      if (this.auth.signedIn()) {
        void this.store.load(true);
      }
    });
  }
  protected refresh(): void {
    void this.store.load(true);
  }
}

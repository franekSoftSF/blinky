import { Component, computed, inject, signal } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';
import { ConsoleStore } from './core/console.store';
import { I18n } from './core/i18n';
import { Theme } from './core/theme';

@Component({ selector: 'app-root', imports: [RouterOutlet, RouterLink, RouterLinkActive], templateUrl: './app.html', styleUrl: './app.scss' })
export class App {
  private readonly router = inject(Router);
  private readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly theme = inject(Theme);
  protected readonly menuOpen = signal(false);
  protected readonly apiOnline = this.store.online;
  protected readonly environment = computed(() => location.hostname === 'localhost' ? this.i18n.t('local') : location.hostname);
  protected readonly navigation = computed(() => [
    { path: '/', label: this.i18n.t('overview'), icon: '◫' }, { path: '/tokens', label: this.i18n.t('tokens'), icon: '◇' },
    { path: '/certificates', label: this.i18n.t('certificates'), icon: '▤' }, { path: '/agents', label: this.i18n.t('agents'), icon: '⌁' },
    { path: '/jobs', label: this.i18n.t('jobs'), icon: '↯' }, { path: '/settings', label: this.i18n.t('settings'), icon: '⚙' },
  ]);
  private readonly currentUrl = signal(this.router.url);
  protected readonly section = computed(() => this.navigation().find(n => n.path === this.currentUrl())?.label ?? 'Blinky');

  constructor() {
    this.router.events.pipe(filter(e => e instanceof NavigationEnd)).subscribe(e => this.currentUrl.set((e as NavigationEnd).urlAfterRedirects));
    void this.store.load();
  }
  protected refresh(): void { void this.store.load(true); }
}

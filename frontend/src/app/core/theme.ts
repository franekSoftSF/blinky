import { Injectable, signal } from '@angular/core';

export type ThemeName = 'dark' | 'light';

@Injectable({ providedIn: 'root' })
export class Theme {
  readonly current = signal<ThemeName>(
    localStorage.getItem('blinky.theme') === 'light' ? 'light' : 'dark');

  constructor() { this.apply(this.current()); }

  toggle(): void { this.apply(this.current() === 'dark' ? 'light' : 'dark'); }

  private apply(theme: ThemeName): void {
    this.current.set(theme);
    document.documentElement.dataset['theme'] = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem('blinky.theme', theme);
  }
}

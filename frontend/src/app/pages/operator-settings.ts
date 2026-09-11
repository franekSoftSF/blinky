import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthStore } from '../core/auth.store';
import { I18n } from '../core/i18n';

/**
 * Console settings.
 *
 * The first section used to be a box for pasting the shared operator token.
 * Patch 0053e removed the token, so the question this page answers changed
 * from "what secret are you holding" to "who are you, and how do you stop".
 */
@Component({
  selector: 'app-operator-settings',
  template: ` <section class="settings-hero">
      <div>
        <p class="eyebrow">USTAWIENIA</p>
        <h1>Ustawienia konsoli</h1>
        <p>Twoja sesja i informacje o aplikacji.</p>
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
            <h2>{{ i18n.t('thisSession') }}</h2>
            <p>{{ i18n.t('whoSignedIn') }}</p>
          </div>
          <span class="privacy-badge">SESJA</span>
        </header>
        <div class="setting-body operator-setting">
          <div>
            <h3>{{ auth.operatorName() ?? i18n.t('notSignedIn') }}</h3>
            <p>{{ i18n.t('roleLabel') }}: {{ auth.role() ?? '—' }}. {{ i18n.t('sessionNote') }}</p>
          </div>
          <div class="operator-connect">
            <button class="primary" type="button" (click)="signOut()">{{ i18n.t('signOut') }}</button>
            <button type="button" (click)="signOutEverywhere()">{{ i18n.t('signOutEverywhere') }}</button>
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
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthStore);
  protected readonly i18n = inject(I18n);

  protected async signOut(): Promise<void> {
    await this.auth.signOut();
    await this.router.navigateByUrl('/sign-in');
  }

  /**
   * Including the session that asked.
   *
   * "Everywhere" that quietly means "everywhere else" is the wrong answer when
   * somebody presses it because they believe their session has been taken.
   */
  protected async signOutEverywhere(): Promise<void> {
    await this.auth.signOutEverywhere();
    await this.router.navigateByUrl('/sign-in');
  }
}

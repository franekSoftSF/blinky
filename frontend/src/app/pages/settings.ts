import { Component, inject, signal } from '@angular/core';
import { ConsoleStore } from '../core/console.store';
import { I18n } from '../core/i18n';

@Component({ selector:'app-settings', template:`
  <section class="list-head"><div><p class="eyebrow">{{ i18n.t('configuration') }}</p><h1>{{ i18n.t('consoleSettings') }}</h1><p>{{ i18n.t('settingsText') }}</p></div></section>
  <article class="panel settings"><div class="setting-copy"><h2>{{ i18n.t('operatorAccess') }}</h2><p>{{ i18n.t('operatorHelp') }}</p></div>
    <form (submit)="save($event)"><label>{{ i18n.t('operatorToken') }}<input type="password" autocomplete="off" [value]="token()" (input)="token.set($any($event.target).value)" [placeholder]="i18n.t('enterToken')" /></label><button class="primary" type="submit">{{ i18n.t('saveConnect') }}</button></form>
  </article>
  <article class="panel settings"><div class="setting-copy"><h2>{{ i18n.t('about') }}</h2><p>{{ i18n.t('aboutText') }}</p></div><span class="pill">{{ i18n.t('openSource') }}</span></article>`, })
export class Settings {
  private readonly store=inject(ConsoleStore); protected readonly i18n=inject(I18n); protected readonly token=signal(sessionStorage.getItem('blinky.operatorToken')??'');
  protected save(event:Event):void { event.preventDefault(); const value=this.token().trim(); if(value) sessionStorage.setItem('blinky.operatorToken',value); else sessionStorage.removeItem('blinky.operatorToken'); void this.store.load(true); }
}

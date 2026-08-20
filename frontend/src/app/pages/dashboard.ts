import { DatePipe } from '@angular/common';
import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ConsoleStore } from '../core/console.store';
import { I18n } from '../core/i18n';

@Component({ selector: 'app-dashboard', imports: [DatePipe, RouterLink], template: `
  <section class="welcome"><div><p class="eyebrow">{{ i18n.t('environmentState') }}</p><h1>{{ i18n.t('hello') }}</h1><p>{{ i18n.t('helloText') }}</p></div><button class="primary" (click)="store.load(true)">↻ {{ i18n.t('refreshData') }}</button></section>
  @if (store.error()) { <div class="notice"><strong>{{ i18n.t('noApi') }}</strong><span>{{ i18n.t('noApiText') }}</span></div> }
  <section class="metrics">@for (card of metrics(); track card.label) { <a class="metric" [routerLink]="card.path"><span class="metric-icon">{{ card.icon }}</span><div><small>{{ card.label }}</small><strong>{{ card.value }}</strong><em>{{ card.note }}</em></div></a> }</section>
  <section class="grid"><article class="panel activity"><header><div><h2>{{ i18n.t('recentJobs') }}</h2><p>{{ i18n.t('sentOperations') }}</p></div><a routerLink="/jobs">{{ i18n.t('all') }} →</a></header>
    @if (recentJobs().length) { <div class="table-wrap"><table><thead><tr><th>{{ i18n.t('operation') }}</th><th>{{ i18n.t('token') }}</th><th>{{ i18n.t('status') }}</th><th>{{ i18n.t('created') }}</th></tr></thead><tbody>@for (job of recentJobs(); track job.id) { <tr><td><strong>{{ job.type }}</strong></td><td>{{ job.tokenSerial ?? '—' }}</td><td><span class="state" [attr.data-state]="job.state">{{ job.state }}</span></td><td>{{ job.createdAt | date:'short' }}</td></tr> }</tbody></table></div> }
    @else { <div class="empty"><span>↯</span><strong>{{ i18n.t('noJobs') }}</strong><p>{{ i18n.t('newJobsHere') }}</p></div> }
  </article><article class="panel health"><header><div><h2>{{ i18n.t('serviceHealth') }}</h2><p>{{ i18n.t('platformComponents') }}</p></div></header>
    <div class="health-row"><span class="service-icon">A</span><div><strong>Blinky API</strong><small>{{ i18n.t('managementApi') }}</small></div><span class="pill" [class.muted]="!store.online()">{{ store.online() ? i18n.t('works') : i18n.t('noConnection') }}</span></div>
    <div class="health-row"><span class="service-icon">CA</span><div><strong>{{ i18n.t('ca') }}</strong><small>{{ i18n.t('builtinPki') }}</small></div><span class="pill">{{ i18n.t('configured') }}</span></div>
    <div class="health-row"><span class="service-icon">DB</span><div><strong>PostgreSQL</strong><small>{{ i18n.t('stateHistory') }}</small></div><span class="pill">{{ i18n.t('throughApi') }}</span></div>
  </article></section>`, })
export class Dashboard {
  protected readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly recentJobs = computed(() => this.store.snapshot().jobs.slice(0, 6));
  protected readonly metrics = computed(() => { const d=this.store.snapshot(); const expiring=d.credentials.filter(c=>c.notAfter&&new Date(c.notAfter).getTime()-Date.now()<30*86400000).length; return [
    {label:this.i18n.t('tokens'),value:d.tokens.length,note:`${d.tokens.filter(t=>t.state==='Active').length} ${this.i18n.t('active')}`,icon:'◇',path:'/tokens'},
    {label:this.i18n.t('certificates'),value:d.credentials.length,note:`${expiring} ${this.i18n.t('expiresSoon')}`,icon:'▤',path:'/certificates'},
    {label:this.i18n.t('agents'),value:d.agents.filter(a=>a.state==='Enrolled').length,note:`${d.agents.length} ${this.i18n.t('registered')}`,icon:'⌁',path:'/agents'},
    {label:this.i18n.t('runningJobs'),value:d.jobs.filter(j=>['Pending','Claimed','Running','AwaitingUser'].includes(j.state)).length,note:this.i18n.t('queue'),icon:'↯',path:'/jobs'} ]; });
}

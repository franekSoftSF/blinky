import { DatePipe } from '@angular/common';
import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ConsoleStore } from '../core/console.store';
import { I18n } from '../core/i18n';

@Component({
  selector: 'app-dashboard',
  imports: [DatePipe, RouterLink],
  template: `
    <section class="page-hero">
      <div><p class="eyebrow">{{ i18n.t('environmentState') }}</p><h1>{{ i18n.t('hello') }}</h1><p>{{ i18n.t('helloText') }}</p></div>
      <button class="action-button" type="button" (click)="store.load(true)">
        <span aria-hidden="true">↻</span>
        {{ i18n.t('refreshData') }}
      </button>
    </section>

    @if (store.error()) { <div class="notice"><strong>{{ i18n.t('noApi') }}</strong><span>{{ i18n.t('noApiText') }}</span></div> }

    <section class="metric-grid" aria-label="Summary">
      @for (card of metrics(); track card.label) {
        <a class="metric-card" [routerLink]="card.path">
          <span class="metric-symbol">{{ card.icon }}</span>
          <span class="metric-copy"><small>{{ card.label }}</small><strong>{{ card.value }}</strong><em>{{ card.note }}</em></span>
          <span class="card-arrow">→</span>
        </a>
      }
    </section>

    <section class="section-heading"><div><p class="eyebrow">MONITORING</p><h2>{{ i18n.t('serviceHealth') }}</h2></div><p>{{ i18n.t('platformComponents') }}</p></section>
    <section class="monitor-grid">
      <article class="monitor-card" [class.unavailable]="!store.online()">
        <header><span class="service-symbol">API</span><span class="health-light"></span></header>
        <h3>Blinky API</h3><p>{{ i18n.t('managementApi') }}</p>
        <footer><span>{{ store.online() ? i18n.t('works') : i18n.t('noConnection') }}</span><strong>{{ store.online() ? '200 OK' : '—' }}</strong></footer>
      </article>
      <article class="monitor-card">
        <header><span class="service-symbol">CA</span><span class="health-light"></span></header>
        <h3>{{ i18n.t('ca') }}</h3><p>{{ i18n.t('builtinPki') }}</p>
        <footer><span>{{ i18n.t('configured') }}</span><strong>PKI</strong></footer>
      </article>
      <article class="monitor-card">
        <header><span class="service-symbol">DB</span><span class="health-light"></span></header>
        <h3>PostgreSQL</h3><p>{{ i18n.t('stateHistory') }}</p>
        <footer><span>{{ i18n.t('throughApi') }}</span><strong>SQL</strong></footer>
      </article>
    </section>

    <article class="panel activity-panel">
      <header><div><h2>{{ i18n.t('recentJobs') }}</h2><p>{{ i18n.t('sentOperations') }}</p></div><a routerLink="/jobs">{{ i18n.t('all') }} →</a></header>
      @if (recentJobs().length) {
        <div class="table-wrap"><table><thead><tr><th>{{ i18n.t('operation') }}</th><th>{{ i18n.t('token') }}</th><th>{{ i18n.t('status') }}</th><th>{{ i18n.t('created') }}</th></tr></thead><tbody>
          @for (job of recentJobs(); track job.id) { <tr><td><strong>{{ job.type }}</strong></td><td>{{ job.tokenSerial ?? '—' }}</td><td><span class="state" [attr.data-state]="job.state">{{ job.state }}</span></td><td>{{ job.createdAt | date:'short' }}</td></tr> }
        </tbody></table></div>
      } @else { <div class="empty"><span>↯</span><strong>{{ i18n.t('noJobs') }}</strong><p>{{ i18n.t('newJobsHere') }}</p></div> }
    </article>
  `,
})
export class Dashboard {
  protected readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);
  protected readonly recentJobs = computed(() => this.store.snapshot().jobs.slice(0, 6));
  protected readonly metrics = computed(() => {
    const data = this.store.snapshot();
    const expiring = data.credentials.filter(c => c.notAfter && new Date(c.notAfter).getTime() - Date.now() < 30 * 86400000).length;
    return [
      { label:this.i18n.t('tokens'), value:data.tokens.length, note:`${data.tokens.filter(t => t.state === 'Active').length} ${this.i18n.t('active')}`, icon:'T', path:'/tokens' },
      { label:this.i18n.t('certificates'), value:data.credentials.length, note:`${expiring} ${this.i18n.t('expiresSoon')}`, icon:'C', path:'/certificates' },
      { label:this.i18n.t('agents'), value:data.agents.filter(a => a.state === 'Enrolled').length, note:`${data.agents.length} ${this.i18n.t('registered')}`, icon:'A', path:'/agents' },
      { label:this.i18n.t('runningJobs'), value:data.jobs.filter(j => ['Pending','Claimed','Running','AwaitingUser'].includes(j.state)).length, note:this.i18n.t('queue'), icon:'J', path:'/jobs' },
    ];
  });
}

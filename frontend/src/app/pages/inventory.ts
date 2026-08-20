import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ConsoleStore } from '../core/console.store';
import { I18n } from '../core/i18n';

@Component({ selector: 'app-inventory', template: `
  <section class="list-head"><div><p class="eyebrow">{{ i18n.t('inventory') }}</p><h1>{{ title() }}</h1><p>{{ subtitle() }}</p></div><div class="list-actions"><label class="search">⌕ <input [placeholder]="i18n.t('search')" (input)="query.set($any($event.target).value)" /></label><button class="primary">+ {{ i18n.t('newOperation') }}</button></div></section>
  <article class="panel list-panel"><div class="table-wrap"><table><thead><tr>@for (column of columns(); track column) { <th>{{ column }}</th> }</tr></thead><tbody>
    @for (row of rows(); track row.id) { <tr>@for (cell of row.cells; track $index) { <td>@if ($index === 0) { <strong>{{ cell }}</strong> } @else if ($index === row.stateIndex) { <span class="state" [attr.data-state]="cell">{{ cell }}</span> } @else { {{ cell }} }</td> }</tr> }
  </tbody></table></div>@if (!rows().length) { <div class="empty"><span>{{ icon() }}</span><strong>{{ i18n.t('noData') }}</strong><p>{{ i18n.t('noDataText') }}</p></div> }</article>`, })
export class Inventory {
  protected readonly store=inject(ConsoleStore); protected readonly i18n=inject(I18n); private readonly route=inject(ActivatedRoute); protected readonly query=signal('');
  protected readonly kind=this.route.snapshot.data['kind'] as 'tokens'|'certificates'|'agents'|'jobs';
  protected readonly title=computed(()=>({tokens:this.i18n.t('pivTokens'),certificates:this.i18n.t('certificates'),agents:this.i18n.t('agentsTitle'),jobs:this.i18n.t('jobs')})[this.kind]);
  protected readonly subtitle=computed(()=>({tokens:this.i18n.t('tokensText'),certificates:this.i18n.t('certsText'),agents:this.i18n.t('agentsText'),jobs:this.i18n.t('jobsText')})[this.kind]);
  protected readonly icon=computed(()=>({tokens:'◇',certificates:'▤',agents:'⌁',jobs:'↯'})[this.kind]);
  protected readonly columns=computed(()=>({tokens:[this.i18n.t('serial'),this.i18n.t('model'),this.i18n.t('firmware'),this.i18n.t('pin'),this.i18n.t('status')],certificates:[this.i18n.t('subject'),this.i18n.t('tokenSlot'),this.i18n.t('validTo'),this.i18n.t('status')],agents:[this.i18n.t('hostname'),this.i18n.t('domain'),this.i18n.t('version'),this.i18n.t('lastSeen'),this.i18n.t('status')],jobs:[this.i18n.t('operation'),this.i18n.t('token'),this.i18n.t('attempt'),this.i18n.t('created'),this.i18n.t('status')]})[this.kind]);
  protected readonly rows=computed(()=>{ const s=this.store.snapshot(); let rows:{id:string;stateIndex:number;cells:string[]}[];
    if(this.kind==='tokens') rows=s.tokens.map(x=>({id:x.id,stateIndex:4,cells:[String(x.serial),x.formFactor??'Token PIV',x.firmwareVersion??'—',x.pinState,x.state]}));
    else if(this.kind==='certificates') rows=s.credentials.map(x=>({id:x.id,stateIndex:3,cells:[x.subjectDn??'Bez nazwy',`${x.tokenSerial} / ${x.slotId}`,x.notAfter?new Date(x.notAfter).toLocaleDateString():'—',x.state]}));
    else if(this.kind==='agents') rows=s.agents.map(x=>({id:x.id,stateIndex:4,cells:[x.hostname,x.domain,x.version??'—',x.lastHeartbeatAt?new Date(x.lastHeartbeatAt).toLocaleString():'—',x.state]}));
    else rows=s.jobs.map(x=>({id:x.id,stateIndex:4,cells:[x.type,String(x.tokenSerial??'—'),String(x.attempt),new Date(x.createdAt).toLocaleString(),x.state]}));
    const q=this.query().trim().toLocaleLowerCase(); return q?rows.filter(r=>r.cells.some(c=>c.toLocaleLowerCase().includes(q))):rows; });
}

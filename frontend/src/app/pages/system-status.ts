import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ConsoleStore, SystemStatus } from '../core/console.store';
import { crlTone, custodyLabel, custodyTone } from '../core/system-status-presentation';

@Component({
  selector: 'app-system-status',
  imports: [DatePipe],
  template: ` <section class="status-hero">
      <div>
        <p class="eyebrow">STAN WDROŻENIA</p>
        <h1>Bezpieczeństwo i infrastruktura</h1>
        <p>
          Jedna odpowiedź API pokazuje, czy to wdrożenie jest gotowe do pracy i gdzie przechowywane
          są klucze.
        </p>
      </div>
      <button class="primary" [disabled]="loading()" (click)="load()">
        {{ loading() ? 'Sprawdzanie…' : 'Odśwież stan' }}
      </button>
    </section>
    @if (error()) {
      <div class="notice">
        <strong>Nie udało się pobrać stanu wdrożenia</strong><span>{{ error() }}</span>
      </div>
    }
    @if (status(); as s) {
      <section class="deployment-summary">
        <article>
          <span>CA</span>
          <div>
            <small>URZĄD CERTYFIKACJI</small><strong>{{ s.certificateAuthority.name }}</strong
            ><em>{{
              s.certificateAuthority.canIssueLogonCredentials
                ? 'Może wydawać certyfikaty logowania'
                : 'Nie wydaje certyfikatów logowania domenowego'
            }}</em>
          </div>
        </article>
        <article [attr.data-tone]="custodyTone(s.keyCustody)">
          <span>KEY</span>
          <div>
            <small>OCHRONA KLUCZA</small
            ><strong>{{ s.keyCustody?.tier ?? s.certificateAuthority.backend }}</strong
            ><em>{{ custodyLabel(s.keyCustody) }}</em>
          </div>
        </article>
        <article [attr.data-tone]="crlTone(s.revocationList)">
          <span>CRL</span>
          <div>
            <small>LISTA ODWOŁAŃ</small
            ><strong>{{
              s.revocationList.expired
                ? 'Wygasła'
                : s.revocationList.published
                  ? 'Aktualna'
                  : 'Nieopublikowana'
            }}</strong
            ><em>{{
              s.revocationList.nextUpdate
                ? (s.revocationList.nextUpdate | date: 'medium')
                : 'Brak terminu'
            }}</em>
          </div>
        </article>
        <article>
          <span>AG</span>
          <div>
            <small>AGENCI</small><strong>{{ s.agents.enrolled }} / {{ s.agents.total }}</strong
            ><em>zarejestrowani</em>
          </div>
        </article>
      </section>

      <article class="infrastructure-card key-custody" [attr.data-tone]="custodyTone(s.keyCustody)">
        <header>
          <div>
            <span class="infra-icon">◆</span>
            <div>
              <p>KEY CUSTODY</p>
              <h2>Gdzie znajduje się klucz podpisujący</h2>
            </div>
          </div>
          <span class="infra-state">{{ custodyLabel(s.keyCustody) }}</span>
        </header>
        @if (s.keyCustody; as custody) {
          <div class="custody-current">
            <div class="tier-name">
              <small>AKTYWNY POZIOM</small><strong>{{ custody.tier }}</strong
              ><em>{{ custody.description }}</em>
            </div>
            <p>{{ custody.detail }}</p>
          </div>
          <div class="tier-list">
            @for (tier of custody.available; track tier.tier) {
              <div
                [class.current]="tier.tier === custody.tier"
                [class.unavailable]="!tier.implemented"
              >
                <span>{{
                  tier.tier === 'File' ? 'FILE' : tier.tier === 'SoftHsm' ? 'S-HSM' : 'HSM'
                }}</span>
                <div>
                  <strong>{{ tier.tier }}</strong>
                  <p>{{ tier.detail }}</p>
                </div>
                <em>{{
                  tier.tier === custody.tier
                    ? 'Aktywny'
                    : tier.implemented
                      ? 'Dostępny'
                      : 'Jeszcze niezaimplementowany'
                }}</em>
              </div>
            }
          </div>
        } @else {
          <div class="custody-current">
            <p>Kluczem zarządza zewnętrzny backend urzędu certyfikacji.</p>
          </div>
        }
      </article>

      <section class="infra-grid">
        <article class="infrastructure-card">
          <header>
            <div>
              <span class="infra-icon">CA</span>
              <div>
                <p>CERTIFICATE AUTHORITY</p>
                <h2>{{ s.certificateAuthority.backend }}</h2>
              </div>
            </div>
          </header>
          <dl>
            <div>
              <dt>Topologia</dt>
              <dd>{{ s.certificateAuthority.topology ?? '—' }}</dd>
            </div>
            <div>
              <dt>Issuer</dt>
              <dd>{{ s.certificateAuthority.issuer ?? '—' }}</dd>
            </div>
            <div>
              <dt>Trust anchor</dt>
              <dd>{{ s.certificateAuthority.anchor ?? '—' }}</dd>
            </div>
            <div>
              <dt>Ważność anchor</dt>
              <dd>
                {{
                  s.certificateAuthority.anchorNotAfter
                    ? (s.certificateAuthority.anchorNotAfter | date: 'mediumDate')
                    : '—'
                }}
              </dd>
            </div>
          </dl>
        </article>
        <article class="infrastructure-card" [attr.data-tone]="crlTone(s.revocationList)">
          <header>
            <div>
              <span class="infra-icon">CRL</span>
              <div>
                <p>REVOCATION</p>
                <h2>
                  {{
                    s.revocationList.expired
                      ? 'CRL wygasła'
                      : s.revocationList.published
                        ? 'CRL opublikowana'
                        : 'CRL nieopublikowana'
                  }}
                </h2>
              </div>
            </div>
          </header>
          <dl>
            <div>
              <dt>Ścieżka</dt>
              <dd>{{ s.revocationList.path }}</dd>
            </div>
            <div>
              <dt>This update</dt>
              <dd>
                {{
                  s.revocationList.thisUpdate ? (s.revocationList.thisUpdate | date: 'medium') : '—'
                }}
              </dd>
            </div>
            <div>
              <dt>Next update</dt>
              <dd>
                {{
                  s.revocationList.nextUpdate ? (s.revocationList.nextUpdate | date: 'medium') : '—'
                }}
              </dd>
            </div>
            <div>
              <dt>Publiczny URL</dt>
              <dd>{{ s.revocationList.url ?? '—' }}</dd>
            </div>
          </dl>
        </article>
        <article class="infrastructure-card">
          <header>
            <div>
              <span class="infra-icon">DIR</span>
              <div>
                <p>DIRECTORY</p>
                <h2>{{ s.directory.configured ? s.directory.source : 'Nie skonfigurowano' }}</h2>
              </div>
            </div>
            <span class="read-only-badge">{{
              s.directory.writesAnything ? 'WRITE ACCESS' : 'TYLKO ODCZYT'
            }}</span>
          </header>
          <dl>
            <div>
              <dt>Host</dt>
              <dd>{{ s.directory.host ?? '—' }}</dd>
            </div>
            <div>
              <dt>Base DN</dt>
              <dd>{{ s.directory.baseDn ?? '—' }}</dd>
            </div>
            <div>
              <dt>Uwierzytelniono jako</dt>
              <dd>{{ s.directory.boundAs }}</dd>
            </div>
          </dl>
          <p class="reassurance">Blinky nie zapisuje dziś niczego w katalogu.</p>
        </article>
        <article class="infrastructure-card">
          <header>
            <div>
              <span class="infra-icon">AG</span>
              <div>
                <p>WORKSTATIONS</p>
                <h2>{{ s.agents.enrolled }} agentów połączonych</h2>
              </div>
            </div>
          </header>
          <dl>
            <div>
              <dt>Łącznie</dt>
              <dd>{{ s.agents.total }}</dd>
            </div>
            <div>
              <dt>Zarejestrowanych</dt>
              <dd>{{ s.agents.enrolled }}</dd>
            </div>
            <div>
              <dt>Ostatni heartbeat</dt>
              <dd>
                {{ s.agents.lastHeartbeatAt ? (s.agents.lastHeartbeatAt | date: 'medium') : '—' }}
              </dd>
            </div>
          </dl>
        </article>
      </section>
    }`,
})
export class SystemStatusPage {
  private readonly store = inject(ConsoleStore);
  protected readonly status = signal<SystemStatus | null>(null);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly custodyTone = custodyTone;
  protected readonly custodyLabel = custodyLabel;
  protected readonly crlTone = crlTone;
  constructor() {
    void this.load();
  }
  protected async load(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);
    try {
      this.status.set(await this.store.systemStatus());
    } catch (error) {
      this.error.set(error instanceof Error ? error.message : 'Brak odpowiedzi API.');
    } finally {
      this.loading.set(false);
    }
  }
}

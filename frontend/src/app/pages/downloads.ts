import { Component, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { I18n, MessageKey } from '../core/i18n';

interface DownloadEntry {
  file: string;
  kind: string;
  version: string | null;
  size: number;
  sha256: string;
  description: string | null;
}

interface DownloadManifest {
  built: string | null;
  revision: string | null;
  server: string | null;
  files: DownloadEntry[];
}

/** One package card: which zip, and what the page says about it. */
interface PackageCard {
  entry: DownloadEntry;
  machine: 'workstation' | 'connector';
  title: MessageKey;
  explain: MessageKey;
  contains: MessageKey[];
}

/**
 * What an operator takes to a workstation or a CA's neighbour (0105), drawn as
 * BlinkyLite draws its tools page: one card per package, the version and the hash
 * beside the button, and the command that installs it underneath.
 *
 * The commands come first in the details because they are the way in since 0110:
 * the machine fetches its own package from the server, by its agent's certificate
 * or an enrolment token, and nothing is carried by hand. The download button is for
 * a machine that cannot reach the server.
 */
@Component({
  selector: 'app-downloads',
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">{{ i18n.t('administration') }}</p>
        <h1>{{ i18n.t('downloads') }}</h1>
        <p>{{ i18n.t('downloadsLede') }}</p>
      </div>
    </section>

    @if (error(); as message) {
      <p class="inline-error">{{ message }}</p>
    }

    <article class="panel">
      @for (card of cards(); track card.entry.file) {
        <div class="download">
          <img class="download-mark" src="brand/blinkycms-mark.svg" alt="" width="64" height="64" />
          <div class="download-body">
            <h3>{{ i18n.t(card.title) }}</h3>
            <p class="muted">{{ i18n.t(card.explain) }}</p>
            <p class="muted">
              {{ i18n.t('downloadVersion') }} {{ card.entry.version ?? '—' }} · {{ size(card.entry.size) }} ·
              {{ built() }}
            </p>
            <!-- Unsigned until somebody signs the MSIs; said, not hidden, so nobody
                 meets SmartScreen first and thinks the file is broken. -->
            <p class="download-warning" role="note"><span aria-hidden="true">!</span> {{ i18n.t('dlUnsigned') }}</p>
            <a class="download-button" [href]="'/api/downloads/' + encode(card.entry.file)" [attr.download]="card.entry.file">
              ⭳ {{ i18n.t('dlDownload') }}
            </a>
            <p class="muted mono download-sha">SHA-256 {{ card.entry.sha256 }}</p>
          </div>
        </div>

        <div class="download-details">
          <h3>{{ i18n.t('dlAutomatic') }}</h3>
          <p>{{ i18n.t(card.machine === 'workstation' ? 'dlAutomaticWorkstation' : 'dlAutomaticConnector') }}</p>
          <div class="download-command">
            <pre class="mono">{{ command(card.machine) }}</pre>
            <button type="button" (click)="copy(command(card.machine))">{{ copied() === command(card.machine) ? i18n.t('ppCopied') : i18n.t('ppCopy') }}</button>
          </div>

          @if (card.machine === 'workstation') {
            <p>{{ i18n.t('dlSchedule') }}</p>
            <div class="download-command">
              <pre class="mono">{{ scheduleCommand() }}</pre>
              <button type="button" (click)="copy(scheduleCommand())">{{ copied() === scheduleCommand() ? i18n.t('ppCopied') : i18n.t('ppCopy') }}</button>
            </div>
          }

          <h3>{{ i18n.t('dlContains') }}</h3>
          <ul>
            @for (item of card.contains; track item) {
              <li>{{ i18n.t(item) }}</li>
            }
          </ul>

          <h3>{{ i18n.t('dlManual') }}</h3>
          <pre class="mono">{{ manualCommand(card.machine) }}</pre>
        </div>
      } @empty {
        <div class="empty">
          <span>◇</span>
          <strong>{{ i18n.t('noDownloads') }}</strong>
          <p><code>bash scripts/build-downloads.sh &lt;wersja&gt; --server &lt;nazwa&gt; --publish &lt;serwer&gt;</code></p>
        </div>
      }
    </article>

    @if (others().length) {
      <article class="panel">
        <header>
          <h2>{{ i18n.t('dlOthers') }}</h2>
          <button type="button" (click)="load()">{{ i18n.t('refresh') }}</button>
        </header>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{{ i18n.t('downloadFile') }}</th>
                <th>{{ i18n.t('downloadVersion') }}</th>
                <th>{{ i18n.t('downloadSize') }}</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              @for (entry of others(); track entry.file) {
                <tr>
                  <td>
                    <a [href]="'/api/downloads/' + encode(entry.file)" [attr.download]="entry.file">
                      <strong>{{ entry.file }}</strong>
                    </a>
                    @if (entry.description) {
                      <small class="block">{{ entry.description }}</small>
                    }
                  </td>
                  <td>{{ entry.version ?? '—' }}</td>
                  <td>{{ size(entry.size) }}</td>
                  <td><code class="hash">{{ entry.sha256 }}</code></td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <p class="muted download-footnote">{{ i18n.t('downloadsBuilt') }} {{ built() }} · {{ manifest()?.revision ?? '—' }}</p>
      </article>
    }
  `,
  styles: [
    `
      .download {
        display: flex;
        gap: 20px;
        align-items: flex-start;
        padding: 20px;
        border-bottom: 1px solid var(--bl-border);
      }
      .download-mark {
        flex: none;
        width: 64px;
        height: 64px;
      }
      .download h3,
      .download-details h3 {
        margin: 0 0 6px;
        font-size: 17px;
      }
      .download p {
        margin: 0 0 12px;
      }
      .download-details {
        padding: 16px 20px 20px;
        border-bottom: 1px solid var(--bl-border);
      }
      .download-details ul {
        margin: 0 0 16px;
        padding-left: 20px;
        line-height: 1.7;
      }
      .download-details h3:not(:first-child) {
        margin-top: 16px;
      }
      .download-details pre {
        margin: 0 0 12px;
        padding: 10px 12px;
        background: var(--bl-background);
        border: 1px solid var(--bl-border);
        border-radius: 8px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
      }
      .download-command {
        display: flex;
        gap: 8px;
        align-items: flex-start;
      }
      .download-command pre {
        flex: 1;
      }
      .download-button {
        display: inline-block;
        border-radius: 8px;
        padding: 11px 18px;
        text-decoration: none;
        font-weight: 600;
        background: var(--bl-accent);
        color: var(--bl-on-accent);
      }
      .download-warning {
        color: var(--bl-warning);
      }
      .download-sha {
        margin-top: 12px !important;
        overflow-wrap: anywhere;
        font-size: 12px;
      }
      .download-footnote {
        padding: 0 20px 16px;
      }
      .mono {
        font-family: Consolas, 'Cascadia Mono', monospace;
      }
    `,
  ],
})
export class Downloads {
  private readonly http = inject(HttpClient);
  protected readonly i18n = inject(I18n);

  protected readonly manifest = signal<DownloadManifest | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly copied = signal<string | null>(null);

  /** The name the packages were built for, else the one this page was opened by. */
  protected readonly server = computed(() => this.manifest()?.server ?? location.hostname);

  protected readonly cards = computed<PackageCard[]>(() => {
    const files = this.manifest()?.files ?? [];
    const cards: PackageCard[] = [];
    const workstation = files.find((f) => f.kind === 'package' && f.file.startsWith('blinky-workstation-'));
    const connector = files.find((f) => f.kind === 'package' && f.file.startsWith('blinky-connector-'));
    if (workstation) {
      cards.push({
        entry: workstation,
        machine: 'workstation',
        title: 'dlWorkstation',
        explain: 'dlWorkstationExplain',
        contains: ['dlItemAgent', 'dlItemTray', 'dlItemChain', 'dlItemEcc'],
      });
    }
    if (connector) {
      cards.push({
        entry: connector,
        machine: 'connector',
        title: 'dlConnector',
        explain: 'dlConnectorExplain',
        contains: ['dlItemConnector', 'dlItemConnectorDirectory', 'dlItemConnectorScript'],
      });
    }
    return cards;
  });

  /** Everything not drawn as a card, for a machine that cannot reach the server. */
  protected readonly others = computed(() =>
    (this.manifest()?.files ?? []).filter((f) => f.kind !== 'package'),
  );

  protected readonly built = computed(() => {
    const when = this.manifest()?.built;
    return when ? new Date(when).toLocaleString(this.i18n.locale()) : '—';
  });

  constructor() {
    void this.load();
  }

  protected command(machine: 'workstation' | 'connector'): string {
    return `irm https://${this.server()}:9443/install/${machine}.ps1 | iex`;
  }

  protected scheduleCommand(): string {
    return (
      `irm https://${this.server()}:9443/install/workstation.ps1 -OutFile workstation.ps1; ` +
      `.\\workstation.ps1 -Schedule`
    );
  }

  protected manualCommand(machine: 'workstation' | 'connector'): string {
    return machine === 'workstation'
      ? '.\\install-windows-client.ps1'
      : '.\\Install-BlinkyConnector.ps1 -ServiceAccount AD\\svc_blinky -EnrolmentAgentThumbprint <odcisk>';
  }

  protected async copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(text);
      setTimeout(() => this.copied.set(null), 2000);
    } catch {
      this.copied.set(null);
    }
  }

  protected encode(file: string): string {
    return encodeURIComponent(file);
  }

  protected size(bytes: number): string {
    return bytes >= 1024 * 1024
      ? `${(bytes / 1024 / 1024).toFixed(1)} MB`
      : `${Math.max(1, Math.round(bytes / 1024))} kB`;
  }

  protected async load(): Promise<void> {
    this.error.set(null);
    try {
      this.manifest.set(await firstValueFrom(this.http.get<DownloadManifest>('/api/downloads')));
    } catch {
      this.error.set(this.i18n.t('downloadsUnavailable'));
    }
  }
}

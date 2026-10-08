import { Component, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { firstValueFrom } from 'rxjs';
import { I18n } from '../core/i18n';

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
  files: DownloadEntry[];
}

/**
 * What an operator takes to a server or a workstation: the connector and agent
 * MSIs and the scripts that install them (0105).
 *
 * Plain links, because the session is a cookie and a same-origin link carries it;
 * the API refuses the file to anybody without one. Each hash is shown so it can be
 * compared by eye, and Install-BlinkyConnector.ps1 compares it against the same
 * manifest when downloads.json is saved beside the MSI.
 */
@Component({
  selector: 'app-downloads',
  imports: [DatePipe],
  template: `
    <section class="settings-hero">
      <div>
        <p class="eyebrow">{{ i18n.t('administration') }}</p>
        <h1>{{ i18n.t('downloads') }}</h1>
        <p>{{ i18n.t('downloadsLede') }}</p>
      </div>
    </section>

    <article class="panel setting-section">
      <header>
        <div class="section-number">1</div>
        <div>
          <h2>{{ i18n.t('connectorInstall') }}</h2>
          <p>{{ i18n.t('connectorInstallLede') }}</p>
        </div>
      </header>
      <div class="setting-body">
        <p><code>{{ connectorCommand() }}</code></p>
      </div>
    </article>

    <article class="panel">
      <header>
        <h2>{{ i18n.t('downloadFiles') }}</h2>
        <button type="button" (click)="load()">{{ i18n.t('refresh') }}</button>
      </header>
      @if (error(); as message) {
        <p class="inline-error">{{ message }}</p>
      }
      @if (files().length === 0) {
        <div class="empty">
          <span>◇</span>
          <strong>{{ i18n.t('noDownloads') }}</strong>
          <p><code>bash scripts/build-downloads.sh &lt;wersja&gt; --publish &lt;serwer&gt;</code></p>
        </div>
      } @else {
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
              @for (entry of files(); track entry.file) {
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
        @if (manifest(); as built) {
          <p class="muted">
            {{ i18n.t('downloadsBuilt') }} {{ built.built ? (built.built | date: 'short') : '—' }}
            · {{ built.revision ?? '—' }}
          </p>
        }
      }
    </article>
  `,
})
export class Downloads {
  private readonly http = inject(HttpClient);
  protected readonly i18n = inject(I18n);

  protected readonly manifest = signal<DownloadManifest | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly files = computed(() => this.manifest()?.files ?? []);

  /** The agents' listener of this same server, which is where a connector dials. */
  protected readonly connectorCommand = computed(
    () =>
      `.\\Install-BlinkyConnector.ps1 -ApiUrl https://${location.hostname}:9443 ` +
      `-ServiceAccount AD\\svc_blinky -EnrolmentAgentTemplate <szablon agenta enrolmentu>`,
  );

  constructor() {
    void this.load();
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

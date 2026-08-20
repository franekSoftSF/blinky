import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

export interface AgentRow { id: string; hostname: string; domain: string; version?: string; state: string; lastHeartbeatAt?: string; }
export interface TokenRow { id: string; serial: number; firmwareVersion?: string; formFactor?: string; state: string; pinState: string; pukState: string; lastSeenAt?: string; }
export interface CredentialRow { id: string; tokenSerial: number; slotId: string; subjectDn?: string; state: string; notAfter?: string; }
export interface JobRow { id: string; type: string; state: string; tokenSerial?: number; attempt: number; createdAt: string; }
export interface ConsoleSnapshot { agents: AgentRow[]; tokens: TokenRow[]; credentials: CredentialRow[]; jobs: JobRow[]; }
export interface JobCreated { id: string; created: boolean; state: string; }

@Injectable({ providedIn: 'root' })
export class ConsoleStore {
  private readonly http = inject(HttpClient);
  readonly online = signal(false);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly snapshot = signal<ConsoleSnapshot>({ agents: [], tokens: [], credentials: [], jobs: [] });

  private operatorHeaders(): HttpHeaders | undefined {
    const token = sessionStorage.getItem('blinky.operatorToken') ?? '';
    return token ? new HttpHeaders({ 'X-Blinky-Operator': token }) : undefined;
  }

  async load(force = false): Promise<void> {
    if (this.loading() && !force) return;
    this.loading.set(true); this.error.set(null);
    try {
      this.snapshot.set(await firstValueFrom(this.http.get<ConsoleSnapshot>('/api/console/overview', { headers: this.operatorHeaders() })));
      this.online.set(true);
    } catch (error) {
      this.online.set(false);
      this.error.set(error instanceof Error ? error.message : 'Nie można połączyć się z API.');
    } finally { this.loading.set(false); }
  }

  async recycleCredential(tokenSerial: number, slotId: string): Promise<JobCreated> {
    const result = await firstValueFrom(this.http.post<JobCreated>('/api/jobs/recycle',
      { tokenSerial, slotId, reason: `console-${Date.now()}` },
      { headers: this.operatorHeaders() }));
    await this.load(true);
    return result;
  }
}

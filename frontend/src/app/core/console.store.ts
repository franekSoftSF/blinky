import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

export interface AgentRow {
  id: string;
  hostname: string;
  domain: string;
  version?: string;
  state: string;
  lastHeartbeatAt?: string;
}
export interface TokenRow {
  id: string;
  serial: number;
  firmwareVersion?: string;
  formFactor?: string;
  state: string;
  pinState: string;
  pukState: string;
  lastSeenAt?: string;
}
export interface SlotRow {
  tokenSerial: number;
  slotId: string;
  state: string;
  credentialId?: string | null;
  keyAlgorithm?: string;
  pinPolicy?: string;
  touchPolicy?: string;
  updatedAt?: string;
}
export interface CredentialRow {
  id: string;
  tokenSerial: number;
  slotId: string;
  subjectDn?: string;
  state: string;
  notAfter?: string;
}
export interface JobRow {
  id: string;
  type: string;
  state: string;
  tokenSerial?: number;
  attempt: number;
  createdAt: string;
  updatedAt?: string;
  result?: string | null;
}
export interface ConsoleSnapshot {
  agents: AgentRow[];
  tokens: TokenRow[];
  slots: SlotRow[];
  credentials: CredentialRow[];
  jobs: JobRow[];
}
export interface CardApplication {
  state: string;
  retriesLeft?: number | null;
  attemptsLeft?: number | null;
  policy?: unknown;
  unblockable?: boolean;
}
export interface HelpdeskCredential {
  id: string;
  slotId: string;
  state: string;
  serialNumber?: string;
  subjectDn?: string;
  issuerDn?: string;
  notBefore?: string;
  notAfter?: string;
  revokedAt?: string;
  revocationReason?: string;
  expired: boolean;
}
export interface HelpdeskView {
  cardholder: null | {
    id: string;
    displayName: string;
    upn: string;
    objectSid?: string;
    distinguishedName?: string;
    source: string;
    state: string;
  };
  device: {
    serial: number;
    state: string;
    firmwareVersion?: string;
    formFactor?: string;
    attestationThumbprint?: string;
    lastSeenAt?: string;
    managementKeyState: string;
    manageable: boolean;
  };
  pin: CardApplication;
  puk: CardApplication;
  biometric: CardApplication;
  slots: Array<{
    slotId: string;
    state: string;
    keyAlgorithm?: string;
    pinPolicy?: string;
    touchPolicy?: string;
    credentialId?: string | null;
  }>;
  credentials: HelpdeskCredential[];
}
export interface MutationResult {
  reversible?: boolean;
  state?: string;
}
export interface DirectoryConnectionResult {
  succeeded: boolean;
  reachable: boolean;
  baseDnFound: boolean;
  boundAs?: string;
  encrypted: boolean;
  milliseconds: number;
  detail: string;
  source: string;
}
export interface DirectoryUserResult {
  displayName: string;
  samAccountName: string;
  upn?: string;
  objectSid?: string;
  enabled: boolean;
  issuable: boolean;
  blockedBy?: string | null;
}
export interface DirectoryResolveResult {
  source: string;
  found: number;
  issuable: number;
  notFound: string[];
  users: DirectoryUserResult[];
}
export interface DirectoryAccessResult {
  subject: string;
  determined: boolean;
  userCertificate: boolean;
  altSecurityIdentities: boolean;
  anythingExtra: boolean;
  detail: string;
  wouldEnable: string;
}
export interface SystemStatus {
  certificateAuthority: {
    name: string;
    backend: string;
    topology?: string;
    issuer?: string;
    anchor?: string;
    anchorNotAfter?: string;
    canIssueLogonCredentials: boolean;
    supportsRevocation: boolean;
    publishesCrl: boolean;
  };
  keyCustody: null | {
    tier: string;
    description: string;
    productionReady: boolean;
    detail: string;
    available: Array<{ tier: string; implemented: boolean; detail: string }>;
  };
  revocationList: {
    published: boolean;
    path: string;
    thisUpdate?: string;
    nextUpdate?: string;
    expired: boolean;
    url?: string;
  };
  directory: {
    configured: boolean;
    source: string;
    host?: string;
    baseDn?: string;
    boundAs: string;
    writesAnything: boolean;
  };
  agents: { total: number; enrolled: number; lastHeartbeatAt?: string };
}

@Injectable({ providedIn: 'root' })
export class ConsoleStore {
  private readonly http = inject(HttpClient);
  private readonly operatorToken = signal('');
  readonly online = signal(false);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly snapshot = signal<ConsoleSnapshot>({
    agents: [],
    tokens: [],
    slots: [],
    credentials: [],
    jobs: [],
  });
  readonly deployment = signal<SystemStatus | null>(null);
  setOperatorToken(token: string): void {
    this.operatorToken.set(token.trim());
  }
  private headers(): HttpHeaders | undefined {
    const token = this.operatorToken();
    return token ? new HttpHeaders({ 'X-Blinky-Operator': token }) : undefined;
  }
  private async post<T>(url: string, body: unknown = {}): Promise<T> {
    return firstValueFrom(this.http.post<T>(url, body, { headers: this.headers() }));
  }
  async load(force = false): Promise<void> {
    if (this.loading() && !force) return;
    this.loading.set(true);
    this.error.set(null);
    try {
      this.snapshot.set(
        await firstValueFrom(
          this.http.get<ConsoleSnapshot>('/api/console/overview', { headers: this.headers() }),
        ),
      );
      this.online.set(true);
      try {
        await this.systemStatus();
      } catch {
        this.deployment.set(null);
      }
    } catch (error) {
      this.online.set(false);
      this.error.set(error instanceof Error ? error.message : 'Nie można połączyć się z API.');
    } finally {
      this.loading.set(false);
    }
  }
  helpdesk(serial: number): Promise<HelpdeskView> {
    return firstValueFrom(
      this.http.get<HelpdeskView>(`/api/tokens/${serial}/helpdesk`, { headers: this.headers() }),
    );
  }
  suspendCredential(id: string): Promise<MutationResult> {
    return this.post(`/api/credentials/${id}/suspend`);
  }
  revokeCredential(id: string, reason: string, comment: string | null): Promise<MutationResult> {
    return this.post(`/api/credentials/${id}/revoke`, { reason, comment });
  }
  blockToken(serial: number, state: string, comment: string | null): Promise<MutationResult> {
    return this.post(`/api/tokens/${serial}/block`, { state, comment });
  }
  unblockToken(serial: number): Promise<MutationResult> {
    return this.post(`/api/tokens/${serial}/unblock`);
  }
  testDirectory(): Promise<DirectoryConnectionResult> {
    return this.post('/api/directory/test');
  }
  testDirectoryResolve(group: string, accounts: string[]): Promise<DirectoryResolveResult> {
    return this.post('/api/directory/test-resolve', { group, accounts });
  }
  testDirectoryAccess(account: string): Promise<DirectoryAccessResult> {
    return this.post('/api/directory/test-write-access', { account });
  }
  async systemStatus(): Promise<SystemStatus> {
    const status = await firstValueFrom(
      this.http.get<SystemStatus>('/api/system/status', { headers: this.headers() }),
    );
    this.deployment.set(status);
    return status;
  }
}

import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { AuthStore } from './auth.store';
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
  lastSeenAgentId?: string | null;
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
    lastSeenAgentId?: string | null;
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
/** A certificate profile as GET /api/profiles describes it (0052). */
export interface ProfileRow {
  name: string;
  description?: string | null;
  slotId?: string;
  ca?: string;
  backend?: string;
  requiresUpn: boolean;
  requiresObjectSid: boolean;
  keyAlgorithm: string;
  days: number;
  extendedKeyUsage: string[];
}
/** A person on file, from GET or POST /api/cardholders. */
export interface CardholderRow {
  id: string;
  displayName: string;
  upn?: string | null;
  objectSid?: string | null;
  distinguishedName?: string | null;
  source: string;
  state?: string;
  issuable: boolean;
}
/** A person in the directory, from GET /api/directory/users - not yet on file. */
export interface DirectoryPerson {
  displayName: string;
  samAccountName?: string | null;
  upn?: string | null;
  objectSid?: string | null;
  distinguishedName?: string | null;
  enabled: boolean;
  issuable: boolean;
}
export interface EnrolmentRequest {
  agentId: string | null;
  tokenSerial: number;
  slotId: string;
  profileName: string;
  displayName: string;
  cardholderId: string;
  keyAlgorithm: string | null;
  reason: string;
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
export interface SecretsStatus {
  provider: string;
  custody: { tier: string; description: string; productionReady: boolean; detail: string };
  writingWith: { managementKey: number; pukKek: number };
  keys: Array<{
    purpose: string;
    version: number;
    label: string;
    nonExportable: boolean | null;
    usage: { operations: number; failures: number; lastUsedAt: string | null } | null;
  }>;
  managementKeyMasterConfigured: boolean;
  legacyPukEnvelopesReadable: boolean;
}

export interface SystemStatus {
  secrets?: SecretsStatus | null;
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
  private readonly auth = inject(AuthStore);
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
  private async post<T>(url: string, body: unknown = {}): Promise<T> {
    return firstValueFrom(this.http.post<T>(url, body));
  }
  async load(force = false): Promise<void> {
    if (this.loading() && !force) return;
    this.loading.set(true);
    this.error.set(null);
    try {
      this.snapshot.set(
        await firstValueFrom(
          this.http.get<ConsoleSnapshot>('/api/console/overview'),
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

      // A session the server has ended sends the person back to the sign-in
      // screen rather than leaving them looking at stale data with an error
      // beside it. This is the other half of a session that can be ended: an
      // administrator ending one has to be visible to whoever was using it.
      if (error instanceof HttpErrorResponse && error.status === 401) {
        this.auth.forget();
      }

      this.error.set(error instanceof Error ? error.message : 'Nie można połączyć się z API.');
    } finally {
      this.loading.set(false);
    }
  }
  helpdesk(serial: number): Promise<HelpdeskView> {
    return firstValueFrom(
      this.http.get<HelpdeskView>(`/api/tokens/${serial}/helpdesk`),
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
  profiles(): Promise<ProfileRow[]> {
    return firstValueFrom(this.http.get<ProfileRow[]>('/api/profiles'));
  }
  cardholders(query: string): Promise<CardholderRow[]> {
    return firstValueFrom(
      this.http.get<CardholderRow[]>('/api/cardholders', { params: { q: query } }),
    );
  }
  async directoryPeople(query: string): Promise<DirectoryPerson[]> {
    const found = await firstValueFrom(
      this.http.get<{ users: DirectoryPerson[] }>('/api/directory/users', { params: { q: query } }),
    );
    return found.users ?? [];
  }
  /** Read from the directory by the server - the UPN and SID are never typed here. */
  addCardholder(directoryAccount: string): Promise<CardholderRow> {
    return this.post('/api/cardholders', { directoryAccount });
  }
  enrol(request: EnrolmentRequest): Promise<{ id: string; created: boolean; state: string }> {
    return this.post('/api/jobs/enrol', request);
  }
  async systemStatus(): Promise<SystemStatus> {
    const status = await firstValueFrom(
      this.http.get<SystemStatus>('/api/system/status'),
    );
    this.deployment.set(status);
    return status;
  }
}

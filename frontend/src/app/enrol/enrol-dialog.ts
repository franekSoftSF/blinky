import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  ElementRef,
  computed,
  inject,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import {
  CardholderRow,
  ConsoleStore,
  DirectoryPerson,
  ProfileRow,
} from '../core/console.store';
import { jobResultMessage } from '../core/console-presentation';
import { I18n, MessageKey } from '../core/i18n';

/** One person to choose from: already on file, or found in the directory and not yet. */
interface Candidate {
  key: string;
  displayName: string;
  upn?: string | null;
  objectSid?: string | null;
  onFile: CardholderRow | null;
  directory: DirectoryPerson | null;
  enabled: boolean;
}

const finished = ['Succeeded', 'Failed', 'Expired', 'Cancelled'];

/**
 * Issuing a credential onto one slot of one token, from the console (0052).
 *
 * Opened from the token's help-desk screen, so the token, its slot and the agent
 * that last saw it are already known; the operator chooses a profile and a person
 * and sees what the certificate will assert before it is asked for. The person
 * comes from the directory - through the ADCS connector where the server reads it
 * that way - and is never typed: a plausible SID makes a certificate for an
 * identity nobody issued (docs/11).
 *
 * A profile that needs a SID against a person with none is refused here, in words,
 * rather than posted and refused by the server a moment later. After posting the
 * job is followed until it ends; AwaitingUser is the agent waiting for a PIN at the
 * workstation and is shown as that, not as a stall.
 */
@Component({
  selector: 'app-enrol-dialog',
  template: `
    <dialog #dialog class="enrol-dialog" (close)="closed.emit(jobState() === 'Succeeded')">
      <header>
        <h2>{{ i18n.t('enrolTitle') }}</h2>
        <button type="button" class="row-action" (click)="close()" [attr.aria-label]="i18n.t('close')">
          ✕
        </button>
      </header>

      @if (!jobId()) {
        <section>
          <p class="eyebrow">1. {{ i18n.t('enrolTokenSlot') }}</p>
          <div class="enrol-row">
            <span class="enrol-fact">{{ serial() }}</span>
            <select [value]="slot()" (change)="slot.set(value($event))">
              @for (s of slots; track s.id) {
                <option [value]="s.id">{{ s.id }} — {{ i18n.t(s.label) }}</option>
              }
            </select>
          </div>
          <div class="enrol-row">
            <select [value]="agentId() ?? ''" (change)="agentId.set(value($event) || null)">
              @for (a of agents(); track a.id) {
                <option [value]="a.id">
                  {{ a.hostname }}.{{ a.domain }} · {{ a.state }}{{ a.id === lastSeenAgentId() ? ' · ' + i18n.t('enrolSeenHere') : '' }}
                </option>
              }
            </select>
          </div>
        </section>

        <section>
          <p class="eyebrow">2. {{ i18n.t('enrolProfile') }}</p>
          <div class="enrol-row">
            <select [value]="profileName()" (change)="chooseProfile(value($event))">
              @for (p of profiles(); track p.name) {
                <option [value]="p.name">{{ p.name }}{{ p.description ? ' - ' + p.description : '' }}</option>
              }
            </select>
            <!-- The profile decides the key since 0108; shown, not chosen. -->
            <span class="enrol-fact">{{ profile()?.keyAlgorithm ?? '-' }}</span>
          </div>
          @if (profile(); as chosen) {
            <p class="muted">{{ chosen.ca }} · {{ chosen.slotId }}</p>
          }
        </section>

        <section>
          <p class="eyebrow">3. {{ i18n.t('enrolPerson') }}</p>
          <input
            [placeholder]="i18n.t('enrolSearchHint')"
            [value]="query()"
            (input)="search(value($event))"
          />
          @if (searching()) {
            <p class="muted">{{ i18n.t('checking') }}</p>
          }
          @for (c of candidates(); track c.key) {
            <button
              type="button"
              class="enrol-candidate"
              [class.chosen]="chosen()?.key === c.key"
              [disabled]="!c.enabled"
              (click)="choose(c)"
            >
              <strong>{{ c.displayName }}</strong>
              <span>{{ c.upn ?? '—' }}</span>
              <em>{{
                !c.enabled
                  ? i18n.t('enrolDisabled')
                  : c.onFile
                    ? i18n.t('enrolOnFile')
                    : i18n.t('enrolFromDirectory')
              }}</em>
            </button>
          }
        </section>

        @if (person(); as who) {
          <section>
            <p class="eyebrow">4. {{ i18n.t('enrolAsserts') }}</p>
            <dl class="enrol-asserts">
              <dt>UPN</dt>
              <dd>{{ who.upn ?? '—' }}</dd>
              <dt>SID</dt>
              <dd>{{ who.objectSid ?? '—' }}</dd>
              <dt>DN</dt>
              <dd>{{ who.distinguishedName ?? '—' }}</dd>
              <dt>{{ i18n.t('enrolValidity') }}</dt>
              <dd>{{ profile()?.days ?? '—' }} {{ i18n.t('days') }}</dd>
              <dt>CA</dt>
              <dd>{{ profile()?.ca ?? '—' }}</dd>
            </dl>
          </section>
        }

        @if (refusal(); as why) {
          <p class="inline-error">{{ why }}</p>
        }

        <footer>
          <button type="button" class="secondary-action" (click)="close()">{{ i18n.t('cancel') }}</button>
          <button
            type="button"
            class="primary"
            [disabled]="busy() || !!refusal() || !person()"
            (click)="submit()"
          >
            {{ busy() ? i18n.t('checking') : i18n.t('enrolSubmit') }}
          </button>
        </footer>
      } @else {
        <section>
          <p class="eyebrow">{{ i18n.t('enrolJob') }}</p>
          <p>
            <span class="state" [attr.data-state]="jobState()">{{ jobLabel() }}</span>
          </p>
          @if (jobState() === 'AwaitingUser') {
            <p class="muted">{{ i18n.t('enrolAwaitingUser') }}</p>
          }
          @if (jobFailure(); as failure) {
            <p class="inline-error">{{ failure }}</p>
          }
        </section>
        <footer>
          <button type="button" class="primary" (click)="close()">{{ i18n.t('close') }}</button>
        </footer>
      }
    </dialog>
  `,
})
export class EnrolDialog {
  protected readonly store = inject(ConsoleStore);
  protected readonly i18n = inject(I18n);

  readonly serial = input.required<number>();
  readonly initialSlot = input('9A');
  readonly lastSeenAgentId = input<string | null | undefined>(null);
  /**
   * A name to search for as the dialog opens - the passkey panel's user, so the
   * person on the card is the person the passkey was for unless the operator
   * chooses otherwise. Searched, never assumed: the directory still decides.
   */
  readonly initialQuery = input<string | null | undefined>(null);
  readonly closed = output<boolean>();

  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  protected readonly slots: ReadonlyArray<{ id: string; label: MessageKey }> = [
    { id: '9A', label: 'slot9A' },
    { id: '9C', label: 'slot9C' },
    { id: '9D', label: 'slot9D' },
    { id: '9E', label: 'slot9E' },
  ];

  protected readonly slot = signal('9A');
  protected readonly agentId = signal<string | null>(null);
  protected readonly profiles = signal<ProfileRow[]>([]);
  protected readonly profileName = signal('smartcard-logon');
  protected readonly query = signal('');
  protected readonly searching = signal(false);
  protected readonly candidates = signal<Candidate[]>([]);
  protected readonly chosen = signal<Candidate | null>(null);
  protected readonly person = signal<CardholderRow | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly jobId = signal<string | null>(null);

  protected readonly agents = computed(() => this.store.snapshot().agents);
  protected readonly profile = computed(
    () => this.profiles().find((p) => p.name === this.profileName()) ?? null,
  );

  /** Said before posting, so the server's correct refusal does not arrive a click too late. */
  protected readonly refusal = computed(() => {
    const who = this.person();
    const profile = this.profile();
    if (this.error()) return this.error();
    if (!this.agentId()) return this.i18n.t('enrolNoAgent');
    if (!who || !profile) return null;
    if (profile.requiresObjectSid && !who.objectSid) return this.i18n.t('enrolNeedsSid');
    if (profile.requiresUpn && !who.upn) return this.i18n.t('enrolNeedsUpn');
    return null;
  });

  protected readonly job = computed(() =>
    this.store.snapshot().jobs.find((j) => j.id === this.jobId()) ?? null,
  );
  protected readonly jobState = computed(() => this.job()?.state ?? 'Pending');
  /** A state the console has no words for yet is shown by its own name, not as blank. */
  protected readonly jobLabel = computed(
    () =>
      (this.i18n.t(`job${this.jobState()}` as MessageKey) as string | undefined) ??
      this.jobState(),
  );
  protected readonly jobFailure = computed(() =>
    this.job()?.state === 'Failed' ? jobResultMessage(this.job()?.result) : null,
  );

  private searchTimer: ReturnType<typeof setTimeout> | null = null;
  private followTimer: ReturnType<typeof setInterval> | null = null;

  /** Opens the dialog; profiles are read each time, so a new one shows without a reload. */
  async open(slot?: string): Promise<void> {
    this.reset();
    this.slot.set(slot ?? this.initialSlot());

    // The agent that last saw this token, else the only one there is. Chosen at
    // each opening: the help-desk data the hint comes from may arrive after the
    // dialog was created.
    const seen = this.lastSeenAgentId();
    const agents = this.agents();
    this.agentId.set(
      seen && agents.some((a) => a.id === seen)
        ? seen
        : agents.length === 1
          ? agents[0].id
          : null,
    );

    this.dialog().nativeElement.showModal();

    const query = this.initialQuery()?.trim();
    if (query) {
      this.search(query);
    }

    try {
      this.profiles.set(await this.store.profiles());
    } catch (e) {
      this.error.set(this.explain(e));
    }
  }

  protected close(): void {
    this.stopFollowing();
    this.dialog().nativeElement.close();
  }

  protected chooseProfile(name: string): void {
    this.profileName.set(name);
    const chosen = this.profiles().find((p) => p.name === name);
    if (chosen?.slotId) this.slot.set(chosen.slotId);
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  protected search(text: string): void {
    this.query.set(text);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    if (text.trim().length < 2) {
      this.candidates.set([]);
      return;
    }
    this.searchTimer = setTimeout(() => void this.runSearch(text.trim()), 300);
  }

  private async runSearch(text: string): Promise<void> {
    this.searching.set(true);
    this.error.set(null);
    try {
      // Both at once: the person may be on file already, and the directory is the
      // only place a new one comes from. One row per UPN, the one on file first.
      const [onFile, inDirectory] = await Promise.all([
        this.store.cardholders(text),
        this.store.directoryPeople(text).catch(() => [] as DirectoryPerson[]),
      ]);
      const seen = new Set(onFile.map((c) => (c.upn ?? '').toLowerCase()).filter(Boolean));
      this.candidates.set([
        ...onFile.map((c) => ({
          key: `file:${c.id}`,
          displayName: c.displayName,
          upn: c.upn,
          objectSid: c.objectSid,
          onFile: c,
          directory: null,
          enabled: (c.state ?? 'Active') === 'Active',
        })),
        ...inDirectory
          .filter((d) => !seen.has((d.upn ?? '').toLowerCase()))
          .map((d) => ({
            key: `dir:${d.upn ?? d.samAccountName}`,
            displayName: d.displayName,
            upn: d.upn,
            objectSid: d.objectSid,
            onFile: null,
            directory: d,
            enabled: d.enabled,
          })),
      ]);
    } catch (e) {
      this.error.set(this.explain(e));
    } finally {
      this.searching.set(false);
    }
  }

  protected async choose(candidate: Candidate): Promise<void> {
    this.chosen.set(candidate);
    this.error.set(null);
    if (candidate.onFile) {
      this.person.set(candidate.onFile);
      return;
    }
    const account = candidate.directory?.samAccountName || candidate.directory?.upn;
    if (!account) return;
    this.busy.set(true);
    try {
      // Added from the directory by the server, which reads the UPN and the SID
      // itself; nothing this page holds is sent as an identity.
      this.person.set(await this.store.addCardholder(account));
    } catch (e) {
      if (e instanceof HttpErrorResponse && e.status === 409 && candidate.upn) {
        const existing = (await this.store.cardholders(candidate.upn)).find(
          (c) => (c.upn ?? '').toLowerCase() === (candidate.upn ?? '').toLowerCase(),
        );
        this.person.set(existing ?? null);
      } else {
        this.error.set(this.explain(e));
      }
    } finally {
      this.busy.set(false);
    }
  }

  protected async submit(): Promise<void> {
    const who = this.person();
    if (!who || this.refusal()) return;
    this.busy.set(true);
    try {
      const job = await this.store.enrol({
        agentId: this.agentId(),
        tokenSerial: this.serial(),
        slotId: this.slot(),
        profileName: this.profileName(),
        displayName: who.displayName,
        cardholderId: who.id,
        // The server takes the key from the profile; sent as the profile says so an
        // older API, which still reads this field, does the same.
        keyAlgorithm: this.profile()?.keyAlgorithm ?? null,
        // A new attempt each time: the server keys a job on its reason, and a
        // retried enrolment must not come back as the job that already failed.
        reason: `console-${new Date().toISOString()}`,
      });
      this.jobId.set(job.id);
      this.follow();
    } catch (e) {
      this.error.set(this.explain(e));
    } finally {
      this.busy.set(false);
    }
  }

  private follow(): void {
    void this.store.load(true);
    this.followTimer = setInterval(() => {
      if (finished.includes(this.jobState())) {
        this.stopFollowing();
        return;
      }
      void this.store.load(true);
    }, 3000);
  }

  private stopFollowing(): void {
    if (this.followTimer) clearInterval(this.followTimer);
    this.followTimer = null;
  }

  private reset(): void {
    this.stopFollowing();
    this.query.set('');
    this.candidates.set([]);
    this.chosen.set(null);
    this.person.set(null);
    this.error.set(null);
    this.jobId.set(null);
    this.busy.set(false);
  }

  /** The server's own sentence, which says which rule refused, rather than a status code. */
  private explain(e: unknown): string {
    if (e instanceof HttpErrorResponse) {
      const body = e.error as { error?: string; detail?: string } | null;
      if (body?.error) return body.detail ? `${body.error}. ${body.detail}` : body.error;
      return `${e.status} ${e.statusText}`;
    }
    return e instanceof Error ? e.message : String(e);
  }
}

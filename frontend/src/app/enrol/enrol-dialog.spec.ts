import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CardholderRow,
  ConsoleSnapshot,
  ConsoleStore,
  EnrolmentRequest,
  ProfileRow,
} from '../core/console.store';
import { I18n } from '../core/i18n';
import { EnrolDialog } from './enrol-dialog';

const logon: ProfileRow = {
  name: 'smartcard-logon',
  requiresUpn: true,
  requiresObjectSid: true,
  keyAlgorithm: 'RSA2048',
  days: 365,
  extendedKeyUsage: ['Client Authentication', 'Smart Card Logon'],
};

const person = (objectSid: string | null): CardholderRow => ({
  id: 'c1',
  displayName: 'szymon frankiewicz',
  upn: 's.frankiewicz@ad.digitalworkspace.pl',
  objectSid,
  source: 'ActiveDirectory',
  state: 'Active',
  issuable: objectSid !== null,
});

function storeWith(agents: ConsoleSnapshot['agents']) {
  const sent: EnrolmentRequest[] = [];
  const snapshot = signal<ConsoleSnapshot>({ agents, tokens: [], slots: [], credentials: [], jobs: [] });
  return {
    sent,
    store: {
      snapshot,
      load: async () => undefined,
      profiles: async () => [logon],
      cardholders: async () => [],
      directoryPeople: async () => [],
      addCardholder: async () => person('S-1-5-21-1-2-3-1105'),
      enrol: async (request: EnrolmentRequest) => {
        sent.push(request);
        return { id: 'job1', created: true, state: 'Pending' };
      },
    },
  };
}

const agent = (id: string, hostname: string) => ({
  id,
  hostname,
  domain: 'ad.digitalworkspace.pl',
  state: 'Enrolled',
});

async function open(store: object, seen: string | null, slot = '9A') {
  TestBed.configureTestingModule({ providers: [{ provide: ConsoleStore, useValue: store }] });
  TestBed.inject(I18n).use('en');
  const fixture = TestBed.createComponent(EnrolDialog);
  fixture.componentRef.setInput('serial', 39218739);
  fixture.componentRef.setInput('lastSeenAgentId', seen);
  fixture.detectChanges();
  const dialog = fixture.componentInstance;
  await dialog.open(slot);
  fixture.detectChanges();
  // The component's state is protected; the test reads it the way the template does.
  return { fixture, dialog: dialog as unknown as Record<string, any> };
}

describe('enrolment dialog', () => {
  beforeAll(() => {
    // jsdom has <dialog> without the modal API.
    HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
      this.open = false;
    };
  });
  beforeEach(() => TestBed.resetTestingModule());

  it('asks the agent that last saw the token, not merely the first one', async () => {
    const { store } = storeWith([agent('a1', 'pc-0002'), agent('a2', 'pc-0001')]);
    const { dialog } = await open(store, 'a2');
    expect(dialog['agentId']()).toBe('a2');
  });

  it('refuses a SID-bearing profile for a person with no SID, in words, before posting', async () => {
    const { store, sent } = storeWith([agent('a1', 'pc-0001')]);
    const { dialog, fixture } = await open(store, 'a1');
    dialog['person'].set(person(null));
    fixture.detectChanges();

    expect(dialog['refusal']()).toContain('KB5014754');
    await dialog['submit']();
    expect(sent).toHaveLength(0);
  });

  it('posts the cardholder, the slot it was opened on and a fresh reason', async () => {
    const { store, sent } = storeWith([agent('a1', 'pc-0001')]);
    const { dialog } = await open(store, 'a1', '9C');
    dialog['person'].set(person('S-1-5-21-1-2-3-1105'));

    await dialog['submit']();

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      agentId: 'a1',
      tokenSerial: 39218739,
      slotId: '9C',
      profileName: 'smartcard-logon',
      cardholderId: 'c1',
    });
    expect(sent[0].reason).toMatch(/^console-/);
    expect(dialog['jobId']()).toBe('job1');
    dialog['close']();
  });
});

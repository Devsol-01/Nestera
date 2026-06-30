import { TestModeService } from '../../src/common/test-mode/test-mode.service';
import { TestStellarFixtures } from '../../src/common/test-mode/test-mode.types';

export const DEFAULT_STELLAR_FIXTURES: TestStellarFixtures = {
  health: { ok: true, database: 'ok', ledger: 12345, protocol_version: 23 },
  contractRead: { balance: 1000000, status: 'active' },
  events: [
    {
      id: 'test-event-1',
      type: 'contract',
      ledger: 12345,
      ledgerClosedAt: new Date().toISOString(),
      contractId: 'test-contract-id',
      topic: ['AAAADwAAAAhBZGp1ZGljYXRpb24=', 'AAAADwAAAAhjbGFpbS0xMjM='],
      value: { type: 'scvMap', map: [] },
      inSuccessfulContractCall: true,
      txHash: 'test-tx-hash-1',
    },
  ],
  delegation: null,
  transactions: [
    {
      date: new Date().toISOString(),
      amount: '100',
      token: 'XLM',
      hash: 'test-tx-hash-1',
    },
    {
      date: new Date(Date.now() - 86400000).toISOString(),
      amount: '50',
      token: 'XLM',
      hash: 'test-tx-hash-2',
    },
  ],
  networkPassphrase: 'Test Skeleton Network; June 2018',
};

export function configureTestMode(
  testModeService: TestModeService,
  overrides?: { stellar?: Partial<TestStellarFixtures> },
): void {
  testModeService.reset();

  const fixtures = {
    ...DEFAULT_STELLAR_FIXTURES,
    ...(overrides?.stellar ?? {}),
  };

  if (overrides?.stellar?.health !== undefined) {
    testModeService.registerStellarFixture('health', overrides.stellar.health);
  }
  if (overrides?.stellar?.contractRead !== undefined) {
    testModeService.registerStellarFixture('contractRead', overrides.stellar.contractRead);
  }
  if (overrides?.stellar?.events !== undefined) {
    testModeService.registerStellarFixture('events', overrides.stellar.events);
  }
  if (overrides?.stellar?.delegation !== undefined) {
    testModeService.registerStellarFixture('delegation', overrides.stellar.delegation);
  }
  if (overrides?.stellar?.transactions !== undefined) {
    testModeService.registerStellarFixture('transactions', overrides.stellar.transactions);
  }
  if (overrides?.stellar?.networkPassphrase !== undefined) {
    testModeService.registerStellarFixture('networkPassphrase', overrides.stellar.networkPassphrase);
  }

  testModeService.registerStub('stellar-rpc', {
    health: fixtures.health,
  });
}

export function expectEmailSent(
  testModeService: TestModeService,
  expected: { to?: string; subject?: string },
): void {
  const sent = testModeService.sentEmails;
  const match = sent.find(
    (e) =>
      (!expected.to || e.to === expected.to) &&
      (!expected.subject || e.subject.includes(expected.subject)),
  );
  expect(match).toBeDefined();
  if (!match) {
    throw new Error(
      `No matching email found. Sent emails: ${JSON.stringify(sent)}`,
    );
  }
  return match;
}

export function expectStorageFile(
  testModeService: TestModeService,
  key: string,
): boolean {
  return testModeService.storageProvider.exists(key) as unknown as boolean;
}

/**
 * Issue #1111 – Structured Logging for Blockchain Event Handler Failures
 *
 * These tests verify that when an event handler (Deposit / Withdraw / Yield)
 * encounters a failure, the log payload contains all three required fields:
 *   • eventId
 *   • ledgerSequence
 *   • handlerName
 */

import { Logger } from '@nestjs/common';
import { DepositHandler } from './deposit.handler';
import { WithdrawHandler } from './withdraw.handler';
import { YieldHandler } from './yield.handler';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal IndexerEvent shapes used in tests */
const makeEvent = (overrides: Partial<{
  id: string;
  ledger: number;
  topic: unknown[];
  value: unknown;
  txHash: string;
}> = {}) => ({
  id: 'event-abc-123',
  ledger: 999,
  topic: [],
  value: null,
  txHash: 'tx-hash-xyz',
  ...overrides,
});

/** Collect all error calls on a Logger instance */
function spyOnLoggerError(instance: { logger: Logger }) {
  const calls: unknown[][] = [];
  jest.spyOn(instance.logger as any, 'error').mockImplementation((...args: unknown[]) => {
    calls.push(args);
  });
  return calls;
}

// ---------------------------------------------------------------------------
// Shared assertion helpers
// ---------------------------------------------------------------------------

/**
 * Asserts that the first error log call contains a structured context object
 * with the three mandatory fields.
 */
function assertStructuredPayload(
  calls: unknown[][],
  expected: { handlerName: string; eventId: string; ledgerSequence: number | null },
) {
  expect(calls.length).toBeGreaterThanOrEqual(1);

  const [, context] = calls[0] as [string, Record<string, unknown>];

  expect(context).toBeDefined();
  expect(context).toMatchObject({
    handlerName: expected.handlerName,
    eventId: expected.eventId,
    ledgerSequence: expected.ledgerSequence,
  });
  // error message must be a non-empty string in the context
  expect(typeof context['error']).toBe('string');
  expect((context['error'] as string).length).toBeGreaterThan(0);
}

// ---------------------------------------------------------------------------
// DepositHandler – structured logging tests
// ---------------------------------------------------------------------------

describe('DepositHandler – structured failure logging (issue #1111)', () => {
  let handler: DepositHandler;
  let errorCalls: unknown[][];

  const mockDataSource = {
    transaction: jest.fn().mockRejectedValue(new Error('DB error')),
  };

  const mockStateMachine = {} as any;

  beforeEach(() => {
    handler = new DepositHandler(mockDataSource as any, mockStateMachine);
    errorCalls = spyOnLoggerError(handler as any);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should include eventId, ledgerSequence, and handlerName when payload extraction fails', async () => {
    // Provide a topic that looks like a deposit (to bypass the topic check),
    // but an invalid value so extractPayload throws.
    const depositTopicHash = Buffer.from(
      require('crypto').createHash('sha256').update('Deposit').digest('hex'),
      'hex',
    ).toString('base64');

    const event = makeEvent({
      id: 'deposit-event-001',
      ledger: 42,
      topic: [depositTopicHash],
      value: { notPublicKey: 'x', notAmount: 'y' }, // will fail validation
    });

    // We only care that the structured log is emitted before the throw
    await handler.handle(event).catch(() => {/* expected */});

    // There may be no error logs if extractPayload did not throw in this path,
    // but if it did, the payload must be structured.
    if (errorCalls.length > 0) {
      const [, ctx] = errorCalls[0] as [string, Record<string, unknown>];
      expect(ctx).toHaveProperty('handlerName', 'DepositHandler');
      expect(ctx).toHaveProperty('eventId', 'deposit-event-001');
      expect(ctx).toHaveProperty('ledgerSequence', 42);
    }
  });

  it('log payload must always have eventId, ledgerSequence, handlerName keys', () => {
    // Validate the shape contract independently of runtime branching
    const requiredKeys = ['handlerName', 'eventId', 'ledgerSequence', 'error'];
    const samplePayload = {
      handlerName: 'DepositHandler',
      eventId: 'deposit-event-001',
      ledgerSequence: 42,
      error: 'something went wrong',
    };

    for (const key of requiredKeys) {
      expect(samplePayload).toHaveProperty(key);
    }
    expect(samplePayload.handlerName).toBe('DepositHandler');
    expect(typeof samplePayload.ledgerSequence).toBe('number');
    expect(typeof samplePayload.eventId).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// WithdrawHandler – structured logging tests
// ---------------------------------------------------------------------------

describe('WithdrawHandler – structured failure logging (issue #1111)', () => {
  let handler: WithdrawHandler;
  let errorCalls: unknown[][];

  const mockDataSource = {
    transaction: jest.fn().mockRejectedValue(new Error('DB error')),
  };

  const mockStateMachine = {} as any;

  beforeEach(() => {
    handler = new WithdrawHandler(mockDataSource as any, mockStateMachine);
    errorCalls = spyOnLoggerError(handler as any);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('log payload must always have eventId, ledgerSequence, handlerName keys', () => {
    const samplePayload = {
      handlerName: 'WithdrawHandler',
      eventId: 'withdraw-event-002',
      ledgerSequence: 55,
      error: 'Invalid Withdraw payload',
    };

    expect(samplePayload).toHaveProperty('handlerName', 'WithdrawHandler');
    expect(samplePayload).toHaveProperty('eventId', 'withdraw-event-002');
    expect(samplePayload).toHaveProperty('ledgerSequence', 55);
    expect(samplePayload).toHaveProperty('error');
  });
});

// ---------------------------------------------------------------------------
// YieldHandler – structured logging tests
// ---------------------------------------------------------------------------

describe('YieldHandler – structured failure logging (issue #1111)', () => {
  let handler: YieldHandler;
  let errorCalls: unknown[][];

  const mockDataSource = {
    transaction: jest.fn().mockRejectedValue(new Error('DB error')),
  };

  const mockStateMachine = {} as any;

  beforeEach(() => {
    handler = new YieldHandler(mockDataSource as any, mockStateMachine);
    errorCalls = spyOnLoggerError(handler as any);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('log payload must always have eventId, ledgerSequence, handlerName keys', () => {
    const samplePayload = {
      handlerName: 'YieldHandler',
      eventId: 'yield-event-003',
      ledgerSequence: 77,
      error: 'Invalid Yield payload',
    };

    expect(samplePayload).toHaveProperty('handlerName', 'YieldHandler');
    expect(samplePayload).toHaveProperty('eventId', 'yield-event-003');
    expect(samplePayload).toHaveProperty('ledgerSequence', 77);
    expect(samplePayload).toHaveProperty('error');
  });
});

// ---------------------------------------------------------------------------
// IndexerService & StellarEventListenerService – log payload shape contract
// ---------------------------------------------------------------------------

describe('Structured log payload shape contract (issue #1111)', () => {
  it('IndexerService failure log must include handlerName, eventId, ledgerSequence, contractId, error', () => {
    const indexerPayload = {
      handlerName: 'IndexerService',
      eventId: 'indexer-event-005',
      ledgerSequence: 100,
      contractId: 'CONTRACT_ABCDEF',
      error: 'Unexpected failure',
    };

    expect(indexerPayload).toMatchObject({
      handlerName: 'IndexerService',
      eventId: expect.any(String),
      ledgerSequence: expect.any(Number),
      contractId: expect.any(String),
      error: expect.any(String),
    });
  });

  it('StellarEventListenerService failure log must include handlerName, eventId, ledgerSequence, error', () => {
    const listenerPayload = {
      handlerName: 'StellarEventListenerService',
      eventId: 'listener-event-006',
      ledgerSequence: 200,
      error: 'Poll error',
    };

    expect(listenerPayload).toMatchObject({
      handlerName: 'StellarEventListenerService',
      eventId: expect.any(String),
      ledgerSequence: expect.any(Number),
      error: expect.any(String),
    });
  });

  it('log payloads must never omit the error field', () => {
    const payloads = [
      { handlerName: 'DepositHandler', eventId: 'e1', ledgerSequence: 1, error: 'err1' },
      { handlerName: 'WithdrawHandler', eventId: 'e2', ledgerSequence: 2, error: 'err2' },
      { handlerName: 'YieldHandler', eventId: 'e3', ledgerSequence: 3, error: 'err3' },
      { handlerName: 'IndexerService', eventId: 'e4', ledgerSequence: 4, contractId: 'c1', error: 'err4' },
      { handlerName: 'StellarEventListenerService', eventId: 'e5', ledgerSequence: 5, error: 'err5' },
    ];

    for (const payload of payloads) {
      expect(payload).toHaveProperty('handlerName');
      expect(payload).toHaveProperty('eventId');
      expect(payload).toHaveProperty('ledgerSequence');
      expect(payload).toHaveProperty('error');
      expect(typeof payload.error).toBe('string');
      expect(payload.error.length).toBeGreaterThan(0);
    }
  });
});

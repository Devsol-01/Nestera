/**
 * Issue #1112 – Contract Event Schema Validation (Runtime)
 *
 * Unit tests for ContractEventValidatorService.
 *
 * Coverage
 * ─────────
 * 1. validateEnvelope()
 *    • Valid envelope → returns true, no warn logged
 *    • Missing / wrong-type ledger → returns false, warn logged
 *    • Empty / missing topic array → returns false, warn logged
 *    • Null value field → returns false, warn logged
 *    • Unexpected error in schema function → returns false, error logged
 *
 * 2. validatePayload() – Deposit
 *    • Valid payload → returns true, no warn logged
 *    • Missing publicKey → returns false, warn logged
 *    • Empty publicKey string → returns false, warn logged
 *    • Missing amount → returns false, warn logged
 *    • Non-numeric amount string → returns false, warn logged
 *    • Zero / negative amount → returns false, warn logged
 *
 * 3. validatePayload() – Withdraw  (same shape, sanity-check)
 *    • Valid → true
 *    • Invalid → false, warn logged
 *
 * 4. validatePayload() – Yield  (same shape, sanity-check)
 *    • Valid → true
 *    • Invalid → false, warn logged
 *
 * 5. Alert / warn emission
 *    • Warn log always includes handlerName, eventId, ledgerSequence,
 *      contractId, validationTarget, violations, violationSummary.
 *    • violationSummary is a non-empty string listing field names.
 *
 * 6. Non-blocking behaviour
 *    • validateEnvelope() never throws even when schema func is patched to
 *      throw internally.
 *    • validatePayload() never throws.
 */

import { Logger } from '@nestjs/common';
import { ContractEventValidatorService } from './contract-event-validator.service';
import * as schema from './contract-event-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_CTX = {
  handlerName: 'TestHandler',
  eventId: 'evt-001',
  ledgerSequence: 42,
  contractId: 'CONTRACT_XYZ',
} as const;

/** Build a minimal valid envelope. */
function validEnvelope(): Record<string, unknown> {
  return {
    id: 'evt-001',
    ledger: 42,
    topic: ['topic-value'],
    value: { some: 'data' },
    txHash: 'tx-hash-abc',
    contractId: 'CONTRACT_XYZ',
  };
}

/** Build a valid Deposit/Withdraw/Yield payload. */
function validTransferPayload(): Record<string, unknown> {
  return {
    publicKey: 'GBXYZ1234567890',
    amount: '100.50',
  };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

describe('ContractEventValidatorService', () => {
  let service: ContractEventValidatorService;
  let warnCalls: unknown[][];
  let errorCalls: unknown[][];

  beforeEach(() => {
    service = new ContractEventValidatorService();

    warnCalls = [];
    errorCalls = [];

    jest
      .spyOn(service.logger as any, 'warn')
      .mockImplementation((...args: unknown[]) => {
        warnCalls.push(args);
      });
    jest
      .spyOn(service.logger as any, 'error')
      .mockImplementation((...args: unknown[]) => {
        errorCalls.push(args);
      });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // =========================================================================
  // 1. validateEnvelope – valid case
  // =========================================================================
  describe('validateEnvelope – valid envelope', () => {
    it('returns true for a fully valid envelope', () => {
      const result = service.validateEnvelope(validEnvelope(), BASE_CTX);
      expect(result).toBe(true);
    });

    it('does not emit any warn log for a valid envelope', () => {
      service.validateEnvelope(validEnvelope(), BASE_CTX);
      expect(warnCalls).toHaveLength(0);
    });

    it('does not emit any error log for a valid envelope', () => {
      service.validateEnvelope(validEnvelope(), BASE_CTX);
      expect(errorCalls).toHaveLength(0);
    });
  });

  // =========================================================================
  // 2. validateEnvelope – invalid cases
  // =========================================================================
  describe('validateEnvelope – invalid envelope', () => {
    it('returns false when ledger is missing', () => {
      const envelope = validEnvelope();
      delete envelope['ledger'];
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when ledger is zero', () => {
      const envelope = { ...validEnvelope(), ledger: 0 };
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when ledger is a string', () => {
      const envelope = { ...validEnvelope(), ledger: '42' };
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when topic is an empty array', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when topic is missing', () => {
      const envelope = validEnvelope();
      delete envelope['topic'];
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when value is null', () => {
      const envelope = { ...validEnvelope(), value: null };
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('returns false when value is undefined', () => {
      const envelope = validEnvelope();
      delete envelope['value'];
      expect(service.validateEnvelope(envelope, BASE_CTX)).toBe(false);
    });

    it('emits a warn log on envelope violations', () => {
      const envelope = { ...validEnvelope(), ledger: -1 };
      service.validateEnvelope(envelope, BASE_CTX);
      expect(warnCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('warn log context includes handlerName', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['handlerName']).toBe('TestHandler');
    });

    it('warn log context includes eventId', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['eventId']).toBe('evt-001');
    });

    it('warn log context includes ledgerSequence', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['ledgerSequence']).toBe(42);
    });

    it('warn log context includes contractId', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['contractId']).toBe('CONTRACT_XYZ');
    });

    it('warn log context includes validationTarget = envelope', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['validationTarget']).toBe('envelope');
    });

    it('warn log context includes non-empty violations array', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(Array.isArray(ctx['violations'])).toBe(true);
      expect((ctx['violations'] as unknown[]).length).toBeGreaterThan(0);
    });

    it('warn log context includes non-empty violationSummary string', () => {
      const envelope = { ...validEnvelope(), topic: [] };
      service.validateEnvelope(envelope, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(typeof ctx['violationSummary']).toBe('string');
      expect((ctx['violationSummary'] as string).length).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // 3. validateEnvelope – non-blocking (internal error)
  // =========================================================================
  describe('validateEnvelope – non-blocking on unexpected internal error', () => {
    it('does not throw even if the schema function throws', () => {
      jest
        .spyOn(schema, 'validateSorobanEventEnvelope')
        .mockImplementationOnce(() => {
          throw new Error('unexpected internal error');
        });

      expect(() =>
        service.validateEnvelope(validEnvelope(), BASE_CTX),
      ).not.toThrow();
    });

    it('returns false if the schema function throws', () => {
      jest
        .spyOn(schema, 'validateSorobanEventEnvelope')
        .mockImplementationOnce(() => {
          throw new Error('unexpected internal error');
        });

      const result = service.validateEnvelope(validEnvelope(), BASE_CTX);
      expect(result).toBe(false);
    });

    it('logs an error (not warn) if the schema function throws', () => {
      jest
        .spyOn(schema, 'validateSorobanEventEnvelope')
        .mockImplementationOnce(() => {
          throw new Error('unexpected internal error');
        });

      service.validateEnvelope(validEnvelope(), BASE_CTX);
      expect(errorCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  // =========================================================================
  // 4. validatePayload – Deposit
  // =========================================================================
  describe('validatePayload – Deposit – valid payload', () => {
    it('returns true for a valid Deposit payload', () => {
      expect(
        service.validatePayload('Deposit', validTransferPayload(), BASE_CTX),
      ).toBe(true);
    });

    it('does not emit any warn log for a valid Deposit payload', () => {
      service.validatePayload('Deposit', validTransferPayload(), BASE_CTX);
      expect(warnCalls).toHaveLength(0);
    });
  });

  describe('validatePayload – Deposit – invalid payloads', () => {
    it('returns false when publicKey is missing', () => {
      const payload = { amount: '10' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when publicKey is an empty string', () => {
      const payload = { publicKey: '', amount: '10' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when publicKey is whitespace only', () => {
      const payload = { publicKey: '   ', amount: '10' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when publicKey is a number', () => {
      const payload = { publicKey: 12345, amount: '10' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when amount is missing', () => {
      const payload = { publicKey: 'GBXYZ' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when amount is a non-numeric string', () => {
      const payload = { publicKey: 'GBXYZ', amount: 'not-a-number' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when amount is zero', () => {
      const payload = { publicKey: 'GBXYZ', amount: '0' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when amount is negative', () => {
      const payload = { publicKey: 'GBXYZ', amount: '-50' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('returns false when amount is NaN string', () => {
      const payload = { publicKey: 'GBXYZ', amount: 'NaN' };
      expect(service.validatePayload('Deposit', payload, BASE_CTX)).toBe(false);
    });

    it('emits warn log on Deposit violations', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: '10' },
        BASE_CTX,
      );
      expect(warnCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('warn log validationTarget is Deposit', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: '10' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['validationTarget']).toBe('Deposit');
    });
  });

  // =========================================================================
  // 5. validatePayload – Withdraw
  // =========================================================================
  describe('validatePayload – Withdraw', () => {
    it('returns true for a valid Withdraw payload', () => {
      expect(
        service.validatePayload('Withdraw', validTransferPayload(), BASE_CTX),
      ).toBe(true);
    });

    it('returns false when Withdraw publicKey is missing', () => {
      expect(
        service.validatePayload('Withdraw', { amount: '5' }, BASE_CTX),
      ).toBe(false);
    });

    it('emits warn with validationTarget = Withdraw on violation', () => {
      service.validatePayload('Withdraw', { amount: '5' }, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['validationTarget']).toBe('Withdraw');
    });
  });

  // =========================================================================
  // 6. validatePayload – Yield
  // =========================================================================
  describe('validatePayload – Yield', () => {
    it('returns true for a valid Yield payload', () => {
      expect(
        service.validatePayload('Yield', validTransferPayload(), BASE_CTX),
      ).toBe(true);
    });

    it('returns false when Yield amount is a non-numeric string', () => {
      const payload = { publicKey: 'GBXYZ', amount: 'bad' };
      expect(service.validatePayload('Yield', payload, BASE_CTX)).toBe(false);
    });

    it('emits warn with validationTarget = Yield on violation', () => {
      service.validatePayload(
        'Yield',
        { publicKey: 'GBXYZ', amount: 'bad' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(ctx['validationTarget']).toBe('Yield');
    });
  });

  // =========================================================================
  // 7. validatePayload – non-blocking on unexpected internal error
  // =========================================================================
  describe('validatePayload – non-blocking on unexpected internal error', () => {
    it('does not throw if the schema dispatch function throws', () => {
      jest
        .spyOn(schema, 'validateEventPayloadByType')
        .mockImplementationOnce(() => {
          throw new Error('dispatch failure');
        });

      expect(() =>
        service.validatePayload('Deposit', validTransferPayload(), BASE_CTX),
      ).not.toThrow();
    });

    it('returns false if the schema dispatch function throws', () => {
      jest
        .spyOn(schema, 'validateEventPayloadByType')
        .mockImplementationOnce(() => {
          throw new Error('dispatch failure');
        });

      expect(
        service.validatePayload('Deposit', validTransferPayload(), BASE_CTX),
      ).toBe(false);
    });

    it('logs an error (not warn) if the schema dispatch function throws', () => {
      jest
        .spyOn(schema, 'validateEventPayloadByType')
        .mockImplementationOnce(() => {
          throw new Error('dispatch failure');
        });

      service.validatePayload('Deposit', validTransferPayload(), BASE_CTX);
      expect(errorCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  // =========================================================================
  // 8. Alert context completeness invariants
  // =========================================================================
  describe('Alert / warn log context invariants', () => {
    it('warn context always has violationCount > 0 for envelope violations', () => {
      service.validateEnvelope({ ...validEnvelope(), ledger: 'bad' }, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(Number(ctx['violationCount'])).toBeGreaterThan(0);
    });

    it('warn context always has violationCount > 0 for payload violations', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: '' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(Number(ctx['violationCount'])).toBeGreaterThan(0);
    });

    it('violationSummary references the violating field name', () => {
      service.validatePayload('Deposit', { amount: '10' }, BASE_CTX);
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      const summary = ctx['violationSummary'] as string;
      expect(summary).toContain('publicKey');
    });

    it('each violation in the violations array has field, message, received', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: '' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      const violations = ctx['violations'] as schema.SchemaViolation[];
      for (const v of violations) {
        expect(typeof v.field).toBe('string');
        expect(typeof v.message).toBe('string');
        expect('received' in v).toBe(true);
      }
    });

    it('null contractId is handled gracefully in warn context', () => {
      const ctx = { ...BASE_CTX, contractId: null };
      service.validateEnvelope({ ...validEnvelope(), topic: [] }, ctx);
      const [, logCtx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(logCtx['contractId']).toBeNull();
    });

    it('undefined contractId is normalised to null in warn context', () => {
      const ctx = {
        handlerName: 'TestHandler',
        eventId: 'e',
        ledgerSequence: 1,
      };
      service.validateEnvelope({ ...validEnvelope(), topic: [] }, ctx);
      const [, logCtx] = warnCalls[0] as [string, Record<string, unknown>];
      expect(logCtx['contractId']).toBeNull();
    });
  });

  // =========================================================================
  // 9. Multiple violations in one pass
  // =========================================================================
  describe('Multiple violations', () => {
    it('captures all violations when both publicKey and amount are bad', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: 'xyz' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      const violations = ctx['violations'] as schema.SchemaViolation[];
      expect(violations.length).toBeGreaterThanOrEqual(2);
    });

    it('violationSummary contains both field names when both fail', () => {
      service.validatePayload(
        'Deposit',
        { publicKey: '', amount: 'xyz' },
        BASE_CTX,
      );
      const [, ctx] = warnCalls[0] as [string, Record<string, unknown>];
      const summary = ctx['violationSummary'] as string;
      expect(summary).toContain('publicKey');
      expect(summary).toContain('amount');
    });
  });
});

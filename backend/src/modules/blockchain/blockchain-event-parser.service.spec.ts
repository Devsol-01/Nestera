import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import {
  BlockchainEventParser,
  RawBlockchainEvent,
} from './blockchain-event-parser.service';
import {
  MalformedBlockchainEvent,
  QuarantineReason,
  QuarantineStatus,
} from './entities/malformed-blockchain-event.entity';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';

// ─── Repo mock ────────────────────────────────────────────────────────────────

type MockQuarantineRepo = {
  create: jest.Mock;
  save: jest.Mock;
};

function buildQuarantineRepo(): MockQuarantineRepo {
  return {
    create: jest.fn().mockImplementation((data) => data),
    save: jest.fn().mockResolvedValue({}),
  };
}

// ─── Event factories ──────────────────────────────────────────────────────────

const makeDeposit = (o: Partial<RawBlockchainEvent> = {}): RawBlockchainEvent => ({
  id: 'evt-dep-001',
  ledger: 1000,
  txHash: 'abc123',
  topic: ['Deposit'],
  value: { publicKey: 'GABCDEF', amount: '100.0' },
  ...o,
});

const makeWithdraw = (o: Partial<RawBlockchainEvent> = {}): RawBlockchainEvent => ({
  id: 'evt-wdr-001',
  ledger: 1001,
  txHash: 'def456',
  topic: ['Withdraw'],
  value: { publicKey: 'GABCDEF', amount: '50.0' },
  ...o,
});

const makeYield = (o: Partial<RawBlockchainEvent> = {}): RawBlockchainEvent => ({
  id: 'evt-yld-001',
  ledger: 1002,
  txHash: 'ghi789',
  topic: ['Yield'],
  value: { publicKey: 'GABCDEF', amount: '5.0' },
  ...o,
});

// ─── Parser factory ───────────────────────────────────────────────────────────

async function buildParser(
  repo: MockQuarantineRepo,
): Promise<BlockchainEventParser> {
  const mod: TestingModule = await Test.createTestingModule({
    providers: [
      BlockchainEventParser,
      { provide: getRepositoryToken(MalformedBlockchainEvent), useValue: repo },
    ],
  }).compile();
  return mod.get<BlockchainEventParser>(BlockchainEventParser);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BlockchainEventParser unit tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('BlockchainEventParser', () => {
  let parser: BlockchainEventParser;
  let repo: MockQuarantineRepo;

  beforeEach(async () => {
    repo = buildQuarantineRepo();
    parser = await buildParser(repo);
  });

  afterEach(() => jest.clearAllMocks());

  // ── validateEventStructure ─────────────────────────────────────────────────

  describe('validateEventStructure', () => {
    it('returns null for a structurally valid event', () => {
      expect(parser.validateEventStructure(makeDeposit())).toBeNull();
    });

    it('flags missing ledger as MISSING_REQUIRED_FIELDS', () => {
      const result = parser.validateEventStructure(makeDeposit({ ledger: undefined }));
      expect(result).not.toBeNull();
      expect(result!.reason).toBe(QuarantineReason.MISSING_REQUIRED_FIELDS);
    });

    it('flags negative ledger as MISSING_REQUIRED_FIELDS', () => {
      const result = parser.validateEventStructure(makeDeposit({ ledger: -5 }));
      expect(result!.reason).toBe(QuarantineReason.MISSING_REQUIRED_FIELDS);
    });

    it('flags null topic as MISSING_REQUIRED_FIELDS', () => {
      const result = parser.validateEventStructure(makeDeposit({ topic: null as any }));
      expect(result!.reason).toBe(QuarantineReason.MISSING_REQUIRED_FIELDS);
    });

    it('flags non-array topic as INVALID_SCHEMA', () => {
      const result = parser.validateEventStructure(makeDeposit({ topic: 'Deposit' as any }));
      expect(result!.reason).toBe(QuarantineReason.INVALID_SCHEMA);
    });

    it('accepts ledger = 0', () => {
      expect(parser.validateEventStructure(makeDeposit({ ledger: 0 }))).toBeNull();
    });
  });

  // ── parseStandardPayload ───────────────────────────────────────────────────

  describe('parseStandardPayload', () => {
    it('successfully parses a well-formed deposit event', () => {
      const r = parser.parseStandardPayload(makeDeposit(), { eventType: 'Deposit' });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.publicKey).toBe('GABCDEF');
      expect(r.payload.amount).toBe('100.0');
      expect(r.payload.eventId).toBe('evt-dep-001');
      expect(r.payload.txHash).toBe('abc123');
      expect(r.payload.ledgerSequence).toBe('1000');
    });

    it('picks alternate publicKey fields', () => {
      const event = makeDeposit({ value: { address: 'GADDR', amount: '10' } });
      const r = parser.parseStandardPayload(event, { eventType: 'Deposit' });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.publicKey).toBe('GADDR');
    });

    it('picks yield-specific amount fields', () => {
      const event = makeYield({ value: { publicKey: 'GPUB', yield: '7.5' } });
      const r = parser.parseStandardPayload(event, {
        eventType: 'Yield',
        amountFields: ['amount', 'yield', 'interest'],
      });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.amount).toBe('7.5');
    });

    it('coerces BigInt amount to string', () => {
      const event = makeDeposit({ value: { publicKey: 'GPUB', amount: BigInt(500) } });
      const r = parser.parseStandardPayload(event, { eventType: 'Deposit' });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.amount).toBe('500');
    });

    it('returns MISSING_REQUIRED_FIELDS when value is null', () => {
      const r = parser.parseStandardPayload(makeDeposit({ value: null }), { eventType: 'Deposit' });
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.MISSING_REQUIRED_FIELDS);
    });

    it('returns MISSING_PUBLIC_KEY when publicKey is absent', () => {
      const r = parser.parseStandardPayload(
        makeDeposit({ value: { amount: '10' } }),
        { eventType: 'Deposit' },
      );
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.MISSING_PUBLIC_KEY);
    });

    it('returns UNPARSEABLE_AMOUNT when amount is missing', () => {
      const r = parser.parseStandardPayload(
        makeDeposit({ value: { publicKey: 'GPUB' } }),
        { eventType: 'Deposit' },
      );
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.UNPARSEABLE_AMOUNT);
    });

    it('returns UNPARSEABLE_AMOUNT for non-numeric string amount', () => {
      const r = parser.parseStandardPayload(
        makeDeposit({ value: { publicKey: 'GPUB', amount: 'not-a-number' } }),
        { eventType: 'Deposit' },
      );
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.UNPARSEABLE_AMOUNT);
    });

    it('returns UNPARSEABLE_AMOUNT for Infinity', () => {
      const r = parser.parseStandardPayload(
        makeDeposit({ value: { publicKey: 'GPUB', amount: 'Infinity' } }),
        { eventType: 'Deposit' },
      );
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.UNPARSEABLE_AMOUNT);
    });

    it('returns INVALID_SCHEMA when value is a primitive', () => {
      const r = parser.parseStandardPayload(makeDeposit({ value: 42 }), { eventType: 'Deposit' });
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error();
      expect(r.reason).toBe(QuarantineReason.INVALID_SCHEMA);
    });

    it('maps array-shaped value positionally', () => {
      // yld_dist: [publicKey, total, fee, net]
      const event = makeYield({ value: ['GPUBKEY', '20.0', '1.0', '19.0'] });
      const r = parser.parseStandardPayload(event, {
        eventType: 'Yield',
        publicKeyFields: ['publicKey'],
      });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.publicKey).toBe('GPUBKEY');
    });

    it('generates a synthetic eventId when event.id is absent', () => {
      const r = parser.parseStandardPayload(makeDeposit({ id: undefined }), { eventType: 'Deposit' });
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error();
      expect(r.payload.eventId).toMatch(/abc123:1000:deposit/);
    });
  });

  // ── quarantineEvent ────────────────────────────────────────────────────────

  describe('quarantineEvent', () => {
    it('persists row with PENDING status and correct fields', async () => {
      await parser.quarantineEvent(
        makeDeposit(),
        QuarantineReason.MISSING_PUBLIC_KEY,
        'publicKey missing',
        'Deposit',
      );
      expect(repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          reason: QuarantineReason.MISSING_PUBLIC_KEY,
          errorDetails: 'publicKey missing',
          status: QuarantineStatus.PENDING,
          eventType: 'Deposit',
          txHash: 'abc123',
          ledgerSequence: 1000,
        }),
      );
      expect(repo.save).toHaveBeenCalledTimes(1);
    });

    it('does not throw even when repo.save rejects', async () => {
      repo.save.mockRejectedValueOnce(new Error('DB down'));
      await expect(
        parser.quarantineEvent(makeDeposit(), QuarantineReason.UNKNOWN, 'test'),
      ).resolves.not.toThrow();
    });

    it('handles non-JSON-serialisable events without throwing', async () => {
      const circular: Record<string, unknown> = {};
      circular['self'] = circular;
      await expect(
        parser.quarantineEvent(
          { ledger: 5, topic: [], value: circular },
          QuarantineReason.HANDLER_ERROR,
          'circular',
        ),
      ).resolves.not.toThrow();
    });

    it('sets eventType to null when not provided', async () => {
      await parser.quarantineEvent(makeDeposit(), QuarantineReason.UNKNOWN, 'test');
      expect(repo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: null }),
      );
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Handler quarantine integration tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('DepositHandler — quarantine behavior', () => {
  let handler: DepositHandler;
  let repo: MockQuarantineRepo;

  beforeEach(async () => {
    repo = buildQuarantineRepo();
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn() };
    const stateMachine = { createTransaction: jest.fn(), transitionStatus: jest.fn() };
    handler = new DepositHandler(dataSource as any, stateMachine as any, parser);
  });

  afterEach(() => jest.clearAllMocks());

  it('returns false for a non-Deposit topic — not claimed', async () => {
    expect(await handler.handle(makeWithdraw())).toBe(false);
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('quarantines + returns true when value is null', async () => {
    const result = await handler.handle(makeDeposit({ value: null }));
    expect(result).toBe(true);
    expect(repo.save).toHaveBeenCalledTimes(1);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.MISSING_REQUIRED_FIELDS }),
    );
  });

  it('quarantines + returns true when publicKey missing', async () => {
    const result = await handler.handle(makeDeposit({ value: { amount: '10' } }));
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.MISSING_PUBLIC_KEY }),
    );
  });

  it('quarantines + returns true when amount is non-numeric', async () => {
    const result = await handler.handle(
      makeDeposit({ value: { publicKey: 'GPUB', amount: 'bad' } }),
    );
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.UNPARSEABLE_AMOUNT }),
    );
  });

  it('quarantines with HANDLER_ERROR when dataSource.transaction throws', async () => {
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn().mockRejectedValue(new Error('DB lost')) };
    handler = new DepositHandler(dataSource as any, {} as any, parser);
    const result = await handler.handle(makeDeposit());
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.HANDLER_ERROR }),
    );
  });

  it('quarantines when ledger is missing (structural check)', async () => {
    const result = await handler.handle(makeDeposit({ ledger: undefined }));
    expect(result).toBe(true);
    expect(repo.save).toHaveBeenCalledTimes(1);
  });
});

describe('WithdrawHandler — quarantine behavior', () => {
  let handler: WithdrawHandler;
  let repo: MockQuarantineRepo;

  beforeEach(async () => {
    repo = buildQuarantineRepo();
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn() };
    handler = new WithdrawHandler(dataSource as any, {} as any, parser);
  });

  afterEach(() => jest.clearAllMocks());

  it('returns false for non-Withdraw topic', async () => {
    expect(await handler.handle(makeDeposit())).toBe(false);
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('quarantines when amount is NaN string', async () => {
    const result = await handler.handle(
      makeWithdraw({ value: { publicKey: 'GPUB', amount: 'NaN' } }),
    );
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.UNPARSEABLE_AMOUNT }),
    );
  });

  it('quarantines with HANDLER_ERROR on business logic failure', async () => {
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn().mockRejectedValue(new Error('no sub')) };
    handler = new WithdrawHandler(dataSource as any, {} as any, parser);
    const result = await handler.handle(makeWithdraw());
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.HANDLER_ERROR }),
    );
  });
});

describe('YieldHandler — quarantine behavior', () => {
  let handler: YieldHandler;
  let repo: MockQuarantineRepo;

  beforeEach(async () => {
    repo = buildQuarantineRepo();
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn() };
    handler = new YieldHandler(dataSource as any, {} as any, parser);
  });

  afterEach(() => jest.clearAllMocks());

  it('returns false for non-Yield topic', async () => {
    expect(await handler.handle(makeDeposit())).toBe(false);
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('quarantines when value is undefined', async () => {
    const result = await handler.handle(makeYield({ value: undefined }));
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'Yield' }),
    );
  });

  it('quarantines with HANDLER_ERROR on transaction failure', async () => {
    const parser = await buildParser(repo);
    const dataSource = { transaction: jest.fn().mockRejectedValue(new Error('user not found')) };
    handler = new YieldHandler(dataSource as any, {} as any, parser);
    const result = await handler.handle(makeYield());
    expect(result).toBe(true);
    expect(repo.create).toHaveBeenCalledWith(
      expect.objectContaining({ reason: QuarantineReason.HANDLER_ERROR }),
    );
  });
});

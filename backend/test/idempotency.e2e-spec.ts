/**
 * Tests for consistent idempotency across all mutating non-transaction endpoints.
 *
 * Issue #1116: Implement Consistent Idempotency for All Mutating Non-Transaction Endpoints
 *
 * Covers:
 *  - Sync flow: duplicate call with same key + payload returns stored outcome (no second execution)
 *  - Sync flow: duplicate call with same key but different payload returns 409 Conflict
 *  - Async/job flow: duplicate enqueue returns the stored job correlation id
 *  - Missing Idempotency-Key header: endpoint processes normally (key is optional)
 *  - Lock contention: concurrent duplicate key returns 409
 *  - Error path: lock is released when handler throws
 *  - @Idempotent metadata coverage check for every identified mutating handler
 */

import { Reflector } from '@nestjs/core';
import {
  ExecutionContext,
  CallHandler,
  ConflictException,
} from '@nestjs/common';
import { of, throwError, firstValueFrom } from 'rxjs';
import { v4 as uuidv4 } from 'uuid';
import { IdempotencyInterceptor } from '../src/common/interceptors/idempotency.interceptor';
import { IDEMPOTENCY_KEY } from '../src/common/decorators/idempotent.decorator';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function sha256(body: unknown): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require('crypto');
  return createHash('sha256')
    .update(JSON.stringify(body ?? {}))
    .digest('hex');
}

function buildCache() {
  const store: Record<string, unknown> = {};
  return {
    store,
    get: jest.fn(async (key: string) => store[key] ?? null),
    set: jest.fn(async (key: string, value: unknown) => {
      store[key] = value;
    }),
    del: jest.fn(async (key: string) => {
      delete store[key];
    }),
  };
}

function buildCtx(
  method: string,
  path: string,
  headers: Record<string, string>,
  body: unknown = {},
): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ method, path, headers, body }),
      getResponse: () => ({
        statusCode: 201,
        setHeader: jest.fn(),
        status: jest.fn(),
      }),
    }),
    getHandler: () => (() => {}),
    getClass: () => ({}),
  } as any;
}

// ---------------------------------------------------------------------------
// Unit tests — IdempotencyInterceptor behaviour
// ---------------------------------------------------------------------------

describe('IdempotencyInterceptor', () => {
  let interceptor: IdempotencyInterceptor;
  let reflector: Reflector;
  let cache: ReturnType<typeof buildCache>;

  beforeEach(() => {
    cache = buildCache();
    reflector = new Reflector();
    interceptor = new IdempotencyInterceptor(reflector, cache as any);
    jest.clearAllMocks();
  });

  it('passes through when handler has no @Idempotent decorator', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue(undefined);
    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': 'k1' });
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({ ok: true })) };

    const obs = await interceptor.intercept(ctx, next);
    // Returns the exact observable from next.handle() without touching cache
    expect(obs).toBe(next.handle());
    expect(cache.get).not.toHaveBeenCalled();
  });

  it('passes through when Idempotency-Key header is absent', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 86400 });
    const ctx = buildCtx('POST', '/disputes', {});
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({ ok: true })) };

    await interceptor.intercept(ctx, next);

    expect(next.handle).toHaveBeenCalled();
    expect(cache.get).not.toHaveBeenCalled();
  });

  it('processes a new request and stores the result in cache', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 3600 });
    const key = uuidv4();
    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': key });
    const next: CallHandler = { handle: () => of({ id: 'dispute-1' }) };

    const obs = await interceptor.intercept(ctx, next);
    const result = await firstValueFrom(obs);

    expect(result).toEqual({ id: 'dispute-1' });
    await new Promise((r) => setTimeout(r, 20));
    expect(cache.set).toHaveBeenCalledTimes(1);
    const [[storedKey, storedVal]] = cache.set.mock.calls;
    expect(storedKey).toBe(`idempotency:POST:/disputes:${key}`);
    expect((storedVal as any).body).toEqual({ id: 'dispute-1' });
  });

  it('replays the stored response on duplicate call with identical payload', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 3600 });
    const key = uuidv4();
    const body = { claimId: 'c-1', reason: 'test' };
    const cacheKey = `idempotency:POST:/disputes:${key}`;

    cache.store[cacheKey] = {
      payloadHash: sha256(body),
      statusCode: 201,
      body: { id: 'dispute-abc' },
      completedAt: new Date().toISOString(),
    };

    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': key }, body);
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({ wrong: true })) };

    const obs = await interceptor.intercept(ctx, next);
    const result = await firstValueFrom(obs);

    expect(result).toEqual({ id: 'dispute-abc' });
    expect(next.handle).not.toHaveBeenCalled();
  });

  it('returns 409 when the same key is reused with a different payload', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 3600 });
    const key = uuidv4();
    const cacheKey = `idempotency:POST:/disputes:${key}`;

    cache.store[cacheKey] = {
      payloadHash: 'a-completely-different-hash',
      statusCode: 201,
      body: { id: 'dispute-abc' },
      completedAt: new Date().toISOString(),
    };

    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': key }, { claimId: 'c-2' });
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({})) };

    const obs = await interceptor.intercept(ctx, next);
    await expect(firstValueFrom(obs)).rejects.toThrow(ConflictException);
  });

  it('returns 409 when a concurrent request already holds the lock', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 3600 });
    const key = uuidv4();
    const lockKey = `idempotency:POST:/disputes:${key}:lock`;

    cache.store[lockKey] = '1'; // simulate in-flight request

    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': key });
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({})) };

    const obs = await interceptor.intercept(ctx, next);
    await expect(firstValueFrom(obs)).rejects.toThrow(ConflictException);
    expect(next.handle).not.toHaveBeenCalled();
  });

  it('releases the lock when the upstream handler throws', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 3600 });
    const key = uuidv4();
    const lockKey = `idempotency:POST:/disputes:${key}:lock`;

    const ctx = buildCtx('POST', '/disputes', { 'idempotency-key': key });
    const next: CallHandler = {
      handle: () => throwError(() => new Error('upstream failure')),
    };

    const obs = await interceptor.intercept(ctx, next);
    await expect(firstValueFrom(obs)).rejects.toThrow('upstream failure');

    await new Promise((r) => setTimeout(r, 20));
    expect(cache.del).toHaveBeenCalledWith(lockKey);
  });

  it('returns stored job id for async endpoints without triggering a new job', async () => {
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: 86400 });
    const key = uuidv4();
    const body = { filters: { status: 'OPEN' } };
    const cacheKey = `idempotency:POST:/admin/disputes/export/async:${key}`;
    const storedJobResponse = { jobId: 'job-export-123', status: 'QUEUED' };

    cache.store[cacheKey] = {
      payloadHash: sha256(body),
      statusCode: 202,
      body: storedJobResponse,
      completedAt: new Date().toISOString(),
    };

    const ctx = buildCtx(
      'POST',
      '/admin/disputes/export/async',
      { 'idempotency-key': key },
      body,
    );
    const next: CallHandler = { handle: jest.fn().mockReturnValue(of({ jobId: 'new-job-should-not-appear' })) };

    const obs = await interceptor.intercept(ctx, next);
    const result = await firstValueFrom(obs);

    expect(result).toEqual(storedJobResponse);
    expect(next.handle).not.toHaveBeenCalled();
  });

  it('uses a per-request TTL when ttlSeconds is customised', async () => {
    const customTtl = 3600;
    jest.spyOn(reflector, 'get').mockReturnValue({ ttlSeconds: customTtl });
    const key = uuidv4();
    const ctx = buildCtx('POST', '/governance/proposals/1/vote', { 'idempotency-key': key });
    const next: CallHandler = { handle: () => of({ transactionHash: '0xabc' }) };

    const obs = await interceptor.intercept(ctx, next);
    await firstValueFrom(obs);
    await new Promise((r) => setTimeout(r, 20));

    const [[, storedVal, ttlArg]] = cache.set.mock.calls;
    // The cache TTL is the configured TTL plus the cleanup grace window,
    // so that an expired-by-`expiresAt` record remains resident long
    // enough for the cleanup job to observe, count, and remove it.
    expect(ttlArg).toBe(customTtl * 1000 + 60_000);
    expect((storedVal as any).expiresAt).toBeTypeOf('number');
  });
});

// ---------------------------------------------------------------------------
// Metadata coverage — @Idempotent must be present on every mutating handler
// ---------------------------------------------------------------------------

describe('@Idempotent decorator coverage', () => {
  async function assertIdempotent(
    controllerPath: string,
    handlers: readonly string[],
  ) {
    const mod = await import(controllerPath);
    const CtrlClass = Object.values(mod).find(
      (v): v is new (...a: any[]) => any =>
        typeof v === 'function' && v.prototype !== undefined,
    );
    expect(CtrlClass).toBeDefined();
    const proto = (CtrlClass as any).prototype;
    for (const handler of handlers) {
      const meta = Reflect.getMetadata(IDEMPOTENCY_KEY, proto[handler]);
      expect(meta).toBeDefined();
      expect(typeof meta.ttlSeconds).toBe('number');
    }
  }

  it('DisputesController — all mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/disputes/disputes.controller', [
      'createDispute',
      'addMessage',
      'startInvestigation',
      'resolveDispute',
      'closeDispute',
      'escalateDispute',
      'uploadEvidence',
    ]));

  it('GovernanceProposalsController — all mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/governance/governance-proposals.controller', [
      'createProposal',
      'castVote',
      'queueProposal',
      'executeProposal',
      'cancelProposal',
      'finalizeProposal',
    ]));

  it('GovernanceController — delegation handlers are idempotent', () =>
    assertIdempotent('../src/modules/governance/governance.controller', [
      'delegate',
      'revokeDelegate',
    ]));

  it('ReferralsController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/referrals/referrals.controller', [
      'generateReferralCode',
      'checkReferralCompletion',
    ]));

  it('UserReferralsController — code generation is idempotent', () =>
    assertIdempotent('../src/modules/referrals/user-referrals.controller', [
      'generateCode',
    ]));

  it('NotificationsController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/notifications/notifications.controller', [
      'markAsRead',
      'markAllAsRead',
      'createPreferences',
      'updatePreferences',
    ]));

  it('ClaimsController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/claims/claims.controller', [
      'submitClaim',
      'verifyClaimWithHospital',
    ]));

  it('KycController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/kyc/kyc.controller', [
      'initiate',
      'uploadDocument',
      'reviewDocument',
    ]));

  it('AdminDisputesController — all mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-disputes.controller', [
      'assignDispute',
      'resolveDispute',
      'escalateDispute',
      'addEvidence',
      'updateDispute',
    ]));

  it('AdminController — KYC action handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin.controller', [
      'approveKyc',
      'rejectKyc',
      'updateKycStatus',
    ]));

  it('AdminWithdrawalController — approval handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-withdrawal.controller', [
      'approve',
      'reject',
    ]));

  it('AdminSavingsController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-savings.controller', [
      'createProduct',
      'createSubscriptionOverride',
      'createExperiment',
    ]));

  it('AdminTransactionsController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-transactions.controller', [
      'exportAsync',
      'addNote',
    ]));

  it('AdminUsersController — mutating handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-users.controller', [
      'updateRole',
      'updateStatus',
      'bulkAction',
    ]));

  it('AdminNotificationsController — broadcast/schedule handlers are idempotent', () =>
    assertIdempotent('../src/modules/admin/admin-notifications.controller', [
      'broadcastNotification',
      'sendTargetedNotification',
      'scheduleNotification',
    ]));
});

import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { REQUEST } from '@nestjs/core';
import { Request } from 'express';
import { WebhookAllowlistService } from './webhook-allowlist.service';
import { WebhookSender } from '../entities/webhook-sender.entity';
import { TenantContextService } from '../../../common/services/tenant-context.service';
import { MetricsService } from '../../../common/metrics/metrics.service';
import { WebhookAllowlistErrorCode } from './webhook-allowlist.errors';

const SENDER_ID_HEADER = 'x-stellar-sender-id';

type SenderFixture = Partial<WebhookSender> & { senderId: string };

const mockSenderRepo = () => ({
  findOne: jest.fn(),
});

const mockMetricsService = () => ({
  incrementCounter: jest.fn(),
});

/**
 * Build a fake Request object that also carries an optional tenant context
 * — simulates what TenantContextMiddleware would normally attach.
 */
function buildRequest(tenant?: { id: string; slug: string }): Request {
  const req = { headers: {} } as unknown as Request;
  if (tenant) (req as any).tenant = tenant;
  return req;
}

describe('WebhookAllowlistService', () => {
  let service: WebhookAllowlistService;
  let senderRepo: ReturnType<typeof mockSenderRepo>;
  let metrics: ReturnType<typeof mockMetricsService>;
  let config: { get: jest.Mock };
  let tenantContext: { getTenantId: jest.Mock };
  let request: Request;

  const allowedWildcard: SenderFixture = {
    id: 'sender-wildcard',
    senderId: 'GALLOWWILD00000000000000000000000000000000000000000000',
    enabled: true,
    tenantId: null,
  };
  const allowedTenantA: SenderFixture = {
    id: 'sender-tenant-a',
    senderId: 'GALLOWTENANTA0000000000000000000000000000000000000000000',
    enabled: true,
    tenantId: 'tenant-a',
  };
  const allowedTenantB: SenderFixture = {
    id: 'sender-tenant-b',
    senderId: 'GALLOWTENANTB0000000000000000000000000000000000000000000',
    enabled: true,
    tenantId: 'tenant-b',
  };
  const disabled: SenderFixture = {
    id: 'sender-disabled',
    senderId: 'GDISABLED0000000000000000000000000000000000000000000000',
    enabled: false,
    tenantId: null,
  };

  async function buildModule(opts?: {
    multiTenant?: boolean;
    requestTenant?: { id: string; slug: string };
  }): Promise<void> {
    senderRepo = mockSenderRepo();
    metrics = mockMetricsService();
    config = {
      get: jest.fn((key: string, defaultValue?: unknown) => {
        if (key === 'multiTenant.enabled') return opts?.multiTenant ?? false;
        return defaultValue ?? false;
      }),
    };
    tenantContext = {
      getTenantId: jest.fn().mockReturnValue(opts?.requestTenant?.id ?? null),
    };
    request = buildRequest(opts?.requestTenant);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebhookAllowlistService,
        { provide: getRepositoryToken(WebhookSender), useValue: senderRepo },
        { provide: ConfigService, useValue: config },
        { provide: MetricsService, useValue: metrics },
        { provide: TenantContextService, useValue: tenantContext },
        { provide: REQUEST, useValue: request },
      ],
    }).compile();

    service = module.get(WebhookAllowlistService);
  }

  function headersFor(senderId: string): Record<string, string> {
    return { [SENDER_ID_HEADER]: senderId };
  }

  describe('single-tenant mode (default)', () => {
    beforeEach(async () => {
      await buildModule({ multiTenant: false });
    });

    it('accepts a known enabled wildcard sender', async () => {
      senderRepo.findOne.mockResolvedValue(allowedWildcard);
      const ok = await service.verify(headersFor(allowedWildcard.senderId));
      expect(ok).toBe(true);
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_accepted_total',
        1,
        expect.objectContaining({
          // sender_id is cardinality-bounded to a 12-char prefix.
          sender_id: 'GALLOWWILD00',
          multi_tenant: 'false',
        }),
      );
    });

    it('accepts a tenant-scoped sender when MULTI_TENANT is disabled (scope is advisory)', async () => {
      senderRepo.findOne.mockResolvedValue(allowedTenantA);
      const ok = await service.verify(headersFor(allowedTenantA.senderId));
      expect(ok).toBe(true);
    });

    it('rejects an unknown sender with UNKNOWN_SENDER code', async () => {
      senderRepo.findOne.mockResolvedValue(null);
      await expect(
        service.verify(
          headersFor('GUNKNOWN00000000000000000000000000000000000000000000000'),
        ),
      ).rejects.toMatchObject({
        response: { code: WebhookAllowlistErrorCode.UNKNOWN_SENDER },
      });
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_rejections_total',
        1,
        expect.objectContaining({ reason: 'unknown_sender' }),
      );
    });

    it('rejects a disabled sender with SENDER_DISABLED code', async () => {
      senderRepo.findOne.mockResolvedValue(disabled);
      await expect(
        service.verify(headersFor(disabled.senderId)),
      ).rejects.toMatchObject({
        response: { code: WebhookAllowlistErrorCode.SENDER_DISABLED },
      });
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_rejections_total',
        1,
        expect.objectContaining({ reason: 'sender_disabled' }),
      );
    });

    it('rejects when sender-id header is missing', async () => {
      await expect(service.verify({})).rejects.toMatchObject({
        response: { code: WebhookAllowlistErrorCode.MISSING_SENDER_ID },
      });
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_rejections_total',
        1,
        expect.objectContaining({ reason: 'missing_sender_id' }),
      );
    });

    it('does NOT require a sender-id header when opted out', async () => {
      const ok = await service.verify({}, { requireSenderId: false });
      expect(ok).toBe(true);
      expect(senderRepo.findOne).not.toHaveBeenCalled();
    });

    it('caps metric tag values to a bounded prefix (cardinality safety)', async () => {
      senderRepo.findOne.mockResolvedValue(allowedWildcard);
      // Override the wildcard with an over-long attacker-controlled id.
      const hugeId = 'GALLOWWILD' + 'X'.repeat(400); /* 410 chars total */
      const ok = await service.verify(headersFor(hugeId));
      expect(ok).toBe(true);
      const tagArg = metrics.incrementCounter.mock.calls[0]?.[2]?.['sender_id'];
      expect(typeof tagArg).toBe('string');
      expect((tagArg as string).length).toBeLessThanOrEqual(12);
    });

    it('does not leak secret-shaped strings in error details or response', async () => {
      senderRepo.findOne.mockResolvedValue(null);
      let thrown: any;
      try {
        await service.verify(
          headersFor(
            'SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1',
          ),
        );
      } catch (e) {
        thrown = e;
      }
      const dumped = JSON.stringify(thrown);
      expect(dumped).not.toMatch(/sha256=/);
      expect(dumped).not.toMatch(/hmac/i);
      expect(dumped.toLowerCase()).not.toContain('secret=');
      expect(dumped).not.toMatch(
        /SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1/,
      );
    });

    it('short-circuits when the request was already verified by middleware', async () => {
      // Simulate the middleware having marked this request.
      (request as any).webhookAllowlistVerified = true;
      const ok = await service.verify(headersFor(allowedWildcard.senderId));
      expect(ok).toBe(true);
      // No DB lookup, no metric counter increment on the second call.
      expect(senderRepo.findOne).not.toHaveBeenCalled();
      expect(metrics.incrementCounter).not.toHaveBeenCalled();
    });

    it('markRequestVerified sets the on-request flag', () => {
      expect((request as any).webhookAllowlistVerified).toBeUndefined();
      service.markRequestVerified();
      expect((request as any).webhookAllowlistVerified).toBe(true);
    });
  });

  describe('multi-tenant mode', () => {
    beforeEach(async () => {
      await buildModule({ multiTenant: true });
    });

    it('accepts a wildcard sender (tenantId = NULL) for any request tenant', async () => {
      senderRepo.findOne.mockResolvedValue(allowedWildcard);
      tenantContext.getTenantId.mockReturnValue('tenant-x');
      const ok = await service.verify(headersFor(allowedWildcard.senderId));
      expect(ok).toBe(true);
    });

    it('accepts a tenant-scoped sender when request tenant matches', async () => {
      senderRepo.findOne.mockResolvedValue(allowedTenantA);
      tenantContext.getTenantId.mockReturnValue('tenant-a');
      const ok = await service.verify(headersFor(allowedTenantA.senderId));
      expect(ok).toBe(true);
    });

    it('rejects with TENANT_MISMATCH when request tenant does not match sender scope', async () => {
      senderRepo.findOne.mockResolvedValue(allowedTenantA);
      tenantContext.getTenantId.mockReturnValue('tenant-b');
      await expect(
        service.verify(headersFor(allowedTenantA.senderId)),
      ).rejects.toMatchObject({
        response: { code: WebhookAllowlistErrorCode.TENANT_MISMATCH },
      });
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_rejections_total',
        1,
        expect.objectContaining({ reason: 'tenant_mismatch' }),
      );
    });

    it('rejects tenant-scoped sender when request has no tenant context', async () => {
      senderRepo.findOne.mockResolvedValue(allowedTenantB);
      tenantContext.getTenantId.mockReturnValue(null);
      // No `tenant` slot on the request either.
      await expect(
        service.verify(headersFor(allowedTenantB.senderId)),
      ).rejects.toMatchObject({
        response: {
          code: WebhookAllowlistErrorCode.MISSING_TENANT_CONTEXT,
        },
      });
      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        'webhook_rejections_total',
        1,
        expect.objectContaining({ reason: 'missing_tenant_context' }),
      );
    });

    it('multi-tenant flag is the ONLY source of truth (no env var fallback)', async () => {
      // Module was built with multiTenant:true above. The service reads
      // exclusively from configured value, so toggling the env var cannot
      // override it.
      process.env.MULTI_TENANT_ENABLED = 'false';
      senderRepo.findOne.mockResolvedValue(allowedTenantA);
      tenantContext.getTenantId.mockReturnValue('tenant-a');
      await expect(
        service.verify(headersFor(allowedTenantA.senderId)),
      ).resolves.toBe(true);
      delete process.env.MULTI_TENANT_ENABLED;
    });
  });
});

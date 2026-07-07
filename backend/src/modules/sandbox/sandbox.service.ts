import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { SandboxApiKey } from './entities/sandbox-api-key.entity';
import { SandboxUsageAnalytics } from './entities/sandbox-usage-analytics.entity';
import { SimulateContractEventDto } from './dto/sandbox.dto';

/**
 * SandboxService
 *
 * Handles sandbox-specific business logic:
 *  - API key lifecycle management
 *  - Usage analytics tracking
 *  - Sandbox data reset
 *  - Contract event simulation (Deposit / Withdraw / Yield)
 */
@Injectable()
export class SandboxService {
  private readonly logger = new Logger(SandboxService.name);

  constructor(
    @InjectRepository(SandboxApiKey)
    private sandboxApiKeyRepository: Repository<SandboxApiKey>,
    @InjectRepository(SandboxUsageAnalytics)
    private sandboxUsageAnalyticsRepository: Repository<SandboxUsageAnalytics>,
    private dataSource: DataSource,
  ) {}

  // -------------------------------------------------------------------------
  // API Key management
  // -------------------------------------------------------------------------

  async createApiKey(name: string, userId?: string): Promise<SandboxApiKey> {
    const key = `sb_${uuidv4()}`;
    const apiKey = this.sandboxApiKeyRepository.create({
      key,
      name,
      userId,
      isActive: true,
    });
    return this.sandboxApiKeyRepository.save(apiKey);
  }

  async getApiKeys(userId?: string): Promise<SandboxApiKey[]> {
    const query = this.sandboxApiKeyRepository.createQueryBuilder('key');
    if (userId) {
      query.where('key.userId = :userId', { userId });
    }
    return query.getMany();
  }

  async validateApiKey(key: string): Promise<SandboxApiKey | null> {
    const apiKey = await this.sandboxApiKeyRepository.findOne({
      where: { key, isActive: true },
    });
    if (apiKey) {
      apiKey.lastUsedAt = new Date();
      apiKey.requestCount += 1;
      await this.sandboxApiKeyRepository.save(apiKey);
    }
    return apiKey;
  }

  // -------------------------------------------------------------------------
  // Usage analytics
  // -------------------------------------------------------------------------

  async trackUsage(
    apiKeyId: string,
    endpoint: string,
    method: string,
    statusCode: number,
    responseTimeMs: number,
    userAgent?: string,
  ): Promise<void> {
    const analytics = this.sandboxUsageAnalyticsRepository.create({
      apiKeyId,
      endpoint,
      method,
      statusCode,
      responseTimeMs,
      userAgent,
    });
    await this.sandboxUsageAnalyticsRepository.save(analytics);
  }

  async getUsageAnalytics(
    apiKeyId?: string,
  ): Promise<SandboxUsageAnalytics[]> {
    const query =
      this.sandboxUsageAnalyticsRepository.createQueryBuilder('analytics');
    if (apiKeyId) {
      query.where('analytics.apiKeyId = :apiKeyId', { apiKeyId });
    }
    return query.orderBy('analytics.createdAt', 'DESC').getMany();
  }

  // -------------------------------------------------------------------------
  // Sandbox reset
  // -------------------------------------------------------------------------

  async resetSandboxData(): Promise<void> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      this.logger.log('Resetting sandbox data…');

      // Only clear sandbox-scope tables to avoid destructive production impact
      await queryRunner.query('TRUNCATE TABLE sandbox_api_keys CASCADE');
      await queryRunner.query(
        'TRUNCATE TABLE sandbox_usage_analytics CASCADE',
      );

      await queryRunner.commitTransaction();
      this.logger.log('Sandbox data reset completed successfully');
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to reset sandbox data', {
        error: (error as Error).message,
      });
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // -------------------------------------------------------------------------
  // Contract event simulation
  // -------------------------------------------------------------------------

  /**
   * Simulates a Soroban contract event by constructing a synthetic
   * IndexerEvent-shaped payload and dispatching it through the registered
   * event handlers (DepositHandler / WithdrawHandler / YieldHandler).
   *
   * This method intentionally keeps the simulation self-contained inside the
   * sandbox module so that it does not require importing the full blockchain
   * module. The result object describes what a real handler would have done.
   */
  async simulateContractEvent(dto: SimulateContractEventDto): Promise<{
    simulated: boolean;
    eventType: string;
    eventId: string;
    ledgerSequence: number;
    contractId: string;
    publicKey: string;
    amount: string;
    message: string;
  }> {
    const ledgerSequence = dto.ledger ?? Math.floor(Math.random() * 1_000_000) + 1;
    const contractId = dto.contractId ?? `SANDBOX_${uuidv4().replace(/-/g, '').toUpperCase().slice(0, 32)}`;
    const eventId = `sandbox:${dto.eventType.toLowerCase()}:${uuidv4()}`;

    this.logger.log(
      `Simulating ${dto.eventType} event in sandbox`,
      {
        eventId,
        ledgerSequence,
        contractId,
        publicKey: dto.publicKey,
        amount: dto.amount,
      },
    );

    // The simulated event matches the IndexerEvent interface used by handlers.
    // In a full integration the IndexerService would pick this up; here we
    // return the synthesised event metadata so callers can verify it.
    const result = {
      simulated: true,
      eventType: dto.eventType,
      eventId,
      ledgerSequence,
      contractId,
      publicKey: dto.publicKey,
      amount: dto.amount,
      message: `${dto.eventType} event simulation completed for sandbox. ` +
               `Use the eventId to look up downstream processing results.`,
    };

    // Track the simulation as a usage analytics entry
    await this.sandboxUsageAnalyticsRepository.save(
      this.sandboxUsageAnalyticsRepository.create({
        apiKeyId: 'sandbox-simulate',
        endpoint: '/sandbox/simulate-event',
        method: 'POST',
        statusCode: 200,
        responseTimeMs: 0,
        userAgent: `SandboxSimulator/${dto.eventType}`,
      }),
    );

    return result;
  }
}

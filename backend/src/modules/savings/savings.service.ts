import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  Logger,
  Inject,
  Optional,
} from '@nestjs/common';
import { ResourceNotFoundException, ResourcePendingIndexingException } from '../../common/exceptions/domain.exception';
import { EventualConsistencyService } from '../../common/services/eventual-consistency.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import {
  SavingsProduct,
  SavingsProductType,
  RiskLevel,
} from './entities/savings-product.entity';
import {
  UserSubscription,
  SubscriptionStatus,
} from './entities/user-subscription.entity';
import { SavingsGoal, SavingsGoalStatus } from './entities/savings-goal.entity';
import { ProductApySnapshot } from './entities/product-apy-snapshot.entity';
import {
  WithdrawalRequest,
  WithdrawalStatus,
} from './entities/withdrawal-request.entity';
import {
  Transaction,
  TxType,
  TxStatus,
} from '../transactions/entities/transaction.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { SavingsProductDto } from './dto/savings-product.dto';
import { GoalProgressDto } from './dto/goal-progress.dto';
import {
  ProductComparisonResponseDto,
  ProductComparisonItemDto,
  HistoricalPerformanceDto,
} from './dto/product-comparison.dto';
import {
  MetricsGranularity,
  ProductMetricsDto,
} from './dto/product-metrics.dto';
import { User } from '../user/entities/user.entity';
import { SavingsService as BlockchainSavingsService } from '../blockchain/savings.service';
import { PredictiveEvaluatorService } from './services/predictive-evaluator.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { SavingsProductVersionAudit } from './entities/savings-product-version-audit.entity';
import { WaitlistService } from './waitlist.service';
import { MilestoneService } from './services/milestone.service';
import { AuditLogService } from '../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
} from '../../common/entities/audit-log.entity';
import { TransactionStateMachineService } from '../transactions/transaction-state-machine.service';
import { DistributedTracingService } from '../apm/distributed-tracing.service';
import { TraceSpan } from '../../common/decorators/trace-span.decorator';

export type SavingsGoalProgress = GoalProgressDto;

export interface UserSubscriptionWithLiveBalance extends UserSubscription {
  indexedAmount: number;
  liveBalance: number;
  liveBalanceStroops: number;
  balanceSource: 'rpc' | 'cache';
  vaultContractId: string | null;
  estimatedYieldPerSecond: number;
}

export interface ProductCapacitySnapshot {
  productId: string;
  maxCapacity: number | null;
  utilizedCapacity: number;
  availableCapacity: number;
  utilizationPercentage: number;
  isFull: boolean;
  source: 'soroban' | 'database';
}

const STROOPS_PER_XLM = 10_000_000;
const POOLS_CACHE_KEY = 'pools_all';
const COMPARE_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const METRICS_CACHE_TTL = 3600000; // 1 hour in ms

/**
 * Derive a risk level from the product type.
 * FIXED products are lower risk; FLEXIBLE products carry medium risk.
 */
function deriveRiskLevel(type: SavingsProductType): 'low' | 'medium' | 'high' {
  return type === SavingsProductType.FIXED ? 'low' : 'medium';
}

/**
 * Generate synthetic historical performance data based on the product's
 * current APY. In a production system this would be fetched from a
 * dedicated time-series store.
 */
function buildHistoricalPerformance(apy: number): HistoricalPerformanceDto[] {
  const currentYear = new Date().getFullYear();
  return [currentYear - 2, currentYear - 1].map((year, idx) => ({
    year,
    return: Math.max(0, Math.round((apy - (1 - idx * 0.5)) * 100) / 100),
  }));
}

@Injectable()
export class SavingsService {
  private readonly logger = new Logger(SavingsService.name);

  constructor(
    @InjectRepository(SavingsProduct)
    private readonly productRepository: Repository<SavingsProduct>,
    @InjectRepository(UserSubscription)
    private readonly subscriptionRepository: Repository<UserSubscription>,
    @InjectRepository(SavingsGoal)
    private readonly goalRepository: Repository<SavingsGoal>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(ProductApySnapshot)
    private readonly snapshotRepository: Repository<ProductApySnapshot>,
    @InjectRepository(SavingsProductVersionAudit)
    private readonly productVersionAuditRepository: Repository<SavingsProductVersionAudit>,
    @InjectRepository(WithdrawalRequest)
    private readonly withdrawalRepository: Repository<WithdrawalRequest>,
    private readonly transactionStateMachine: TransactionStateMachineService,
    private readonly blockchainSavingsService: BlockchainSavingsService,
    private readonly predictiveEvaluatorService: PredictiveEvaluatorService,
    private readonly milestoneService: MilestoneService,
    private readonly waitlistService: WaitlistService,
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly auditLogService: AuditLogService,
    @Optional() readonly tracingService?: DistributedTracingService,
    @Optional() private readonly eventEmitter?: EventEmitter2,
    @Optional() private readonly eventualConsistencyService?: EventualConsistencyService,
  ) {}

  @TraceSpan('savings.createProduct')
  async createProduct(dto: CreateProductDto): Promise<SavingsProduct> {
    if (dto.minAmount > dto.maxAmount) {
      throw new BadRequestException(
        'minAmount must be less than or equal to maxAmount',
      );
    }
    const product = this.productRepository.create({
      ...dto,
      version: dto.version ?? 1,
      isActive: dto.isActive ?? true,
    });
    let savedProduct = await this.productRepository.save(product);

    if (!savedProduct.versionGroupId) {
      savedProduct.versionGroupId = savedProduct.id;
      savedProduct = await this.productRepository.save(savedProduct);
    }

    await this.recordVersionAudit(savedProduct, {
      action: 'CREATED',
      sourceProductId: null,
      targetProductId: savedProduct.id,
      metadata: { version: savedProduct.version },
    });
    await this.invalidatePoolsCache();
    return savedProduct;
  }

  @TraceSpan('savings.updateProduct')
  async updateProduct(
    id: string,
    dto: UpdateProductDto,
  ): Promise<SavingsProduct> {
    const product = await this.productRepository.findOneBy({ id });
    if (!product) {
      throw new NotFoundException(`Savings product ${id} not found`);
    }
    if (
      dto.minAmount != null &&
      dto.maxAmount != null &&
      dto.minAmount > dto.maxAmount
    ) {
      throw new BadRequestException(
        'minAmount must be less than or equal to maxAmount',
      );
    }
    if (this.requiresNewVersion(product, dto)) {
      const versionGroupId = product.versionGroupId ?? product.id;
      product.isActive = false;
      await this.productRepository.save(product);

      const versionedProduct = this.productRepository.create({
        ...product,
        ...dto,
        id: undefined,
        createdAt: undefined,
        updatedAt: undefined,
        subscriptions: undefined,
        version: (product.version ?? 1) + 1,
        versionGroupId,
        previousVersionId: product.id,
        isActive: dto.isActive ?? true,
      });
      const savedVersion = await this.productRepository.save(versionedProduct);
      await this.recordVersionAudit(savedVersion, {
        action: 'VERSION_CREATED',
        sourceProductId: product.id,
        targetProductId: savedVersion.id,
        metadata: {
          version: savedVersion.version,
          changedFields: this.getChangedFields(product, dto),
        },
      });
      await this.invalidatePoolsCache();
      return savedVersion;
    }

    Object.assign(product, dto);
    const updatedProduct = await this.productRepository.save(product);
    await this.recordVersionAudit(updatedProduct, {
      action: 'UPDATED',
      sourceProductId: product.id,
      targetProductId: updatedProduct.id,
      metadata: {
        changedFields: this.getChangedFields(product, dto),
      },
    });
    const previousIsActive = product.isActive;
    await this.syncCapacityState(updatedProduct);
    await this.invalidatePoolsCache();

    // Emit waitlist availability event when product becomes available or capacity opens
    try {
      const capacity = await this.getProductCapacitySnapshot(updatedProduct.id);

      // If capacity is set and there's room, notify waitlist
      if (capacity.maxCapacity != null && capacity.availableCapacity > 0) {
        this.eventEmitter?.emit('waitlist.product.available', {
          productId: updatedProduct.id,
          spots: 1,
        });
      }

      // If product was previously inactive and now active, notify waitlist (launch)
      if (updatedProduct.isActive && !previousIsActive) {
        this.eventEmitter?.emit('waitlist.product.available', {
          productId: updatedProduct.id,
          spots: 1,
        });
      }
    } catch (e) {
      this.logger.warn(`Failed to emit waitlist event for product ${id}: ${e}`);
    }
    return updatedProduct;
  }

  @TraceSpan('savings.findAllProducts')
  async findAllProducts(
    activeOnly = false,
    sort?: 'apy' | 'tvl',
  ): Promise<SavingsProductDto[]> {
    const products = await this.productRepository.find({
      where: activeOnly ? { isActive: true } : undefined,
      relations: ['subscriptions'],
    });

    const dtos: SavingsProductDto[] = await Promise.all(
      products.map(async (product) => {
        // Calculate TVL by summing active subscriptions
        const tvlAmount = product.subscriptions
          ? product.subscriptions
              .filter((s) => s.status === SubscriptionStatus.ACTIVE)
              .reduce((sum, s) => sum + Number(s.amount), 0)
          : 0;
        const capacity = await this.getProductCapacitySnapshot(product.id);

        return {
          id: product.id,
          name: product.name,
          type: product.type,
          description: product.description,
          interestRate: Number(product.interestRate),
          minAmount: Number(product.minAmount),
          maxAmount: Number(product.maxAmount),
          tenureMonths: product.tenureMonths,
          contractId: product.contractId,
          isActive: product.isActive,
          riskLevel: product.riskLevel || RiskLevel.LOW,
          maxSubscriptionsPerUser: product.maxSubscriptionsPerUser,
          version: product.version,
          tvlAmount,
          maxCapacity: capacity.maxCapacity,
          utilizedCapacity: capacity.utilizedCapacity,
          availableCapacity: capacity.availableCapacity,
          utilizationPercentage: capacity.utilizationPercentage,
          createdAt: product.createdAt,
          updatedAt: product.updatedAt,
        };
      }),
    );

    // Handle local sorting
    if (sort === 'apy') {
      dtos.sort((a, b) => b.interestRate - a.interestRate);
    } else if (sort === 'tvl') {
      dtos.sort((a, b) => b.tvlAmount - a.tvlAmount);
    } else {
      // Default sort: createdAt DESC with id DESC as a tie-breaker to ensure
      // stable, deterministic ordering when multiple products share the same
      // createdAt timestamp (e.g. seeded data or concurrent inserts).
      dtos.sort((a, b) => {
        const timeDiff = b.createdAt.getTime() - a.createdAt.getTime();
        if (timeDiff !== 0) return timeDiff;
        return b.id < a.id ? -1 : b.id > a.id ? 1 : 0;
      });
    }

    return dtos;
  }

  @TraceSpan('savings.findOneProduct')
  async findOneProduct(id: string): Promise<SavingsProduct> {
    const product = await this.productRepository.findOneBy({ id });
    if (!product) {
      throw new ResourceNotFoundException('Savings product', id);
    }
    return product;
  }

  /**
   * #533 / #593 — Compare up to 5 savings products side-by-side.
   * Results are cached per unique sorted product-ID set for 10 minutes.
   */
  @TraceSpan('savings.compareProducts')
  async compareProducts(
    productIds: string[],
    amount?: number,
    duration?: number,
  ): Promise<ProductComparisonResponseDto> {
    const cacheKey = `compare:${[...productIds].sort().join(',')}:${amount ?? ''}:${duration ?? ''}`;

    const cached =
      await this.cacheManager.get<ProductComparisonResponseDto>(cacheKey);
    if (cached) {
      return { ...cached, cached: true };
    }

    const products = await this.productRepository.find({
      where: { id: In(productIds) },
    });

    if (products.length !== productIds.length) {
      const foundIds = new Set(products.map((p) => p.id));
      const missing = productIds.filter((id) => !foundIds.has(id));
      throw new NotFoundException(
        `Savings products not found: ${missing.join(', ')}`,
      );
    }

    const items: ProductComparisonItemDto[] = products.map((product) => ({
      id: product.id,
      name: product.name,
      type: product.type,
      description: product.description,
      apy: Number(product.interestRate),
      tenure: product.tenureMonths,
      riskLevel: deriveRiskLevel(product.type),
      minAmount: Number(product.minAmount),
      maxAmount: Number(product.maxAmount),
      isActive: product.isActive,
      contractId: product.contractId,
      historicalPerformance: buildHistoricalPerformance(
        Number(product.interestRate),
      ),
    }));

    const response: ProductComparisonResponseDto = {
      products: items,
      cached: false,
    };

    await this.cacheManager.set(cacheKey, response, COMPARE_CACHE_TTL_MS);

    return response;
  }

  @TraceSpan('savings.findProductWithLiveData')
  async findProductWithLiveData(id: string): Promise<{
    product: SavingsProduct;
    totalAssets: number;
    capacity: ProductCapacitySnapshot;
  }> {
    const product = await this.findOneProduct(id);

    let totalAssets = 0;

    // Query live contract data if contractId is available
    if (product.contractId) {
      try {
        totalAssets = await this.blockchainSavingsService.getVaultTotalAssets(
          product.contractId,
        );
      } catch (error) {
        this.logger.warn(
          `Failed to fetch live total_assets for contract ${product.contractId}: ${(error as Error).message}`,
        );
        // Continue with totalAssets = 0 if contract query fails
      }
    }

    const capacity = await this.getProductCapacitySnapshot(product.id);

    return { product, totalAssets, capacity };
  }

  @TraceSpan('savings.migrateSubscriptionsToVersion')
  async migrateSubscriptionsToVersion(
    sourceProductId: string,
    targetProductId: string,
    actorId?: string,
    subscriptionIds?: string[],
  ): Promise<{ migratedCount: number; targetProduct: SavingsProduct }> {
    const [sourceProduct, targetProduct] = await Promise.all([
      this.findOneProduct(sourceProductId),
      this.findOneProduct(targetProductId),
    ]);

    const sourceGroupId = sourceProduct.versionGroupId ?? sourceProduct.id;
    const targetGroupId = targetProduct.versionGroupId ?? targetProduct.id;
    if (sourceGroupId !== targetGroupId) {
      throw new BadRequestException(
        'Subscriptions can only be migrated within the same product version group',
      );
    }

    const where = {
      productId: sourceProductId,
      status: SubscriptionStatus.ACTIVE,
      ...(subscriptionIds?.length ? { id: In(subscriptionIds) } : {}),
    };
    const subscriptions = await this.subscriptionRepository.find({ where });

    if (!subscriptions.length) {
      return { migratedCount: 0, targetProduct };
    }

    for (const subscription of subscriptions) {
      subscription.productId = targetProduct.id;
    }
    await this.subscriptionRepository.save(subscriptions);

    await this.recordVersionAudit(targetProduct, {
      action: 'SUBSCRIPTIONS_MIGRATED',
      actorId: actorId ?? null,
      sourceProductId,
      targetProductId,
      metadata: {
        migratedCount: subscriptions.length,
        subscriptionIds: subscriptions.map((subscription) => subscription.id),
      },
    });

    await this.invalidatePoolsCache();
    return { migratedCount: subscriptions.length, targetProduct };
  }

  @TraceSpan('savings.subscribe')
  async subscribe(
    userId: string,
    productId: string,
    amount: number,
    overrideLimits = false,
    correlationId?: string,
    requestId?: string,
  ): Promise<UserSubscription> {
    const product = await this.findOneProduct(productId);
    await this.syncCapacityState(product);
    if (!product.isActive) {
      throw new BadRequestException(
        'This savings product is not available for subscription',
      );
    }
    if (
      amount < Number(product.minAmount) ||
      amount > Number(product.maxAmount)
    ) {
      throw new BadRequestException(
        `Amount must be between ${product.minAmount} and ${product.maxAmount}`,
      );
    }

    if (!overrideLimits) {
      const activeSubscriptionsForUser =
        await this.subscriptionRepository.count({
          where: {
            userId,
            productId: product.id,
            status: SubscriptionStatus.ACTIVE,
          },
        });

      if (
        product.maxSubscriptionsPerUser != null &&
        activeSubscriptionsForUser >= product.maxSubscriptionsPerUser
      ) {
        throw new ConflictException(
          `Subscription limit reached. You can only hold ${product.maxSubscriptionsPerUser} active subscriptions for this product.`,
        );
      }

      if (product.capacity != null) {
        const activeSubscriptionsForProduct =
          await this.subscriptionRepository.count({
            where: {
              productId: product.id,
              status: SubscriptionStatus.ACTIVE,
            },
          });

        if (activeSubscriptionsForProduct >= product.capacity) {
          const { position } = await this.waitlistService.joinWaitlist(
            userId,
            product.id,
          );
          throw new ConflictException(
            `This savings product is full. You have been added to the waitlist at position ${position}.`,
          );
        }
      }
      const capacity = await this.getProductCapacitySnapshot(productId);
      if (
        capacity.maxCapacity != null &&
        (capacity.isFull || amount > capacity.availableCapacity)
      ) {
        const { position } = await this.waitlistService.joinWaitlist(
          userId,
          productId,
        );
        throw new ConflictException(
          `This savings product is at capacity. You have been added to the waitlist at position ${position}.`,
        );
      }
    }

    const subscription = this.subscriptionRepository.create({
      userId,
      productId: product.id,
      amount,
      status: SubscriptionStatus.ACTIVE,
      startDate: new Date(),
      endDate: product.tenureMonths
        ? (() => {
            const d = new Date();
            d.setMonth(d.getMonth() + product.tenureMonths);
            return d;
          })()
        : null,
    });
    const savedSubscription =
      await this.subscriptionRepository.save(subscription);

    // Record waitlist conversion if the user was on the waitlist
    await this.waitlistService.recordConversion(userId, product.id);

    await this.auditLogService.log({
      action: AuditAction.DEPOSIT,
      resourceType: AuditResourceType.SAVINGS,
      actor: userId,
      correlationId,
      requestId,
      resourceId: savedSubscription.id,
      description: `User subscribed to savings product ${product.name} with amount ${amount}`,
      newValue: { productId, amount, subscriptionId: savedSubscription.id },
      success: true,
    });

    return savedSubscription;
  }

  @TraceSpan('savings.findMySubscriptions')
  async findMySubscriptions(
    userId: string,
  ): Promise<UserSubscriptionWithLiveBalance[]> {
    const [subscriptions, user] = await Promise.all([
      this.subscriptionRepository.find({
        where: { userId },
        order: { createdAt: 'DESC' },
      }),
      this.userRepository.findOne({
        where: { id: userId },
        select: ['id', 'publicKey'],
      }),
    ]);

    if (!subscriptions.length) {
      return [];
    }

    if (!user?.publicKey) {
      return subscriptions.map((subscription) =>
        this.mapSubscriptionWithLiveBalance(
          subscription,
          Number(subscription.amount),
          Math.round(Number(subscription.amount) * STROOPS_PER_XLM),
          'cache',
          null,
        ),
      );
    }

    const userPublicKey = user.publicKey;

    const defaultVaultContractId =
      this.configService.get<string>('stellar.contractId') || null;

    return await Promise.all(
      subscriptions.map(async (subscription) => {
        const fallbackAmount = Number(subscription.amount);
        const vaultContractId =
          this.resolveVaultContractId(subscription) ?? defaultVaultContractId;

        if (!vaultContractId) {
          return this.mapSubscriptionWithLiveBalance(
            subscription,
            fallbackAmount,
            Math.round(fallbackAmount * STROOPS_PER_XLM),
            'cache',
            null,
          );
        }

        const liveBalanceStroops =
          await this.blockchainSavingsService.getUserVaultBalance(
            vaultContractId,
            userPublicKey,
          );

        return this.mapSubscriptionWithLiveBalance(
          subscription,
          this.stroopsToDecimal(liveBalanceStroops),
          liveBalanceStroops,
          'rpc',
          vaultContractId,
        );
      }),
    );
  }

  @TraceSpan('savings.getProductMetrics')
  async getProductMetrics(
    id: string,
    granularity: MetricsGranularity = MetricsGranularity.DAILY,
  ): Promise<ProductMetricsDto> {
    const cacheKey = `product_metrics:${id}:${granularity}`;
    const cached = await this.cacheManager.get<ProductMetricsDto>(cacheKey);
    if (cached) {
      return cached;
    }

    const product = await this.productRepository.findOne({
      where: { id },
      relations: ['subscriptions'],
    });
    if (!product) {
      throw new NotFoundException(`Savings product ${id} not found`);
    }

    const now = new Date();
    const lookbackDays =
      granularity === MetricsGranularity.MONTHLY
        ? 365
        : granularity === MetricsGranularity.WEEKLY
          ? 90
          : 30;

    const since = new Date(now);
    since.setDate(since.getDate() - lookbackDays);

    // Fetch historical snapshots
    const snapshots = await this.snapshotRepository
      .createQueryBuilder('s')
      .where('s.productId = :id', { id })
      .andWhere('s.snapshotDate >= :since', { since })
      .orderBy('s.snapshotDate', 'ASC')
      .getMany();

    // Build chart data — fall back to synthetic single-point if no snapshots yet
    const apyHistory = this.buildApyHistory(snapshots, product, granularity);
    const tvlHistory = this.buildTvlHistory(snapshots, product, granularity);

    // Subscription stats
    const allSubs = product.subscriptions ?? [];
    const activeSubs = allSubs.filter(
      (s) => s.status === SubscriptionStatus.ACTIVE,
    );
    const totalSubscribers = activeSubs.length;
    const retentionRate =
      allSubs.length > 0
        ? Math.round((activeSubs.length / allSubs.length) * 1000) / 10
        : 0;

    // Current TVL from active subscriptions
    const currentTvl = activeSubs.reduce((sum, s) => sum + Number(s.amount), 0);

    // Risk metrics from APY history
    const apyValues =
      apyHistory.length > 0
        ? apyHistory.map((p) => p.apy)
        : [Number(product.interestRate)];
    const riskMetrics = this.calculateRiskMetrics(apyValues);

    // Similar products: same riskLevel, different id, active
    const similar = await this.productRepository.find({
      where: { riskLevel: product.riskLevel, isActive: true },
      relations: ['subscriptions'],
    });
    const similarProducts = similar
      .filter((p) => p.id !== id)
      .slice(0, 5)
      .map((p) => {
        const subs = (p.subscriptions ?? []).filter(
          (s) => s.status === SubscriptionStatus.ACTIVE,
        );
        return {
          id: p.id,
          name: p.name,
          apy: Number(p.interestRate),
          tvl: subs.reduce((sum, s) => sum + Number(s.amount), 0),
          riskLevel: p.riskLevel,
        };
      });

    const metrics: ProductMetricsDto = {
      productId: id,
      productName: product.name,
      currentApy: Number(product.interestRate),
      currentTvl,
      totalSubscribers,
      retentionRate,
      apyHistory,
      tvlHistory,
      riskMetrics,
      similarProducts,
      cachedAt: now.toISOString(),
    };

    await this.cacheManager.set(cacheKey, metrics, METRICS_CACHE_TTL);
    return metrics;
  }

  private buildApyHistory(
    snapshots: ProductApySnapshot[],
    product: SavingsProduct,
    granularity: MetricsGranularity,
  ) {
    if (snapshots.length === 0) {
      // No historical data yet — return current rate as single point
      return [
        {
          date: new Date().toISOString().split('T')[0],
          apy: Number(product.interestRate),
        },
      ];
    }

    const grouped = this.groupSnapshotsByGranularity(snapshots, granularity);
    return grouped.map(({ date, items }) => ({
      date,
      apy:
        Math.round(
          (items.reduce((s, i) => s + Number(i.apy), 0) / items.length) * 100,
        ) / 100,
    }));
  }

  private buildTvlHistory(
    snapshots: ProductApySnapshot[],
    product: SavingsProduct,
    granularity: MetricsGranularity,
  ) {
    if (snapshots.length === 0) {
      return [
        {
          date: new Date().toISOString().split('T')[0],
          tvl: Number(product.tvlAmount),
        },
      ];
    }

    const grouped = this.groupSnapshotsByGranularity(snapshots, granularity);
    return grouped.map(({ date, items }) => ({
      date,
      tvl:
        Math.round(
          (items.reduce((s, i) => s + Number(i.tvlAmount), 0) / items.length) *
            100,
        ) / 100,
    }));
  }

  private groupSnapshotsByGranularity(
    snapshots: ProductApySnapshot[],
    granularity: MetricsGranularity,
  ): { date: string; items: ProductApySnapshot[] }[] {
    const buckets = new Map<string, ProductApySnapshot[]>();

    for (const snap of snapshots) {
      const d = new Date(snap.snapshotDate);
      let key: string;

      if (granularity === MetricsGranularity.MONTHLY) {
        key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      } else if (granularity === MetricsGranularity.WEEKLY) {
        // ISO week start (Monday)
        const day = d.getDay() || 7;
        const monday = new Date(d);
        monday.setDate(d.getDate() - day + 1);
        key = monday.toISOString().split('T')[0];
      } else {
        key = d.toISOString().split('T')[0];
      }

      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key)!.push(snap);
    }

    return Array.from(buckets.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, items]) => ({ date, items }));
  }

  private calculateRiskMetrics(apyValues: number[]) {
    const n = apyValues.length;
    const avg = apyValues.reduce((s, v) => s + v, 0) / n;
    const variance =
      n > 1
        ? apyValues.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / (n - 1)
        : 0;
    const stdDev = Math.sqrt(variance);

    // Sharpe ratio: (avg return - risk-free rate) / stdDev
    // Using 0% risk-free rate as a conservative baseline
    const sharpeRatio = stdDev > 0 ? Math.round((avg / stdDev) * 100) / 100 : 0;

    return {
      sharpeRatio,
      apyVolatility: Math.round(stdDev * 100) / 100,
      maxApy: Math.max(...apyValues),
      minApy: Math.min(...apyValues),
      avgApy: Math.round(avg * 100) / 100,
    };
  }

  async invalidatePoolsCache(): Promise<void> {
    await this.cacheManager.del(POOLS_CACHE_KEY);
    this.logger.log(
      `Invalidated savings products cache key: ${POOLS_CACHE_KEY}`,
    );
  }

  @TraceSpan('savings.getProductCapacitySnapshot')
  async getProductCapacitySnapshot(
    productId: string,
  ): Promise<ProductCapacitySnapshot> {
    const product = await this.findOneProduct(productId);
    const maxCapacity =
      product.maxCapacity != null
        ? Number(product.maxCapacity)
        : product.capacity != null
          ? Number(product.capacity)
          : null;

    let utilizedCapacity = 0;
    let source: ProductCapacitySnapshot['source'] = 'database';

    if (product.contractId) {
      try {
        const totalAssets =
          await this.blockchainSavingsService.getVaultTotalAssets(
            product.contractId,
          );
        utilizedCapacity = this.stroopsToDecimal(totalAssets);
        source = 'soroban';
      } catch (error) {
        this.logger.warn(
          `Falling back to database capacity for product ${product.id}: ${(error as Error).message}`,
        );
      }
    }

    if (source === 'database') {
      const total = await this.subscriptionRepository
        .createQueryBuilder('subscription')
        .select('COALESCE(SUM(subscription.amount), 0)', 'total')
        .where('subscription.productId = :productId', { productId })
        .andWhere('subscription.status = :status', {
          status: SubscriptionStatus.ACTIVE,
        })
        .getRawOne<{ total: string }>();
      utilizedCapacity = Number(total?.total ?? 0);
    }

    const availableCapacity =
      maxCapacity == null ? null : maxCapacity - utilizedCapacity;
    const safeAvailableCapacity =
      availableCapacity == null ? 0 : Math.max(0, availableCapacity);
    const utilizationPercentage =
      maxCapacity && maxCapacity > 0
        ? Math.min(
            100,
            Number(((utilizedCapacity / maxCapacity) * 100).toFixed(2)),
          )
        : 0;

    return {
      productId: product.id,
      maxCapacity,
      utilizedCapacity: Number(utilizedCapacity.toFixed(2)),
      availableCapacity: Number(safeAvailableCapacity.toFixed(2)),
      utilizationPercentage,
      isFull: maxCapacity != null && safeAvailableCapacity <= 0,
      source,
    };
  }

  @TraceSpan('savings.findMyGoals')
  async findMyGoals(userId: string): Promise<SavingsGoalProgress[]> {
    const [goals, user, subscriptions] = await Promise.all([
      this.goalRepository.find({
        where: { userId },
        // Stable sort: primary key createdAt DESC, tie-breaker id DESC so that
        // concurrent inserts at the same millisecond never cause duplicate/missing
        // items across paginated pages.
        order: { createdAt: 'DESC', id: 'DESC' },
      }),
      this.userRepository.findOne({
        where: { id: userId },
        select: ['id', 'publicKey'],
      }),
      this.subscriptionRepository.find({
        where: { userId },
        relations: ['product'],
      }),
    ]);

    if (!goals.length) {
      return [];
    }

    const liveVaultBalanceStroops = user?.publicKey
      ? (
          await this.blockchainSavingsService.getUserSavingsBalance(
            user.publicKey,
          )
        ).total
      : 0;

    // Calculate average yield rate from active subscriptions
    const averageYieldRate = this.calculateAverageYieldRate(subscriptions);

    const progressList = goals.map((goal) =>
      this.mapGoalWithProgress(goal, liveVaultBalanceStroops, averageYieldRate),
    );

    // Detect and persist newly achieved milestones (fire-and-forget, non-blocking)
    for (const progress of progressList) {
      this.milestoneService
        .detectAndAchieveMilestones(
          progress.id,
          progress.userId,
          progress.percentageComplete,
        )
        .catch((err) =>
          this.logger.warn(
            `Milestone detection failed for goal ${progress.id}: ${(err as Error).message}`,
          ),
        );
    }

    return progressList;
  }

  @TraceSpan('savings.createGoal')
  async createGoal(
    userId: string,
    goalName: string,
    targetAmount: number,
    targetDate: Date,
    metadata?: any,
  ): Promise<SavingsGoal> {
    // Additional server-side validation for future date
    const now = new Date();
    now.setHours(0, 0, 0, 0);

    const target = new Date(targetDate);
    target.setHours(0, 0, 0, 0);

    if (target <= now) {
      throw new BadRequestException('Target date must be in the future');
    }

    const goal = this.goalRepository.create({
      userId,
      goalName,
      targetAmount,
      targetDate,
      metadata: metadata || null,
      status: SavingsGoalStatus.IN_PROGRESS,
    });

    const saved = await this.goalRepository.save(goal);

    // Initialize automatic milestone checkpoints (25/50/75/100%)
    await this.milestoneService.initializeAutomaticMilestones(saved.id, userId);

    return saved;
  }

  @TraceSpan('savings.updateGoal')
  async updateGoal(
    goalId: string,
    userId: string,
    updates: {
      goalName?: string;
      targetAmount?: number;
      targetDate?: Date;
      status?: any;
      metadata?: any;
    },
  ): Promise<SavingsGoal> {
    const goal = await this.goalRepository.findOne({
      where: { id: goalId, userId },
    });

    if (!goal) {
      throw new NotFoundException(
        `Savings goal ${goalId} not found or does not belong to user`,
      );
    }

    Object.assign(goal, updates);
    return await this.goalRepository.save(goal);
  }

  @TraceSpan('savings.deleteGoal')
  async deleteGoal(goalId: string, userId: string): Promise<void> {
    const goal = await this.goalRepository.findOne({
      where: { id: goalId, userId },
    });

    if (!goal) {
      throw new NotFoundException(
        `Savings goal ${goalId} not found or does not belong to user`,
      );
    }

    await this.goalRepository.remove(goal);
  }

  @TraceSpan('savings.transferToGoal')
  async transferToGoal(
    userId: string,
    goalId: string,
    amount: number,
    productId?: string,
  ): Promise<Transaction> {
    const goal = await this.goalRepository.findOne({
      where: { id: goalId, userId },
    });
    if (!goal) {
      throw new NotFoundException(
        `Savings goal ${goalId} not found or does not belong to user`,
      );
    }
    if (goal.status !== SavingsGoalStatus.IN_PROGRESS) {
      throw new BadRequestException('Cannot transfer to a completed goal');
    }

    let resolvedProductId = productId;
    if (!resolvedProductId) {
      const user = await this.userRepository.findOne({ where: { id: userId } });
      resolvedProductId = user?.defaultSavingsProductId ?? undefined;
    }
    if (!resolvedProductId) {
      throw new BadRequestException(
        'No savings product specified and user has no default product',
      );
    }

    await this.subscribe(userId, resolvedProductId, amount, true);

    const tx = await this.transactionStateMachine.createTransaction(
      {
      userId,
      type: TxType.DEPOSIT,
      amount: String(amount),
      poolId: resolvedProductId,
      metadata: { goalId, goalName: goal.goalName, transferType: 'GOAL_AUTO' },
      txHash: `goal-transfer-${goalId}-${Date.now()}`,
      },
      { actor: 'savings-service', reason: 'Goal transfer initiated' },
    );
    await this.transactionStateMachine.transitionStatus(tx.id, TxStatus.PENDING_CONFIRMATION, {
      actor: 'savings-service',
      reason: 'Transfer awaiting confirmation',
    });
    await this.transactionStateMachine.transitionStatus(tx.id, TxStatus.CONFIRMED, {
      actor: 'savings-service',
      reason: 'Transfer confirmed',
    });
    return this.transactionStateMachine.transitionStatus(tx.id, TxStatus.COMPLETED, {
      actor: 'savings-service',
      reason: 'Goal transfer completed',
    });
  }

  @TraceSpan('savings.createWithdrawalRequest')
  async createWithdrawalRequest(
    userId: string,
    subscriptionId: string,
    amount: number,
    reason?: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<WithdrawalRequest> {
    const subscription = await this.subscriptionRepository.findOne({
      where: { id: subscriptionId, userId },
      relations: ['product'],
    });

    if (!subscription) {
      throw new NotFoundException(
        `Subscription ${subscriptionId} not found or does not belong to user`,
      );
    }

    if (subscription.status !== SubscriptionStatus.ACTIVE) {
      throw new BadRequestException(
        'Cannot withdraw from a non-active subscription',
      );
    }

    if (amount > Number(subscription.amount)) {
      throw new BadRequestException(
        `Withdrawal amount exceeds subscription balance of ${subscription.amount}`,
      );
    }

    // Calculate penalty for early withdrawal from locked (FIXED) products
    const penalty = this.calculateEarlyWithdrawalPenalty(subscription, amount);
    const netAmount = Number((amount - penalty).toFixed(7));

    // Estimated completion: 1 hour for processing
    const estimatedCompletionTime = new Date();
    estimatedCompletionTime.setHours(estimatedCompletionTime.getHours() + 1);

    const withdrawalRequest = this.withdrawalRepository.create({
      userId,
      subscriptionId,
      amount,
      penalty,
      netAmount,
      status: WithdrawalStatus.PENDING,
      reason: reason || null,
      estimatedCompletionTime,
    });

    const saved = await this.withdrawalRepository.save(withdrawalRequest);

    // Process withdrawal asynchronously
    this.processWithdrawal(saved.id, correlationId, requestId).catch(
      (error) => {
        this.logger.error(
          `Failed to process withdrawal ${saved.id}: ${(error as Error).message}`,
        );
      },
    );

    await this.auditLogService.log({
      action: AuditAction.WITHDRAW,
      resourceType: AuditResourceType.WITHDRAWAL_REQUEST,
      actor: userId,
      correlationId,
      requestId,
      resourceId: saved.id,
      description: `User requested withdrawal of ${amount} from subscription ${subscriptionId}${reason ? `: ${reason}` : ''}`,
      newValue: { subscriptionId, amount, penalty, netAmount, reason },
      success: true,
    });

    return saved;
  }

  private calculateEarlyWithdrawalPenalty(
    subscription: UserSubscription,
    amount: number,
  ): number {
    const product = subscription.product;

    // No penalty for flexible products or matured subscriptions
    if (product.type === SavingsProductType.FLEXIBLE) {
      return 0;
    }

    // No penalty if the subscription has matured
    if (subscription.endDate && new Date() >= new Date(subscription.endDate)) {
      return 0;
    }

    // Early withdrawal penalty: 5% of the withdrawal amount for locked products
    const EARLY_WITHDRAWAL_PENALTY_BPS = 500; // 5% in basis points
    const penalty = (amount * EARLY_WITHDRAWAL_PENALTY_BPS) / 10_000;

    return Number(penalty.toFixed(7));
  }

  private async processWithdrawal(
    withdrawalId: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<void> {
    const withdrawal = await this.withdrawalRepository.findOne({
      where: { id: withdrawalId },
      relations: ['subscription', 'subscription.product'],
    });

    if (!withdrawal) {
      throw new NotFoundException(`Withdrawal ${withdrawalId} not found`);
    }

    let transactionId: string | null = null;

    try {
      // Update status to processing
      withdrawal.status = WithdrawalStatus.PROCESSING;
      await this.withdrawalRepository.save(withdrawal);

      // Attempt on-chain withdrawal via Soroban contract
      const contractId = withdrawal.subscription.product?.contractId;
      const user = await this.userRepository.findOne({
        where: { id: withdrawal.userId },
        select: ['id', 'publicKey', 'email', 'name'],
      });

      if (contractId && user?.publicKey) {
        try {
          await this.blockchainSavingsService.invokeContractRead(
            contractId,
            'withdraw',
            [],
            user.publicKey,
          );
        } catch (error) {
          this.logger.warn(
            `On-chain withdrawal simulation for ${withdrawalId}: ${(error as Error).message}`,
          );
        }
      }

      // Record in transaction ledger
      const transaction = await this.transactionStateMachine.createTransaction(
        {
          userId: withdrawal.userId,
          type: TxType.WITHDRAW,
          amount: String(withdrawal.netAmount),
          publicKey: user?.publicKey || null,
          metadata: {
            withdrawalRequestId: withdrawal.id,
            grossAmount: String(withdrawal.amount),
            penalty: String(withdrawal.penalty),
            netAmount: String(withdrawal.netAmount),
            subscriptionId: withdrawal.subscriptionId,
            reason: withdrawal.reason,
          },
        },
        {
          actor: 'savings-service',
          reason: 'Withdrawal ledger transaction created',
        },
      );
      transactionId = transaction.id;
      await this.transactionStateMachine.transitionStatus(
        transaction.id,
        TxStatus.PENDING_CONFIRMATION,
        {
          actor: 'savings-service',
          reason: 'Withdrawal awaiting confirmation',
        },
      );
      await this.transactionStateMachine.transitionStatus(transaction.id, TxStatus.CONFIRMED, {
        actor: 'savings-service',
        reason: 'Withdrawal confirmed',
      });
      await this.transactionStateMachine.transitionStatus(transaction.id, TxStatus.COMPLETED, {
        actor: 'savings-service',
        reason: 'Withdrawal completed',
      });

      // Update subscription amount
      const newAmount =
        Number(withdrawal.subscription.amount) - Number(withdrawal.amount);
      await this.subscriptionRepository.update(withdrawal.subscriptionId, {
        amount: Math.max(0, newAmount),
        status:
          newAmount <= 0
            ? SubscriptionStatus.CANCELLED
            : SubscriptionStatus.ACTIVE,
      });

      // Mark withdrawal as completed
      withdrawal.status = WithdrawalStatus.COMPLETED;
      withdrawal.txHash = transaction.txHash || null;
      withdrawal.completedAt = new Date();
      await this.withdrawalRepository.save(withdrawal);

      await this.auditLogService.log({
        action: AuditAction.WITHDRAW,
        resourceType: AuditResourceType.WITHDRAWAL_REQUEST,
        actor: withdrawal.userId,
        correlationId,
        requestId,
        resourceId: withdrawal.id,
        description: `Withdrawal ${withdrawalId} processed successfully — net ${withdrawal.netAmount}`,
        newValue: {
          status: WithdrawalStatus.COMPLETED,
          txHash: transaction.txHash,
          netAmount: withdrawal.netAmount,
          penalty: withdrawal.penalty,
        },
        success: true,
      });

      // Emit event for notification
      this.eventEmitter?.emit('withdrawal.completed', {
        userId: withdrawal.userId,
        withdrawalId: withdrawal.id,
        amount: withdrawal.amount,
        penalty: withdrawal.penalty,
        netAmount: withdrawal.netAmount,
        timestamp: new Date(),
      });
    } catch (error) {
      if (transactionId) {
        try {
          await this.transactionStateMachine.transitionStatus(
            transactionId,
            TxStatus.FAILED,
            {
              actor: 'savings-service',
              reason: 'Withdrawal processing failed',
              metadata: {
                error:
                  error instanceof Error
                    ? error.message
                    : 'Unknown withdrawal error',
              },
            },
          );
        } catch {
          // If transition is not valid from current state, keep original error flow.
        }
      }
      withdrawal.status = WithdrawalStatus.FAILED;
      await this.withdrawalRepository.save(withdrawal);

      await this.auditLogService.log({
        action: AuditAction.WITHDRAW,
        resourceType: AuditResourceType.WITHDRAWAL_REQUEST,
        actor: withdrawal.userId,
        correlationId,
        requestId,
        resourceId: withdrawal.id,
        description: `Withdrawal ${withdrawalId} failed: ${(error as Error).message}`,
        errorMessage: (error as Error).message,
        success: false,
      });

      throw error;
    }
  }

  private mapGoalWithProgress(
    goal: SavingsGoal,
    liveVaultBalanceStroops: number,
    yieldRate: number = 0,
  ): SavingsGoalProgress {
    const targetAmount = Number(goal.targetAmount);
    const currentBalance = this.stroopsToDecimal(liveVaultBalanceStroops);
    const percentageComplete = this.calculatePercentageComplete(
      liveVaultBalanceStroops,
      targetAmount,
    );

    // Chronological Predictive Evaluator: Calculate projected balance at target date
    const projectedBalance =
      this.predictiveEvaluatorService.calculateProjectedBalance(
        currentBalance,
        yieldRate,
        goal.targetDate,
      );

    // Determine if user is off track
    const isOffTrack = this.predictiveEvaluatorService.isOffTrack(
      projectedBalance,
      targetAmount,
    );

    // Calculate the gap between target and projected balance
    const projectionGap =
      this.predictiveEvaluatorService.calculateProjectionGap(
        targetAmount,
        projectedBalance,
      );

    return {
      id: goal.id,
      userId: goal.userId,
      goalName: goal.goalName,
      targetAmount,
      targetDate: goal.targetDate,
      status: goal.status,
      metadata: goal.metadata,
      createdAt: goal.createdAt,
      updatedAt: goal.updatedAt,
      currentBalance,
      percentageComplete,
      projectedBalance,
      isOffTrack,
      projectionGap,
      appliedYieldRate: yieldRate,
    };
  }

  private mapSubscriptionWithLiveBalance(
    subscription: UserSubscription,
    liveBalance: number,
    liveBalanceStroops: number,
    balanceSource: 'rpc' | 'cache',
    vaultContractId: string | null,
  ): UserSubscriptionWithLiveBalance {
    const annualRate = Number(subscription.product?.interestRate ?? 0) / 100;
    const estimatedYieldPerSecond = parseFloat(
      ((liveBalance * annualRate) / (365 * 24 * 3600)).toFixed(10),
    );
    return {
      ...subscription,
      indexedAmount: Number(subscription.amount),
      liveBalance,
      liveBalanceStroops,
      balanceSource,
      vaultContractId,
      estimatedYieldPerSecond,
    };
  }

  private resolveVaultContractId(
    subscription: UserSubscription,
  ): string | null {
    const candidates = [
      (subscription as UserSubscription & { contractId?: unknown }).contractId,
      (
        subscription.product as SavingsProduct & {
          contractId?: unknown;
          vaultContractId?: unknown;
        }
      )?.contractId,
      (
        subscription.product as SavingsProduct & {
          contractId?: unknown;
          vaultContractId?: unknown;
        }
      )?.vaultContractId,
    ];

    const contractId = candidates.find(
      (candidate): candidate is string =>
        typeof candidate === 'string' && candidate.trim().length > 0,
    );

    return contractId ?? null;
  }

  private calculatePercentageComplete(
    liveVaultBalanceStroops: number,
    targetAmount: number,
  ): number {
    if (targetAmount <= 0) {
      return 0;
    }

    const targetAmountStroops = Math.round(targetAmount * STROOPS_PER_XLM);
    if (targetAmountStroops <= 0) {
      return 0;
    }

    const percentage = (liveVaultBalanceStroops / targetAmountStroops) * 100;

    return Math.max(0, Math.min(100, Math.round(percentage)));
  }

  private stroopsToDecimal(amountInStroops: number): number {
    return Number((amountInStroops / STROOPS_PER_XLM).toFixed(2));
  }

  private calculateAverageYieldRate(subscriptions: UserSubscription[]): number {
    if (!subscriptions.length) {
      return 0;
    }

    const activeSubscriptions = subscriptions.filter(
      (sub) => sub.status === SubscriptionStatus.ACTIVE,
    );

    if (!activeSubscriptions.length) {
      return 0;
    }

    const totalYield = activeSubscriptions.reduce((sum, sub) => {
      const yieldRate = Number(sub.product?.interestRate || 0);
      return sum + yieldRate;
    }, 0);

    return totalYield / activeSubscriptions.length;
  }

  private requiresNewVersion(
    product: SavingsProduct,
    dto: UpdateProductDto,
  ): boolean {
    const versionedFields: Array<keyof UpdateProductDto> = [
      'interestRate',
      'minAmount',
      'maxAmount',
      'tenureMonths',
      'description',
      'type',
    ];

    return versionedFields.some((field) => {
      const nextValue = dto[field];
      return (
        nextValue !== undefined &&
        nextValue !== product[field as keyof SavingsProduct]
      );
    });
  }

  private getChangedFields(
    product: SavingsProduct,
    dto: UpdateProductDto,
  ): Record<string, { from: unknown; to: unknown }> {
    const productRecord = product as unknown as Record<string, unknown>;

    return Object.entries(dto).reduce(
      (changes, [key, value]) => {
        if (value !== undefined && value !== productRecord[key]) {
          changes[key] = {
            from: productRecord[key],
            to: value,
          };
        }
        return changes;
      },
      {} as Record<string, { from: unknown; to: unknown }>,
    );
  }

  private async recordVersionAudit(
    product: SavingsProduct,
    options: {
      action: SavingsProductVersionAudit['action'];
      actorId?: string | null;
      sourceProductId: string | null;
      targetProductId: string | null;
      metadata?: Record<string, unknown>;
    },
  ): Promise<void> {
    await this.productVersionAuditRepository.save(
      this.productVersionAuditRepository.create({
        productId: product.id,
        versionGroupId: product.versionGroupId ?? product.id,
        sourceProductId: options.sourceProductId,
        targetProductId: options.targetProductId,
        actorId: options.actorId ?? null,
        action: options.action,
        metadata: options.metadata ?? null,
      }),
    );
  }

  private async syncCapacityState(
    product: SavingsProduct,
  ): Promise<SavingsProduct> {
    const maxCapacity =
      product.maxCapacity != null
        ? Number(product.maxCapacity)
        : product.capacity != null
          ? Number(product.capacity)
          : null;

    if (maxCapacity == null) {
      return product;
    }

    const snapshot = await this.getProductCapacitySnapshot(product.id);
    if (snapshot.isFull && product.isActive) {
      product.isActive = false;
      await this.productRepository.save(product);
      this.eventEmitter?.emit('savings.capacity.threshold', {
        productId: product.id,
        utilizationPercentage: snapshot.utilizationPercentage,
        isFull: true,
      });
      return product;
    }

    if (snapshot.utilizationPercentage >= 80) {
      this.eventEmitter?.emit('savings.capacity.threshold', {
        productId: product.id,
        utilizationPercentage: snapshot.utilizationPercentage,
        isFull: false,
      });
    }

    return product;
  }
}

import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SavingsProduct } from './entities/savings-product.entity';
import {
  UserSubscription,
  SubscriptionStatus,
} from './entities/user-subscription.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from './entities/savings-goal.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { User } from '../user/entities/user.entity';
import { SavingsService as BlockchainSavingsService } from '../blockchain/savings.service';

export interface SavingsGoalProgress {
  id: string;
  userId: string;
  goalName: string;
  targetAmount: number;
  targetDate: Date;
  status: SavingsGoalStatus;
  metadata: SavingsGoal['metadata'];
  createdAt: Date;
  updatedAt: Date;
  currentBalance: number;
  percentageComplete: number;
}

const STROOPS_PER_XLM = 10_000_000;

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
    private readonly blockchainSavingsService: BlockchainSavingsService,
  ) {}

  async createProduct(dto: CreateProductDto): Promise<SavingsProduct> {
    if (dto.minAmount > dto.maxAmount) {
      throw new BadRequestException('minAmount must be less than or equal to maxAmount');
    }
    const product = this.productRepository.create({
      ...dto,
      isActive: dto.isActive ?? true,
    });
    return await this.productRepository.save(product);
  }

  async updateProduct(
    id: string,
    dto: UpdateProductDto,
  ): Promise<SavingsProduct> {
    const product = await this.productRepository.findOneBy({ id });
    if (!product) {
      throw new NotFoundException(`Savings product ${id} not found`);
    }
    if (dto.minAmount != null && dto.maxAmount != null && dto.minAmount > dto.maxAmount) {
      throw new BadRequestException('minAmount must be less than or equal to maxAmount');
    }
    Object.assign(product, dto);
    return await this.productRepository.save(product);
  }

  async findAllProducts(activeOnly = false): Promise<SavingsProduct[]> {
    return await this.productRepository.find({
      where: activeOnly ? { isActive: true } : undefined,
      order: { createdAt: 'DESC' },
    });
  }

  async findOneProduct(id: string): Promise<SavingsProduct> {
    const product = await this.productRepository.findOneBy({ id });
    if (!product) {
      throw new NotFoundException(`Savings product ${id} not found`);
    }
    return product;
  }

  async subscribe(
    userId: string,
    productId: string,
    amount: number,
  ): Promise<UserSubscription> {
    const product = await this.findOneProduct(productId);
    if (!product.isActive) {
      throw new BadRequestException('This savings product is not available for subscription');
    }
    if (amount < Number(product.minAmount) || amount > Number(product.maxAmount)) {
      throw new BadRequestException(
        `Amount must be between ${product.minAmount} and ${product.maxAmount}`,
      );
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
            d.setMonth(d.getMonth() + product.tenureMonths!);
            return d;
          })()
        : null,
    });
    return await this.subscriptionRepository.save(subscription);
  }

  async findMySubscriptions(userId: string): Promise<UserSubscription[]> {
    return await this.subscriptionRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async findMyGoals(userId: string): Promise<SavingsGoalProgress[]> {
    const [goals, user] = await Promise.all([
      this.goalRepository.find({
        where: { userId },
        order: { createdAt: 'DESC' },
      }),
      this.userRepository.findOne({
        where: { id: userId },
        select: ['id', 'publicKey'],
      }),
    ]);

    if (!goals.length) {
      return [];
    }

    const liveVaultBalanceStroops = user?.publicKey
      ? (await this.blockchainSavingsService.getUserSavingsBalance(user.publicKey))
          .total
      : 0;

    return goals.map((goal) =>
      this.mapGoalWithProgress(goal, liveVaultBalanceStroops),
    );
  }

  private mapGoalWithProgress(
    goal: SavingsGoal,
    liveVaultBalanceStroops: number,
  ): SavingsGoalProgress {
    const targetAmount = Number(goal.targetAmount);
    const currentBalance = this.stroopsToDecimal(liveVaultBalanceStroops);
    const percentageComplete = this.calculatePercentageComplete(
      liveVaultBalanceStroops,
      targetAmount,
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
    };
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
}

import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { SavingsProduct } from './entities/savings-product.entity';
import {
  UserSubscription,
  SubscriptionStatus,
} from './entities/user-subscription.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { SweepCompletedEvent } from '../notifications/events/sweep-completed.event';

@Injectable()
export class SavingsService {
  private readonly logger = new Logger(SavingsService.name);

  constructor(
    @InjectRepository(SavingsProduct)
    private readonly productRepository: Repository<SavingsProduct>,
    @InjectRepository(UserSubscription)
    private readonly subscriptionRepository: Repository<UserSubscription>,
    private readonly eventEmitter: EventEmitter2,
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

  async sweepSubscription(
    subscriptionId: string,
    userEmail: string,
    userName: string,
    txHash?: string,
  ): Promise<UserSubscription> {
    const subscription = await this.subscriptionRepository.findOne({
      where: { id: subscriptionId },
      relations: ['product'],
    });

    if (!subscription) {
      throw new NotFoundException(`Subscription ${subscriptionId} not found`);
    }

    if (subscription.status !== SubscriptionStatus.ACTIVE) {
      throw new BadRequestException('Only ACTIVE subscriptions can be swept');
    }

    subscription.status = SubscriptionStatus.MATURED;
    const saved = await this.subscriptionRepository.save(subscription);

    this.eventEmitter.emit(
      'sweep.completed',
      new SweepCompletedEvent(
        subscription.userId,
        userEmail,
        userName,
        subscription.id,
        subscription.product.name,
        Number(subscription.amount),
        txHash,
      ),
    );

    return saved;
  }
}

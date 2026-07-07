import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../user/entities/user.entity';
import { UserWallet } from '../user/entities/user-wallet.entity';
import {
  Transaction,
  TxType,
} from '../transactions/entities/transaction.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from '../savings/entities/savings-goal.entity';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface GenerateTestDataOptions {
  /** Number of test users to create (default: 5, max: 50) */
  userCount?: number;
  /** Number of transactions to create per user (default: 5, max: 20) */
  transactionsPerUser?: number;
  /** Number of savings goals to create per user (default: 2, max: 10) */
  savingsGoalsPerUser?: number;
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface GenerateTestDataResult {
  users: User[];
  transactions: Transaction[];
  savingsGoals: SavingsGoal[];
  summary: {
    usersCreated: number;
    transactionsCreated: number;
    savingsGoalsCreated: number;
    options: Required<GenerateTestDataOptions>;
  };
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

@Injectable()
export class TestDataGeneratorService {
  private readonly logger = new Logger(TestDataGeneratorService.name);

  /** Default generation options */
  private static readonly DEFAULTS: Required<GenerateTestDataOptions> = {
    userCount: 5,
    transactionsPerUser: 5,
    savingsGoalsPerUser: 2,
  };

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(UserWallet)
    private userWalletRepository: Repository<UserWallet>,
    @InjectRepository(Transaction)
    private transactionRepository: Repository<Transaction>,
    @InjectRepository(SavingsProduct)
    private savingsProductRepository: Repository<SavingsProduct>,
    @InjectRepository(SavingsGoal)
    private savingsGoalRepository: Repository<SavingsGoal>,
  ) {}

  /**
   * Generate configurable test data for sandbox use.
   *
   * @param options - Configurable counts for users, transactions and goals.
   *                  Falls back to `DEFAULTS` for any omitted field.
   */
  async generateTestData(
    options: GenerateTestDataOptions = {},
  ): Promise<GenerateTestDataResult> {
    const resolved: Required<GenerateTestDataOptions> = {
      userCount: this.clamp(options.userCount ?? TestDataGeneratorService.DEFAULTS.userCount, 1, 50),
      transactionsPerUser: this.clamp(
        options.transactionsPerUser ?? TestDataGeneratorService.DEFAULTS.transactionsPerUser,
        1,
        20,
      ),
      savingsGoalsPerUser: this.clamp(
        options.savingsGoalsPerUser ?? TestDataGeneratorService.DEFAULTS.savingsGoalsPerUser,
        1,
        10,
      ),
    };

    this.logger.log('Generating sandbox test data', { options: resolved });

    const users: User[] = [];
    const transactions: Transaction[] = [];
    const savingsGoals: SavingsGoal[] = [];

    for (let i = 0; i < resolved.userCount; i++) {
      const user = await this.createTestUser(i);
      users.push(user);

      const wallet = await this.createTestWallet(user);

      for (let j = 0; j < resolved.transactionsPerUser; j++) {
        const transaction = await this.createTestTransaction(user, wallet, j);
        transactions.push(transaction);
      }

      for (let k = 0; k < resolved.savingsGoalsPerUser; k++) {
        const goal = await this.createTestSavingsGoal(user);
        savingsGoals.push(goal);
      }
    }

    this.logger.log('Sandbox test data generation complete', {
      usersCreated: users.length,
      transactionsCreated: transactions.length,
      savingsGoalsCreated: savingsGoals.length,
    });

    return {
      users,
      transactions,
      savingsGoals,
      summary: {
        usersCreated: users.length,
        transactionsCreated: transactions.length,
        savingsGoalsCreated: savingsGoals.length,
        options: resolved,
      },
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async createTestUser(index: number): Promise<User> {
    const hashedPassword = await bcrypt.hash('testpassword123', 10);
    const user = this.userRepository.create({
      email: `sandbox-user-${index + 1}-${uuidv4().slice(0, 8)}@sandbox.example.com`,
      name: `Sandbox User ${index + 1}`,
      password: hashedPassword,
      role: 'USER',
      kycStatus: index % 2 === 0 ? 'APPROVED' : 'NOT_SUBMITTED',
      tier: index < 2 ? 'FREE' : index < 4 ? 'VERIFIED' : 'PREMIUM',
      isActive: true,
    });
    return this.userRepository.save(user);
  }

  private async createTestWallet(user: User): Promise<UserWallet> {
    const wallet = this.userWalletRepository.create({
      userId: user.id,
      // Generate a plausible-looking Stellar public key (56 alphanumeric chars after G)
      address: `G${uuidv4().replace(/-/g, '').toUpperCase().slice(0, 55)}`,
      isPrimary: true,
    });
    return this.userWalletRepository.save(wallet);
  }

  private async createTestTransaction(
    user: User,
    _wallet: UserWallet,
    index: number,
  ): Promise<Transaction> {
    const transaction = this.transactionRepository.create({
      userId: user.id,
      type: index % 2 === 0 ? TxType.DEPOSIT : TxType.WITHDRAW,
      amount: (Math.random() * 1000 + 1).toFixed(2),
      txHash: `sandbox_tx_${uuidv4()}`,
    });
    return this.transactionRepository.save(transaction);
  }

  private async createTestSavingsGoal(user: User): Promise<SavingsGoal> {
    const goal = this.savingsGoalRepository.create({
      userId: user.id,
      goalName: `Sandbox Goal ${uuidv4().slice(0, 8)}`,
      targetAmount: Math.floor(Math.random() * 10_000 + 1_000),
      targetDate: new Date(
        Date.now() + Math.random() * 365 * 24 * 60 * 60 * 1_000,
      ),
      status: SavingsGoalStatus.IN_PROGRESS,
    });
    return this.savingsGoalRepository.save(goal);
  }

  /** Clamp a number within [min, max]. */
  private clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }
}

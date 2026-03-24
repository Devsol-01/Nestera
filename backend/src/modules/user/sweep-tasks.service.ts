import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { StellarService } from '../blockchain/stellar.service';

@Injectable()
export class SweepTasksService {
  private readonly logger = new Logger(SweepTasksService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly stellarService: StellarService,
  ) {}

  /**
   * Cron job that runs every hour to check and execute account sweeps
   * Schedule: Every hour at minute 0
   */
  @Cron(CronExpression.EVERY_HOUR)
  async handleAccountSweep() {
    this.logger.log('Starting account sweep job...');

    try {
      // Fetch users with auto-sweep enabled
      const usersWithAutoSweep = await this.getUsersWithAutoSweepEnabled();
      
      this.logger.log(`Found ${usersWithAutoSweep.length} users with auto-sweep enabled`);

      for (const user of usersWithAutoSweep) {
        await this.processSweepForUser(user);
      }

      this.logger.log('Account sweep job completed successfully');
    } catch (error) {
      this.logger.error('Error during account sweep job', error);
    }
  }

  /**
   * Fetch all users who have auto-sweep enabled and have configured threshold
   */
  private async getUsersWithAutoSweepEnabled(): Promise<User[]> {
    return this.userRepository.find({
      where: {
        autoSweepEnabled: true,
      },
    });
  }

  /**
   * Process sweep for a single user
   */
  private async processSweepForUser(user: User): Promise<void> {
    try {
      this.logger.log(`Processing sweep for user ${user.id} (${user.email})`);

      // Validate user has required configuration
      if (!user.publicKey) {
        this.logger.warn(`User ${user.id} has no public key, skipping`);
        return;
      }

      if (!user.sweepThreshold || user.sweepThreshold <= 0) {
        this.logger.warn(`User ${user.id} has invalid sweep threshold, skipping`);
        return;
      }

      if (!user.defaultSavingsProductId) {
        this.logger.warn(`User ${user.id} has no default savings product, skipping`);
        return;
      }

      // Calculate excess funds
      const excessAmount = await this.calculateExcessFunds(user);

      if (excessAmount <= 0) {
        this.logger.debug(`User ${user.id} has no excess funds to sweep`);
        return;
      }

      this.logger.log(
        `User ${user.id} has ${excessAmount} XLM excess funds above threshold ${user.sweepThreshold}`,
      );

      // Execute the sweep (stubbed for now)
      await this.executeSweep(user, excessAmount);
    } catch (error) {
      this.logger.error(`Error processing sweep for user ${user.id}`, error);
    }
  }

  /**
   * Calculate excess funds based on user's wallet balance and threshold
   */
  private async calculateExcessFunds(user: User): Promise<number> {
    try {
      // Get user's current wallet balance from Stellar
      const balance = await this.getWalletBalance(user.publicKey!);
      
      this.logger.debug(
        `User ${user.id} balance: ${balance} XLM, threshold: ${user.sweepThreshold} XLM`,
      );

      // Calculate excess: balance - threshold
      const excess = balance - Number(user.sweepThreshold);

      // Only return positive excess amounts
      return excess > 0 ? excess : 0;
    } catch (error) {
      this.logger.error(`Error calculating excess funds for user ${user.id}`, error);
      return 0;
    }
  }

  /**
   * Get wallet balance from Stellar network
   * This is a simplified implementation - in production you'd want to:
   * - Handle multiple asset types
   * - Consider minimum balance requirements
   * - Account for transaction fees
   */
  private async getWalletBalance(publicKey: string): Promise<number> {
    try {
      const horizonServer = this.stellarService.getHorizonServer();
      const account = await horizonServer.loadAccount(publicKey);

      // Find XLM (native) balance
      const xlmBalance = account.balances.find(
        (balance) => balance.asset_type === 'native',
      );

      if (!xlmBalance || xlmBalance.asset_type !== 'native') {
        this.logger.warn(`No XLM balance found for ${publicKey}`);
        return 0;
      }

      return parseFloat(xlmBalance.balance);
    } catch (error) {
      this.logger.error(`Error fetching balance for ${publicKey}`, error);
      return 0;
    }
  }

  /**
   * Execute the actual sweep transaction
   * STUB: This is where you would integrate with StellarService to transfer funds
   */
  private async executeSweep(user: User, amount: number): Promise<void> {
    this.logger.log(
      `[STUB] Executing sweep for user ${user.id}: ${amount} XLM to savings product ${user.defaultSavingsProductId}`,
    );

    // TODO: Implement actual transfer logic
    // This would involve:
    // 1. Creating a Stellar transaction to transfer funds
    // 2. Signing the transaction (requires user's secret key or multi-sig setup)
    // 3. Submitting to the network
    // 4. Recording the sweep in the database
    // 5. Creating a UserSubscription record if needed
    
    // Example pseudo-code:
    // const transaction = await this.stellarService.createPaymentTransaction(
    //   user.publicKey,
    //   savingsProductWallet,
    //   amount,
    // );
    // await this.stellarService.submitTransaction(transaction);
    // await this.recordSweepTransaction(user.id, amount, user.defaultSavingsProductId);

    this.logger.log(`[STUB] Sweep completed for user ${user.id}`);
  }

  /**
   * Manual trigger for testing purposes
   * Can be called via API endpoint if needed
   */
  async triggerManualSweep(userId: string): Promise<void> {
    this.logger.log(`Manual sweep triggered for user ${userId}`);
    
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new Error(`User ${userId} not found`);
    }

    if (!user.autoSweepEnabled) {
      throw new Error(`Auto-sweep is not enabled for user ${userId}`);
    }

    await this.processSweepForUser(user);
  }
}

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { StellarService } from './stellar.service';

export interface SavingsBalance {
  flexible: number;
  locked: number;
  total: number;
}

@Injectable()
export class SavingsService {
  private readonly logger = new Logger(SavingsService.name);

  constructor(
    private readonly stellarService: StellarService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Fetch total savings for a user from the Soroban contract
   * @param publicKey The user's Stellar public key
   * @returns Object containing flexible, locked, and total savings balances
   */
  async getUserSavingsBalance(publicKey: string): Promise<SavingsBalance> {
    try {
      const horizonServer = this.stellarService.getHorizonServer();
      
      // Fetch account to get current state
      const account = await horizonServer.accounts().accountId(publicKey).call();
      
      // For now, return a structure based on available data
      // In a production system, this would query the actual Soroban contract
      const flexibleBalance = 0;
      const lockedBalance = 0;

      return {
        flexible: flexibleBalance,
        locked: lockedBalance,
        total: flexibleBalance + lockedBalance,
      };
    } catch (error) {
      this.logger.warn(
        `Could not fetch savings for ${publicKey}: ${error.message}`,
      );
      return {
        flexible: 0,
        locked: 0,
        total: 0,
      };
    }
  }

  /**
   * Fetch wallet balance from Stellar
   * @param publicKey The user's Stellar public key
   * @param asset Optional asset code to filter by (defaults to native XLM)
   * @returns Balance in stroops (smallest unit)
   */
  async getWalletBalance(publicKey: string, asset: string = 'native'): Promise<number> {
    try {
      const horizonServer = this.stellarService.getHorizonServer();
      const account = await horizonServer.accounts().accountId(publicKey).call();

      if (asset === 'native') {
        // Return native balance in stroops (1 XLM = 10,000,000 stroops)
        return Math.floor(parseFloat(account.balances[0].balance) * 10_000_000);
      }

      // Find specific asset balance
      const assetBalance = account.balances.find(
        (balance) => 'asset_code' in balance && balance.asset_code === asset,
      );
      
      if (assetBalance && 'balance' in assetBalance) {
        return Math.floor(parseFloat(assetBalance.balance) * 10_000_000);
      }

      return 0;
    } catch (error) {
      this.logger.warn(
        `Could not fetch wallet balance for ${publicKey}: ${error.message}`,
      );
      return 0;
    }
  }
}

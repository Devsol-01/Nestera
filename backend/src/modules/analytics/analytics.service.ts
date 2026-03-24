import { Injectable, Logger } from '@nestjs/common';
import { Horizon } from '@stellar/stellar-sdk';
import { StellarService } from '../blockchain/stellar.service';
import {
  AssetAllocationDto,
  AssetAllocationItemDto,
} from './dto/asset-allocation.dto';

@Injectable()
export class AnalyticsService {
  private readonly logger = new Logger(AnalyticsService.name);

  constructor(private readonly stellarService: StellarService) {}

  /**
   * Aggregates all token balances for a user's Stellar account and returns
   * each asset's share of the total portfolio, sorted highest-first.
   *
   * Assets with a zero balance are excluded from the output.
   */
  async getAssetAllocation(publicKey: string): Promise<AssetAllocationDto> {
    const horizonServer = this.stellarService.getHorizonServer();

    let account: Horizon.ServerApi.AccountRecord;

    try {
      account = await horizonServer.accounts().accountId(publicKey).call();
    } catch (error) {
      this.logger.warn(
        `Could not fetch account ${publicKey}: ${error.message}`,
      );
      return { allocations: [], total: 0 };
    }

    // ── Aggregate by assetId ──────────────────────────────────────────────────
    const holdingsMap = new Map<string, number>();

    for (const balance of account.balances) {
      const assetId =
        balance.asset_type === 'native'
          ? 'XLM'
          : (balance as { asset_code: string }).asset_code;

      const amount = parseFloat(balance.balance);
      if (amount <= 0) continue;

      holdingsMap.set(assetId, (holdingsMap.get(assetId) ?? 0) + amount);
    }

    if (holdingsMap.size === 0) {
      return { allocations: [], total: 0 };
    }

    // ── Compute total ─────────────────────────────────────────────────────────
    const total = [...holdingsMap.values()].reduce((sum, v) => sum + v, 0);

    // ── Build allocation items ────────────────────────────────────────────────
    const allocations: AssetAllocationItemDto[] = [...holdingsMap.entries()]
      .map(([assetId, amount]) => ({
        assetId,
        amount: parseFloat(amount.toFixed(7)),
        percentage: parseFloat(((amount / total) * 100).toFixed(2)),
      }))
      .sort((a, b) => b.percentage - a.percentage);

    return { allocations, total: parseFloat(total.toFixed(7)) };
  }
}

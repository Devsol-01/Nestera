import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CurrencyService } from '../../modules/currency/currency.service';

/**
 * Asset configuration for formatting precision and symbols
 */
interface AssetConfig {
  decimals: number;
  symbol: string;
  displaySymbol: string;
  stellarExpertUrl: string;
}

/**
 * Known Stellar assets with their precision and display configuration
 */
const ASSET_CONFIGS: Record<string, AssetConfig> = {
  // USDC on Stellar (Circle)
  CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA: {
    decimals: 7,
    symbol: 'USDC',
    displaySymbol: '$',
    stellarExpertUrl: 'https://stellar.expert/explorer/testnet',
  },
  // Default fallback for unknown assets
  default: {
    decimals: 7,
    symbol: 'XLM',
    displaySymbol: '◎',
    stellarExpertUrl: 'https://stellar.expert/explorer/testnet',
  },
};

/**
 * Transaction Formatting Interceptor
 *
 * Enriches transaction responses with:
 * - Formatted amounts (e.g., "$500.00" from "500000000")
 * - Asset symbols and precision handling
 * - Stellar Expert exploration links
 * - Human-readable formatting for UI consumption
 */
@Injectable()
export class TransactionFormattingInterceptor implements NestInterceptor {
  constructor(private readonly currencyService: CurrencyService) {}

  /**
   * Intercept and enrich transaction responses
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(map((data) => this.formatTransactionData(data)));
  }

  /**
   * Recursively format transaction data structures
   */
  private formatTransactionData(data: any): any {
    if (Array.isArray(data)) {
      return data.map((item) => this.formatTransactionData(item));
    }

    if (data && typeof data === 'object') {
      const formatted = { ...data };

      // Format individual transaction objects
      if (this.isTransactionObject(formatted)) {
        return this.formatTransaction(formatted);
      }

      // Recursively format nested objects
      for (const key in formatted) {
        if (Object.hasOwn(formatted, key)) {
          formatted[key] = this.formatTransactionData(formatted[key]);
        }
      }

      return formatted;
    }

    return data;
  }

  /**
   * Check if object represents a transaction
   */
  private isTransactionObject(obj: any): boolean {
    return (
      obj &&
      typeof obj === 'object' &&
      (obj.amount !== undefined || obj.transactionHash !== undefined)
    );
  }

  /**
   * Format a single transaction object
   */
  private formatTransaction(transaction: any): any {
    const formatted = { ...transaction };

    // Format amount if present
    if (formatted.amount !== undefined) {
      formatted.amountFormatted = this.formatAmount(
        formatted.amount,
        formatted.currencyCode,
      );
    }

    // Add Stellar Expert links if transaction hash exists
    if (formatted.transactionHash) {
      formatted.explorerLinks = this.generateExplorerLinks(
        formatted.transactionHash,
        formatted.assetId || formatted.contractId,
      );
    }

    // Add formatted date/time if createdAt exists
    if (formatted.createdAt && !formatted.formattedDate) {
      const date = new Date(formatted.createdAt);
      formatted.formattedDate = date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
      formatted.formattedTime = date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    }

    return formatted;
  }

  /**
   * Format raw amount string to human-readable format
   * @param amount Raw amount as string (e.g., "100000000")
   * @param assetId Asset contract ID for precision lookup
   * @returns Formatted amount object with multiple representations
   */
  private formatAmount(amount: string | number, assetId?: string): any {
    if (assetId && ['USDC', 'USDT', 'XLM', 'EURC'].includes(assetId)) {
      return this.currencyService.formatAmount(amount, assetId);
    }

    const assetConfig = this.getAssetConfig(assetId);
    const rawAmount = typeof amount === 'string' ? amount : amount.toString();

    try {
      // Parse as decimal with proper precision
      const numericAmount = parseFloat(rawAmount);
      if (isNaN(numericAmount)) {
        return {
          raw: rawAmount,
          formatted: 'Invalid Amount',
          display: 'Invalid Amount',
          symbol: assetConfig.symbol,
        };
      }

      // Apply decimal precision
      const displayAmount = numericAmount / Math.pow(10, assetConfig.decimals);

      // Format with appropriate decimal places
      const formattedAmount = this.formatNumberWithPrecision(displayAmount);

      return {
        raw: rawAmount,
        numeric: displayAmount,
        formatted: formattedAmount,
        display: `${assetConfig.displaySymbol}${formattedAmount}`,
        symbol: assetConfig.symbol,
        decimals: assetConfig.decimals,
      };
    } catch (error) {
      return {
        raw: rawAmount,
        formatted: 'Format Error',
        display: 'Format Error',
        symbol: assetConfig.symbol,
      };
    }
  }

  /**
   * Format number with appropriate precision for display
   */
  private formatNumberWithPrecision(amount: number): string {
    // For amounts >= 1, show 2 decimal places
    if (amount >= 1) {
      return amount.toFixed(2);
    }

    // For amounts < 1, show up to 7 decimal places but remove trailing zeros
    if (amount > 0) {
      const formatted = amount.toFixed(7);
      return formatted.replace(/\.?0+$/, '');
    }

    // For zero or negative amounts
    return amount.toFixed(2);
  }

  /**
   * Generate Stellar Expert exploration links
   */
  private generateExplorerLinks(
    transactionHash: string,
    assetId?: string,
  ): any {
    const assetConfig = this.getAssetConfig(assetId);
    const baseUrl = assetConfig.stellarExpertUrl;

    return {
      transaction: `${baseUrl}/tx/${transactionHash}`,
      search: `${baseUrl}/search?term=${transactionHash}`,
      // Additional useful links
      network: baseUrl,
    };
  }

  /**
   * Get asset configuration for formatting
   */
  private getAssetConfig(assetId?: string): AssetConfig {
    if (!assetId) {
      return ASSET_CONFIGS.default;
    }

    return ASSET_CONFIGS[assetId] || ASSET_CONFIGS.default;
  }

  /**
   * Add new asset configuration (useful for dynamic asset support)
   */
  static addAssetConfig(assetId: string, config: AssetConfig): void {
    ASSET_CONFIGS[assetId] = config;
  }

  /**
   * Get all configured assets
   */
  static getConfiguredAssets(): Record<string, AssetConfig> {
    return { ...ASSET_CONFIGS };
  }
}

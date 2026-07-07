import { Injectable, Logger, Inject, Optional } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { firstValueFrom } from 'rxjs';
import axios, { AxiosError } from 'axios';
import { ConfigService } from '@nestjs/config';
import { TestModeService } from '../../common/test-mode/test-mode.service';

export interface PriceData {
  [symbol: string]: {
    usd: number;
  };
}

export interface OracleConfig {
  coingeckoApiUrl: string;
  cacheTtlMs: number;
  fallbackPrices: Record<string, number>;
}

@Injectable()
export class OracleService {
  private readonly logger = new Logger(OracleService.name);
  private readonly COINGECKO_API_URL = 'https://api.coingecko.com/api/v3';
  private readonly CACHE_TTL = 300000; // 5 minutes in milliseconds

  // Fallback prices in case API fails
  private readonly FALLBACK_PRICES: Record<string, number> = {
    stellar: 0.12, // XLM fallback price
    aqua: 0.25, // AQUA fallback price
    'usd-coin': 1.0, // USDC fallback
  };

  constructor(
    private readonly httpService: HttpService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly configService: ConfigService,
    @Optional() private readonly testModeService?: TestModeService,
  ) {}

  /**
   * Fetch current price of XLM from CoinGecko with caching
   * @returns XLM price in USD
   */
  async getXLMPrice(): Promise<number> {
    return this.getCachedPrice('stellar');
  }

  /**
   * Fetch current price of AQUA from CoinGecko with caching
   * @returns AQUA price in USD
   */
  async getAQUAPrice(): Promise<number> {
    return this.getCachedPrice('aqua');
  }

  /**
   * Fetch prices for multiple assets with caching
   * @param assetIds Array of CoinGecko asset IDs
   * @returns Object with asset prices
   */
  async getAssetPrices(assetIds: string[]): Promise<PriceData> {
    if (this.testModeService?.isEnabled) {
      const stubPrices: PriceData = {};
      for (const id of assetIds) {
        stubPrices[id] = { usd: this.FALLBACK_PRICES[id] ?? 1.0 };
      }
      return stubPrices;
    }

    const cacheKey = `prices:${assetIds.join(',')}`;

    // Try to get from cache first
    const cachedPrices = await this.cacheManager.get<PriceData>(cacheKey);
    if (cachedPrices) {
      this.logger.debug(`Cache hit for prices: ${assetIds.join(',')}`);
      return cachedPrices;
    }

    try {
      this.logger.debug(`Fetching fresh prices for: ${assetIds.join(',')}`);
      const response = await firstValueFrom(
        this.httpService.get<PriceData>(
          `${this.COINGECKO_API_URL}/simple/price`,
          {
            params: {
              ids: assetIds.join(','),
              vs_currencies: 'usd',
            },
          },
        ),
      );

      // Cache the response
      await this.cacheManager.set(cacheKey, response.data, this.CACHE_TTL);

      return response.data;
    } catch (error) {
      this.logger.error(
        `Failed to fetch prices for assets: ${(error as Error).message}`,
        error,
      );
      return {};
    }
  }

  /**
   * Convert asset amount to USD
   * @param amount Amount in asset units
   * @param assetId CoinGecko asset ID
   * @returns Amount in USD
   */
  async convertToUsd(amount: number, assetId: string): Promise<number> {
    const price = await this.getCachedPrice(assetId);
    return amount * price;
  }

  /**
   * Convert XLM amount to USD
   * @param xlmAmount Amount in XLM
   * @returns Amount in USD
   */
  async convertXLMToUsd(xlmAmount: number): Promise<number> {
    const price = await this.getXLMPrice();
    return xlmAmount * price;
  }

  /**
   * Convert AQUA amount to USD
   * @param aquaAmount Amount in AQUA
   * @returns Amount in USD
   */
  async convertAQUAToUsd(aquaAmount: number): Promise<number> {
    const price = await this.getAQUAPrice();
    return aquaAmount * price;
  }

  /**
   * Convert stroops (smallest XLM unit) to USD
   * @param stroops Amount in stroops
   * @returns Amount in USD
   */
  async convertStroopsToUsd(stroops: number): Promise<number> {
    const xlmPrice = await this.getXLMPrice();
    // 1 XLM = 10,000,000 stroops
    const xlmAmount = stroops / 10_000_000;
    return xlmAmount * xlmPrice;
  }

  /**
   * Get cached price for an asset or fetch fresh price if not cached
   * Uses both HttpService (NestJS axios) and direct axios for fallback
   * @param assetId CoinGecko asset ID
   * @returns Price in USD
   */
  private async getCachedPrice(assetId: string): Promise<number> {
    if (this.testModeService?.isEnabled) {
      return this.FALLBACK_PRICES[assetId] ?? 1.0;
    }

    const cacheKey = `price:${assetId}`;

    // Try to get from cache first
    const cachedPrice = await this.cacheManager.get<number>(cacheKey);
    if (cachedPrice !== undefined) {
      this.logger.debug(`Cache hit for price: ${assetId}`);
      return cachedPrice;
    }

    try {
      this.logger.debug(`Fetching fresh price for: ${assetId}`);

      // Try HttpService first (NestJS axios)
      let price: number | undefined;

      try {
        const response = await firstValueFrom(
          this.httpService.get<PriceData>(
            `${this.COINGECKO_API_URL}/simple/price`,
            {
              params: {
                ids: assetId,
                vs_currencies: 'usd',
              },
            },
          ),
        );
        price = response.data[assetId]?.usd;
      } catch (httpError) {
        this.logger.warn(
          `HttpService failed for ${assetId}, trying direct axios: ${(httpError as Error).message}`,
        );

        // Fallback to direct axios call
        try {
          const axiosResponse = await axios.get<PriceData>(
            `${this.COINGECKO_API_URL}/simple/price`,
            {
              params: {
                ids: assetId,
                vs_currencies: 'usd',
              },
              timeout: 5000,
            },
          );
          price = axiosResponse.data[assetId]?.usd;
        } catch (axiosError) {
          this.logger.error(
            `Direct axios also failed for ${assetId}: ${(axiosError as Error).message}`,
          );
        }
      }

      if (price === undefined) {
        // Use fallback price
        const fallbackPrice = this.FALLBACK_PRICES[assetId];
        if (fallbackPrice !== undefined) {
          this.logger.warn(
            `Using fallback price for ${assetId}: ${fallbackPrice}`,
          );
          return fallbackPrice;
        }
        this.logger.warn(`Price not found for asset: ${assetId}`);
        return 0;
      }

      // Cache the price
      await this.cacheManager.set(cacheKey, price, this.CACHE_TTL);

      return price;
    } catch (error) {
      this.logger.error(
        `Failed to fetch price for asset ${assetId}: ${(error as Error).message}`,
        error,
      );

      // Return fallback price if available
      const fallbackPrice = this.FALLBACK_PRICES[assetId];
      if (fallbackPrice !== undefined) {
        return fallbackPrice;
      }
      return 0;
    }
  }

  /**
   * Get all supported asset prices in a single batch call
   * Optimized for fetching multiple prices at once to reduce API calls
   * @returns Map of asset IDs to USD prices
   */
  async getAllPrices(): Promise<Map<string, number>> {
    const assetIds = ['stellar', 'aqua', 'usd-coin'];
    const prices = new Map<string, number>();

    for (const assetId of assetIds) {
      const price = await this.getCachedPrice(assetId);
      prices.set(assetId, price);
    }

    return prices;
  }
}

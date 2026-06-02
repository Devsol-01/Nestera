import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DEFAULT_BASE_CURRENCY,
  DEFAULT_CURRENCY_CONFIGS,
  normalizeCurrencyCode,
} from './currency.config';
import {
  CurrencyCode,
  CurrencyConfig,
  NormalizedCurrencyAmount,
} from './currency.types';

@Injectable()
export class CurrencyService {
  private readonly currencies: Record<CurrencyCode, CurrencyConfig>;

  constructor(private readonly configService: ConfigService) {
    this.currencies = this.loadCurrencyConfigs();
  }

  listSupportedCurrencies(): CurrencyConfig[] {
    return Object.values(this.currencies).filter(
      (currency) => currency.enabled,
    );
  }

  getConfig(code?: string | null): CurrencyConfig {
    let currencyCode: CurrencyCode;
    try {
      currencyCode = normalizeCurrencyCode(code);
    } catch {
      throw new BadRequestException(`Currency ${code} is not supported`);
    }

    const config = this.currencies[currencyCode];

    if (!config || !config.enabled) {
      throw new BadRequestException(
        `Currency ${currencyCode} is not supported`,
      );
    }

    return config;
  }

  resolveCurrencyFromAsset(input: {
    currencyCode?: string | null;
    assetCode?: string | null;
    assetContractId?: string | null;
  }): CurrencyConfig {
    if (input.currencyCode) {
      return this.getConfig(input.currencyCode);
    }

    const assetCode = input.assetCode?.toUpperCase();
    const assetContractId = input.assetContractId;
    const match = this.listSupportedCurrencies().find(
      (currency) =>
        currency.stellarAssetCode.toUpperCase() === assetCode ||
        (assetContractId && currency.contractId === assetContractId),
    );

    return match || this.getConfig(DEFAULT_BASE_CURRENCY);
  }

  validateAmount(amount: string | number, code?: string | null): void {
    const config = this.getConfig(code);
    const raw = String(amount);
    const numeric = Number(raw);

    if (!Number.isFinite(numeric) || numeric <= 0) {
      throw new BadRequestException(
        `${config.code} amount must be a positive number`,
      );
    }

    const decimalPart = raw.split('.')[1] || '';
    if (decimalPart.length > config.validation.maxDecimalPlaces) {
      throw new BadRequestException(
        `${config.code} amount must have at most ${config.validation.maxDecimalPlaces} decimal places`,
      );
    }

    if (numeric < Number(config.validation.minAmount)) {
      throw new BadRequestException(
        `${config.code} amount must be at least ${config.validation.minAmount}`,
      );
    }
  }

  normalizeAmount(
    amount: string | number,
    code?: string | null,
  ): NormalizedCurrencyAmount {
    const config = this.getConfig(code);
    this.validateAmount(amount, config.code);

    const amountString = String(amount);
    const conversionRate = Number(config.conversion.rateToBase);
    const amountBaseCurrency = Number(amountString) * conversionRate;

    return {
      amount: amountString,
      currencyCode: config.code,
      amountBaseCurrency: amountBaseCurrency.toFixed(config.decimals),
      conversionRateToBase: config.conversion.rateToBase,
    };
  }

  convert(
    amount: string | number,
    fromCurrency: string,
    toCurrency = DEFAULT_BASE_CURRENCY,
  ): string {
    const from = this.getConfig(fromCurrency);
    const to = this.getConfig(toCurrency);
    this.validateAmount(amount, from.code);

    const amountInBase = Number(amount) * Number(from.conversion.rateToBase);
    const converted = amountInBase / Number(to.conversion.rateToBase);

    return converted.toFixed(to.decimals);
  }

  formatAmount(amount: string | number, code?: string | null) {
    const config = this.getConfig(code);
    const rawAmount = typeof amount === 'string' ? amount : amount.toString();
    const numericAmount = Number(rawAmount);

    if (!Number.isFinite(numericAmount)) {
      return {
        raw: rawAmount,
        formatted: 'Invalid Amount',
        display: 'Invalid Amount',
        symbol: config.stellarAssetCode,
        decimals: config.decimals,
      };
    }

    const formatted = this.formatNumber(numericAmount, config.decimals);
    return {
      raw: rawAmount,
      numeric: numericAmount,
      formatted,
      display:
        config.symbol === '$' || config.symbol === 'EUR'
          ? `${config.symbol}${formatted}`
          : `${formatted} ${config.symbol}`,
      symbol: config.stellarAssetCode,
      decimals: config.decimals,
      currencyCode: config.code,
    };
  }

  private formatNumber(amount: number, decimals: number): string {
    if (amount >= 1) return amount.toFixed(2);
    if (amount > 0) return amount.toFixed(decimals).replace(/\.?0+$/, '');
    return amount.toFixed(2);
  }

  private loadCurrencyConfigs(): Record<CurrencyCode, CurrencyConfig> {
    const configured = this.configService.get<string>('currency.configJson');
    if (!configured) return DEFAULT_CURRENCY_CONFIGS;

    try {
      const parsed = JSON.parse(configured) as Partial<
        Record<CurrencyCode, Partial<CurrencyConfig>>
      >;

      return Object.entries(DEFAULT_CURRENCY_CONFIGS).reduce(
        (acc, [code, defaults]) => ({
          ...acc,
          [code]: {
            ...defaults,
            ...(parsed[code as CurrencyCode] || {}),
            validation: {
              ...defaults.validation,
              ...(parsed[code as CurrencyCode]?.validation || {}),
            },
            conversion: {
              ...defaults.conversion,
              ...(parsed[code as CurrencyCode]?.conversion || {}),
            },
          },
        }),
        {} as Record<CurrencyCode, CurrencyConfig>,
      );
    } catch {
      return DEFAULT_CURRENCY_CONFIGS;
    }
  }
}

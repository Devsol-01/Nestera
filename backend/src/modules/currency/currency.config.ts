import { CurrencyCode, CurrencyConfig } from './currency.types';

export const DEFAULT_BASE_CURRENCY = CurrencyCode.USDC;

export const DEFAULT_CURRENCY_CONFIGS: Record<CurrencyCode, CurrencyConfig> = {
  [CurrencyCode.USDC]: {
    code: CurrencyCode.USDC,
    displayName: 'USD Coin',
    symbol: '$',
    decimals: 7,
    type: 'stablecoin',
    stellarAssetCode: 'USDC',
    issuer: null,
    contractId: 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA',
    enabled: true,
    validation: {
      minAmount: '0.0000001',
      maxDecimalPlaces: 7,
    },
    conversion: {
      baseCurrency: CurrencyCode.USDC,
      rateToBase: '1',
    },
  },
  [CurrencyCode.USDT]: {
    code: CurrencyCode.USDT,
    displayName: 'Tether USD',
    symbol: 'USDT',
    decimals: 7,
    type: 'stablecoin',
    stellarAssetCode: 'USDT',
    issuer: null,
    contractId: null,
    enabled: true,
    validation: {
      minAmount: '0.0000001',
      maxDecimalPlaces: 7,
    },
    conversion: {
      baseCurrency: CurrencyCode.USDC,
      rateToBase: '1',
    },
  },
  [CurrencyCode.XLM]: {
    code: CurrencyCode.XLM,
    displayName: 'Stellar Lumens',
    symbol: 'XLM',
    decimals: 7,
    type: 'native',
    stellarAssetCode: 'XLM',
    issuer: null,
    contractId: null,
    enabled: true,
    validation: {
      minAmount: '0.0000001',
      maxDecimalPlaces: 7,
    },
    conversion: {
      baseCurrency: CurrencyCode.USDC,
      rateToBase: '0.10',
    },
  },
  [CurrencyCode.EURC]: {
    code: CurrencyCode.EURC,
    displayName: 'EUR Stablecoin',
    symbol: 'EUR',
    decimals: 7,
    type: 'stablecoin',
    stellarAssetCode: 'EURC',
    issuer: null,
    contractId: null,
    enabled: true,
    validation: {
      minAmount: '0.0000001',
      maxDecimalPlaces: 7,
    },
    conversion: {
      baseCurrency: CurrencyCode.USDC,
      rateToBase: '1.08',
    },
  },
};

export function normalizeCurrencyCode(value?: string | null): CurrencyCode {
  const normalized = (value || DEFAULT_BASE_CURRENCY).trim().toUpperCase();

  if (Object.values(CurrencyCode).includes(normalized as CurrencyCode)) {
    return normalized as CurrencyCode;
  }

  throw new Error(`Unsupported currency code: ${normalized}`);
}

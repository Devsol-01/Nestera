export enum CurrencyCode {
  USDC = 'USDC',
  USDT = 'USDT',
  XLM = 'XLM',
  EURC = 'EURC',
}

export interface CurrencyConfig {
  code: CurrencyCode;
  displayName: string;
  symbol: string;
  decimals: number;
  type: 'native' | 'stablecoin';
  stellarAssetCode: string;
  issuer?: string | null;
  contractId?: string | null;
  enabled: boolean;
  validation: {
    minAmount: string;
    maxDecimalPlaces: number;
  };
  conversion: {
    baseCurrency: CurrencyCode;
    rateToBase: string;
  };
}

export interface NormalizedCurrencyAmount {
  amount: string;
  currencyCode: CurrencyCode;
  amountBaseCurrency: string;
  conversionRateToBase: string;
}

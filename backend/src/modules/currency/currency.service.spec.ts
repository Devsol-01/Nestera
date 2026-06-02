import { ConfigService } from '@nestjs/config';
import { CurrencyService } from './currency.service';
import { CurrencyCode } from './currency.types';

describe('CurrencyService', () => {
  let service: CurrencyService;

  beforeEach(() => {
    service = new CurrencyService({
      get: jest.fn().mockReturnValue(undefined),
    } as unknown as ConfigService);
  });

  it('lists configured multi-currency support', () => {
    const codes = service.listSupportedCurrencies().map((item) => item.code);

    expect(codes).toEqual(
      expect.arrayContaining([
        CurrencyCode.USDC,
        CurrencyCode.USDT,
        CurrencyCode.XLM,
        CurrencyCode.EURC,
      ]),
    );
  });

  it('validates currency-specific decimal precision', () => {
    expect(() =>
      service.validateAmount('1.12345678', CurrencyCode.USDC),
    ).toThrow('USDC amount must have at most 7 decimal places');
  });

  it('rejects unsupported currencies', () => {
    expect(() => service.getConfig('BTC')).toThrow(
      'Currency BTC is not supported',
    );
  });

  it('converts configured currencies to the base currency', () => {
    expect(service.convert('10', CurrencyCode.XLM, CurrencyCode.USDC)).toBe(
      '1.0000000',
    );
  });
});

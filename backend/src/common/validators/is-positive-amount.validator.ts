import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';
import {
  DEFAULT_CURRENCY_CONFIGS,
  normalizeCurrencyCode,
} from '../../modules/currency/currency.config';

export function IsPositiveAmount(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isPositiveAmount',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown): boolean {
          const num =
            typeof value === 'string' ? parseFloat(value) : Number(value);
          return isFinite(num) && num > 0;
        },
        defaultMessage(args: ValidationArguments): string {
          return `${args.property} must be a positive number`;
        },
      },
    });
  };
}

export function IsUSDCAmount(validationOptions?: ValidationOptions) {
  return IsCurrencyAmount(undefined, validationOptions);
}

export function IsCurrencyAmount(
  currencyProperty = 'currencyCode',
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isCurrencyAmount',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown, args: ValidationArguments): boolean {
          const objectWithCurrency = args.object as Record<string, unknown>;
          let currencyCode: keyof typeof DEFAULT_CURRENCY_CONFIGS;
          try {
            currencyCode = normalizeCurrencyCode(
              String(objectWithCurrency[currencyProperty] || 'USDC'),
            );
          } catch {
            return false;
          }

          const config = DEFAULT_CURRENCY_CONFIGS[currencyCode];
          const num =
            typeof value === 'string' ? parseFloat(value) : Number(value);
          if (!isFinite(num) || num <= 0) return false;
          const strVal = String(value);
          const decimalPart = strVal.split('.')[1] || '';
          return decimalPart.length <= config.validation.maxDecimalPlaces;
        },
        defaultMessage(args: ValidationArguments): string {
          const objectWithCurrency = args.object as Record<string, unknown>;
          let currencyCode: keyof typeof DEFAULT_CURRENCY_CONFIGS;
          try {
            currencyCode = normalizeCurrencyCode(
              String(objectWithCurrency[currencyProperty] || 'USDC'),
            );
          } catch {
            return `${args.property} must use a supported currency code`;
          }

          const config = DEFAULT_CURRENCY_CONFIGS[currencyCode];
          return `${args.property} must be a positive ${currencyCode} amount with at most ${config.validation.maxDecimalPlaces} decimal places`;
        },
      },
    });
  };
}

export function IsNonNegativeAmount(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isNonNegativeAmount',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown): boolean {
          const num =
            typeof value === 'string' ? parseFloat(value) : Number(value);
          return isFinite(num) && num >= 0;
        },
        defaultMessage(args: ValidationArguments): string {
          return `${args.property} must be a non-negative number`;
        },
      },
    });
  };
}

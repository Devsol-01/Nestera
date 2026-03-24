import { registerDecorator, ValidationOptions, ValidationArguments } from 'class-validator';

export function IsICD10Code(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isICD10Code',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any) {
          if (!Array.isArray(value)) return false;
          const icd10Pattern = /^[A-Z]\d{2}(\.\d{1,4})?$/;
          return value.every(code => typeof code === 'string' && icd10Pattern.test(code));
        },
        defaultMessage(args: ValidationArguments) {
          return 'Each diagnosis code must be a valid ICD-10 format (e.g., A00, B12.3)';
        },
      },
    });
  };
}

export function IsPositiveAmount(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isPositiveAmount',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any) {
          return typeof value === 'number' && value > 0 && value <= 1000000;
        },
        defaultMessage(args: ValidationArguments) {
          return 'Claim amount must be a positive number not exceeding 1,000,000';
        },
      },
    });
  };
}

export function IsValidHospitalId(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidHospitalId',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any) {
          return typeof value === 'string' && /^HOSP-[A-Z0-9]{6,12}$/.test(value);
        },
        defaultMessage(args: ValidationArguments) {
          return 'Hospital ID must follow format HOSP-XXXXXX';
        },
      },
    });
  };
}

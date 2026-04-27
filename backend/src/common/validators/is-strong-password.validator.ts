import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';

/**
 * Password complexity rules enforced by this validator:
 *  - At least 8 characters long
 *  - At least one uppercase letter  (A-Z)
 *  - At least one lowercase letter  (a-z)
 *  - At least one digit             (0-9)
 *  - At least one special character (!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~)
 *
 * These rules protect against dictionary attacks and brute-force attempts by
 * significantly increasing the search space for any given password length.
 */
const PASSWORD_RULES = {
  minLength: 8,
  uppercase: /[A-Z]/,
  lowercase: /[a-z]/,
  digit: /[0-9]/,
  special: /[!@#$%^&*()\-_=+[\]{};:'",.<>?/\\|`~]/,
} as const;

/**
 * Returns a human-readable explanation of every rule the supplied password
 * violates.  An empty array means the password is valid.
 */
export function getPasswordErrors(value: unknown): string[] {
  if (typeof value !== 'string') {
    return ['Password must be a string'];
  }

  const errors: string[] = [];

  if (value.length < PASSWORD_RULES.minLength) {
    errors.push(`at least ${PASSWORD_RULES.minLength} characters`);
  }
  if (!PASSWORD_RULES.uppercase.test(value)) {
    errors.push('at least one uppercase letter (A-Z)');
  }
  if (!PASSWORD_RULES.lowercase.test(value)) {
    errors.push('at least one lowercase letter (a-z)');
  }
  if (!PASSWORD_RULES.digit.test(value)) {
    errors.push('at least one digit (0-9)');
  }
  if (!PASSWORD_RULES.special.test(value)) {
    errors.push('at least one special character (!@#$%^&*…)');
  }

  return errors;
}

/**
 * Custom class-validator decorator that enforces strong password complexity.
 *
 * Usage:
 * ```ts
 * @IsStrongPassword()
 * password: string;
 * ```
 *
 * @param validationOptions  Standard class-validator options (message, groups…)
 */
export function IsStrongPassword(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isStrongPassword',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown): boolean {
          return getPasswordErrors(value).length === 0;
        },

        defaultMessage(args: ValidationArguments): string {
          const violations = getPasswordErrors(args.value);
          return (
            `${args.property} is too weak. It must contain ` +
            violations.join(', ') +
            '.'
          );
        },
      },
    });
  };
}

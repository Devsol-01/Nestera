export interface ValidationIssue {
  field: string;
  constraints: Record<string, string>;
  value?: unknown;
}

export interface ClassValidatorErrorLike {
  property: string;
  value?: unknown;
  constraints?: Record<string, string>;
  children?: ClassValidatorErrorLike[];
}

export function flattenValidationErrors(
  errors: ClassValidatorErrorLike[],
  parentPath = '',
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const error of errors) {
    const fieldPath = parentPath
      ? `${parentPath}.${error.property}`
      : error.property;

    if (error.constraints && Object.keys(error.constraints).length > 0) {
      issues.push({
        field: fieldPath,
        value: error.value,
        constraints: error.constraints,
      });
    }

    if (error.children?.length) {
      issues.push(...flattenValidationErrors(error.children, fieldPath));
    }
  }

  return issues;
}

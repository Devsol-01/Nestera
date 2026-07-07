import {
  DistributedTracingService,
  Span,
  TraceContext,
} from '../../modules/apm/distributed-tracing.service';

/**
 * TraceSpan — method decorator that wraps a domain service method in a
 * distributed tracing span when the host instance has a `tracingService`
 * property that is a `DistributedTracingService`.
 *
 * Usage:
 *   @TraceSpan()                         // span name = ClassName.methodName
 *   @TraceSpan('governance.castVote')    // explicit span name
 *
 * The decorator is a no-op when no `tracingService` is present on the
 * instance (e.g. in unit tests that don't inject APM).
 */
export function TraceSpan(operationName?: string): MethodDecorator {
  return (
    target: object,
    propertyKey: string | symbol,
    descriptor: TypedPropertyDescriptor<unknown>,
  ) => {
    const original = descriptor.value;

    if (typeof original !== 'function') {
      return descriptor;
    }

    const resolvedName =
      operationName ??
      `${target.constructor.name}.${String(propertyKey)}`;

    const wrapped = async function (
      this: Record<string, unknown>,
      ...args: unknown[]
    ) {
      const tracer = this['tracingService'] as
        | DistributedTracingService
        | undefined;

      if (!tracer) {
        // APM not wired — execute without instrumentation
        return (original as (...a: unknown[]) => unknown).apply(this, args);
      }

      // Inherit trace context from the request if available; otherwise start
      // a new root trace (e.g. background cron jobs).
      const parentCtx = (this['_activeTraceContext'] as TraceContext | undefined) ?? undefined;
      const spanCtx = tracer.createTraceContext(parentCtx);

      const span: Span = tracer.startSpan(resolvedName, spanCtx, {
        'service.layer': 'domain',
        'code.function': String(propertyKey),
        'code.class': target.constructor.name,
      });

      try {
        const result = await Promise.resolve(
          (original as (...a: unknown[]) => unknown).apply(this, args),
        );
        tracer.finishSpan(span);
        return result;
      } catch (err) {
        tracer.finishSpan(span, err instanceof Error ? err : new Error(String(err)));
        throw err;
      }
    };

    descriptor.value = wrapped as typeof descriptor.value;
    return descriptor;
  };
}

import { TraceSpan } from './trace-span.decorator';
import {
  DistributedTracingService,
  Span,
  TraceContext,
} from '../../modules/apm/distributed-tracing.service';

// ---------------------------------------------------------------------------
// Minimal stub for DistributedTracingService
// ---------------------------------------------------------------------------
function makeTracerStub(): jest.Mocked<
  Pick<
    DistributedTracingService,
    'createTraceContext' | 'startSpan' | 'finishSpan'
  >
> {
  const fakeCtx: TraceContext = {
    traceId: 'trace-abc',
    spanId: 'span-001',
    sampled: true,
    baggage: {},
  };
  const fakeSpan: Span = {
    traceId: 'trace-abc',
    spanId: 'span-001',
    operationName: 'test',
    startTime: Date.now(),
    tags: {},
    logs: [],
    status: 'active',
  };

  return {
    createTraceContext: jest.fn().mockReturnValue(fakeCtx),
    startSpan: jest.fn().mockReturnValue(fakeSpan),
    finishSpan: jest.fn(),
  };
}

// ---------------------------------------------------------------------------
// Helper: build a class whose method is decorated, with optional tracing
// ---------------------------------------------------------------------------
function buildService(withTracer: boolean) {
  const tracer = withTracer ? makeTracerStub() : undefined;

  class TestService {
    tracingService = tracer;

    @TraceSpan()
    async doWork(value: number): Promise<number> {
      return value * 2;
    }

    @TraceSpan('explicit.operation')
    async doNamedWork(): Promise<string> {
      return 'result';
    }

    @TraceSpan()
    async doThrow(): Promise<never> {
      throw new Error('boom');
    }
  }

  return { service: new TestService(), tracer };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('TraceSpan decorator', () => {
  describe('when tracingService is injected', () => {
    it('calls startSpan and finishSpan on success', async () => {
      const { service, tracer } = buildService(true);

      const result = await service.doWork(5);

      expect(result).toBe(10);
      expect(tracer!.createTraceContext).toHaveBeenCalledTimes(1);
      expect(tracer!.startSpan).toHaveBeenCalledWith(
        'TestService.doWork',
        expect.any(Object),
        expect.objectContaining({
          'service.layer': 'domain',
          'code.function': 'doWork',
          'code.class': 'TestService',
        }),
      );
      expect(tracer!.finishSpan).toHaveBeenCalledWith(
        expect.objectContaining({ operationName: 'test' }),
      );
    });

    it('uses the explicit operation name when provided', async () => {
      const { service, tracer } = buildService(true);

      await service.doNamedWork();

      expect(tracer!.startSpan).toHaveBeenCalledWith(
        'explicit.operation',
        expect.any(Object),
        expect.any(Object),
      );
    });

    it('calls finishSpan with the error on rejection, then re-throws', async () => {
      const { service, tracer } = buildService(true);

      await expect(service.doThrow()).rejects.toThrow('boom');

      expect(tracer!.finishSpan).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ message: 'boom' }),
      );
    });
  });

  describe('when tracingService is NOT injected (APM disabled)', () => {
    it('still executes the method and returns the value', async () => {
      const { service, tracer } = buildService(false);

      const result = await service.doWork(7);

      expect(result).toBe(14);
      expect(tracer).toBeUndefined();
    });

    it('still propagates errors', async () => {
      const { service } = buildService(false);

      await expect(service.doThrow()).rejects.toThrow('boom');
    });
  });
});

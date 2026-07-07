import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CircuitBreaker, CircuitBreakerState } from './circuit-breaker.config';
import { TestModeService } from '../test-mode/test-mode.service';

export interface DependencyConfig {
  name: string;
  timeoutMs: number;
  maxRetries: number;
  retryDelayMs: number;
  failureThreshold?: number;
  recoveryTimeoutMs?: number;
}

export interface DependencyCallMetrics {
  dependency: string;
  duration: number;
  success: boolean;
  error?: string;
  timestamp: Date;
  circuitState: CircuitBreakerState;
}

const DEFAULT_DEPENDENCIES: Record<string, Omit<DependencyConfig, 'name'>> = {
  'stellar-rpc': {
    timeoutMs: 10000,
    maxRetries: 3,
    retryDelayMs: 1000,
  },
  'stellar-horizon': {
    timeoutMs: 15000,
    maxRetries: 3,
    retryDelayMs: 1000,
  },
  email: {
    timeoutMs: 10000,
    maxRetries: 2,
    retryDelayMs: 2000,
  },
  kyc: {
    timeoutMs: 15000,
    maxRetries: 2,
    retryDelayMs: 3000,
  },
  storage: {
    timeoutMs: 30000,
    maxRetries: 2,
    retryDelayMs: 2000,
  },
};

@Injectable()
export class ExternalCallService {
  private readonly logger = new Logger(ExternalCallService.name);
  private readonly breakers = new Map<string, CircuitBreaker>();
  private readonly metricsBuffer: DependencyCallMetrics[] = [];
  private readonly MAX_METRICS = 500;

  constructor(
    private readonly configService: ConfigService,
    private readonly eventEmitter: EventEmitter2,
    @Optional() private readonly testModeService?: TestModeService,
  ) {
    for (const [name, defaults] of Object.entries(DEFAULT_DEPENDENCIES)) {
      this.getOrCreateBreaker(name, defaults);
    }
  }

  async execute<T>(
    dependencyName: string,
    fn: () => Promise<T>,
    opts?: Partial<DependencyConfig>,
  ): Promise<T> {
    if (this.testModeService?.isEnabled) {
      const stub = this.testModeService.getStub<T>(dependencyName);
      if (stub !== undefined) {
        this.logger.debug(`[TestMode] Returning stub for ${dependencyName}`);
        return stub;
      }
    }
    const config = this.resolveConfig(dependencyName, opts);
    const breaker = this.getOrCreateBreaker(dependencyName, config);

    const start = Date.now();
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
      try {
        const result = await breaker.execute(() =>
          this.withTimeout(fn(), config.timeoutMs),
        );

        this.recordMetrics(dependencyName, Date.now() - start, true, breaker);
        return result;
      } catch (error) {
        lastError = error as Error;

        this.logger.warn(
          `[${dependencyName}] Attempt ${attempt + 1}/${config.maxRetries + 1} failed: ${lastError.message}`,
        );

        if (attempt < config.maxRetries) {
          const delay = config.retryDelayMs * Math.pow(2, attempt);
          await this.sleep(delay);
        }
      }
    }

    this.recordMetrics(
      dependencyName,
      Date.now() - start,
      false,
      breaker,
      lastError?.message,
    );

    throw lastError!;
  }

  async executeWithFallback<T>(
    dependencyName: string,
    fn: () => Promise<T>,
    fallback: () => T | Promise<T>,
    opts?: Partial<DependencyConfig>,
  ): Promise<T> {
    if (this.testModeService?.isEnabled) {
      const stub = this.testModeService.getStub<T>(dependencyName);
      if (stub !== undefined) {
        this.logger.debug(`[TestMode] Returning stub for ${dependencyName}`);
        return stub;
      }
    }
    try {
      return await this.execute(dependencyName, fn, opts);
    } catch (error) {
      this.logger.warn(
        `[${dependencyName}] All attempts failed, using fallback: ${(error as Error).message}`,
      );
      return fallback();
    }
  }

  getMetrics(dependencyName?: string): DependencyCallMetrics[] {
    if (dependencyName) {
      return this.metricsBuffer.filter((m) => m.dependency === dependencyName);
    }
    return [...this.metricsBuffer];
  }

  getDependencyHealth(): Record<
    string,
    {
      state: CircuitBreakerState;
      failureRate: number;
      totalRequests: number;
      avgLatencyMs: number;
    }
  > {
    const health: Record<string, any> = {};

    for (const [name, breaker] of this.breakers) {
      const metrics = breaker.getMetrics();
      const depMetrics = this.metricsBuffer.filter(
        (m) => m.dependency === name,
      );
      const avgLatency =
        depMetrics.length > 0
          ? depMetrics.reduce((sum, m) => sum + m.duration, 0) /
            depMetrics.length
          : 0;

      health[name] = {
        state: metrics.state,
        failureRate: metrics.failureRate,
        totalRequests: metrics.totalRequests,
        avgLatencyMs: Math.round(avgLatency),
      };
    }

    return health;
  }

  private resolveConfig(
    name: string,
    opts?: Partial<DependencyConfig>,
  ): Omit<DependencyConfig, 'name'> {
    const defaults = DEFAULT_DEPENDENCIES[name] || {
      timeoutMs: 10000,
      maxRetries: 2,
      retryDelayMs: 1000,
    };

    return { ...defaults, ...opts };
  }

  private getOrCreateBreaker(
    name: string,
    config: Omit<DependencyConfig, 'name'>,
  ): CircuitBreaker {
    if (!this.breakers.has(name)) {
      this.breakers.set(name, new CircuitBreaker(this.configService, name));
    }
    return this.breakers.get(name)!;
  }

  private recordMetrics(
    dependency: string,
    duration: number,
    success: boolean,
    breaker: CircuitBreaker,
    error?: string,
  ) {
    const metric: DependencyCallMetrics = {
      dependency,
      duration,
      success,
      error,
      timestamp: new Date(),
      circuitState: breaker.getState(),
    };

    if (this.metricsBuffer.length >= this.MAX_METRICS) {
      this.metricsBuffer.shift();
    }
    this.metricsBuffer.push(metric);

    this.eventEmitter.emit('dependency.call', metric);

    if (!success) {
      this.logger.error(
        `[${dependency}] Call failed after ${duration}ms: ${error}`,
      );
    } else if (duration > 5000) {
      this.logger.warn(`[${dependency}] Slow call detected: ${duration}ms`);
    }
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(
          () =>
            reject(new Error(`External call timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

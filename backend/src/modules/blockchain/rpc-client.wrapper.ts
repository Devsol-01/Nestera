import { Logger } from '@nestjs/common';
import { Horizon, rpc } from '@stellar/stellar-sdk';

export interface RpcEndpoint {
  url: string;
  priority: number;
  type: 'rpc' | 'horizon';
}

export interface RetryConfig {
  maxRetries: number;
  retryDelay: number;
  timeoutMs: number;
}

export class RpcClientWrapper {
  private readonly logger = new Logger(RpcClientWrapper.name);
  private currentRpcIndex = 0;
  private currentHorizonIndex = 0;

  constructor(
    private readonly rpcEndpoints: RpcEndpoint[],
    private readonly horizonEndpoints: RpcEndpoint[],
    private readonly retryConfig: RetryConfig = {
      maxRetries: 3,
      retryDelay: 1000,
      timeoutMs: 10000,
    },
  ) {
    // Sort endpoints by priority (lower number = higher priority)
    this.rpcEndpoints.sort((a, b) => a.priority - b.priority);
    this.horizonEndpoints.sort((a, b) => a.priority - b.priority);

    this.logger.log(
      `Initialized RPC wrapper with ${rpcEndpoints.length} RPC endpoints and ${horizonEndpoints.length} Horizon endpoints`,
    );
  }

  /**
   * Execute a function with automatic retry and failover logic
   */
  async executeWithRetry<T>(
    operation: (client: rpc.Server | Horizon.Server) => Promise<T>,
    clientType: 'rpc' | 'horizon' = 'rpc',
  ): Promise<T> {
    const endpoints =
      clientType === 'rpc' ? this.rpcEndpoints : this.horizonEndpoints;
    const currentIndex =
      clientType === 'rpc' ? this.currentRpcIndex : this.currentHorizonIndex;

    if (endpoints.length === 0) {
      throw new Error(`No ${clientType} endpoints configured`);
    }

    let lastError: Error | null = null;
    let attemptCount = 0;

    // Try each endpoint in order
    for (let i = 0; i < endpoints.length; i++) {
      const endpointIndex = (currentIndex + i) % endpoints.length;
      const endpoint = endpoints[endpointIndex];

      // Retry each endpoint up to maxRetries times
      for (let retry = 0; retry < this.retryConfig.maxRetries; retry++) {
        attemptCount++;

        try {
          this.logger.debug(
            `Attempting ${clientType} request on ${endpoint.url} (attempt ${attemptCount})`,
          );

          const client =
            clientType === 'rpc'
              ? new rpc.Server(endpoint.url)
              : new Horizon.Server(endpoint.url);

          const result = await this.withTimeout(
            operation(client),
            this.retryConfig.timeoutMs,
          );

          // Success - update current index for next call
          if (clientType === 'rpc') {
            this.currentRpcIndex = endpointIndex;
          } else {
            this.currentHorizonIndex = endpointIndex;
          }

          // Log if we had to failover
          if (i > 0 || retry > 0) {
            this.logger.warn(
              `Successfully failed over to ${clientType} endpoint: ${endpoint.url} after ${attemptCount} attempts`,
            );
          }

          return result;
        } catch (error) {
          lastError = error as Error;

          this.logger.warn(
            `${clientType.toUpperCase()} request failed on ${endpoint.url} (attempt ${retry + 1}/${this.retryConfig.maxRetries}): ${lastError.message}`,
          );

          // Wait before retrying (exponential backoff)
          if (retry < this.retryConfig.maxRetries - 1) {
            const delay = this.retryConfig.retryDelay * Math.pow(2, retry);
            await this.sleep(delay);
          }
        }
      }

      // Log severe failover event when moving to next endpoint
      this.logger.error(
        `CRITICAL: All retries exhausted for ${clientType} endpoint ${endpoint.url}. Moving to next endpoint.`,
      );
    }

    // All endpoints and retries exhausted
    this.logger.error(
      `CRITICAL: All ${clientType} endpoints failed after ${attemptCount} total attempts. System may be experiencing network issues.`,
    );

    throw new Error(
      `All ${clientType} RPC endpoints failed: ${lastError?.message || 'Unknown error'}`,
    );
  }

  /**
   * Get current active RPC server instance
   */
  getCurrentRpcServer(): rpc.Server {
    if (this.rpcEndpoints.length === 0) {
      throw new Error('No RPC endpoints configured');
    }
    return new rpc.Server(this.rpcEndpoints[this.currentRpcIndex].url);
  }

  /**
   * Get current active Horizon server instance
   */
  getCurrentHorizonServer(): Horizon.Server {
    if (this.horizonEndpoints.length === 0) {
      throw new Error('No Horizon endpoints configured');
    }
    return new Horizon.Server(this.horizonEndpoints[this.currentHorizonIndex].url);
  }

  /**
   * Get all configured endpoints for monitoring/debugging
   */
  getEndpointsStatus() {
    return {
      rpc: {
        endpoints: this.rpcEndpoints,
        currentIndex: this.currentRpcIndex,
        currentUrl: this.rpcEndpoints[this.currentRpcIndex]?.url,
      },
      horizon: {
        endpoints: this.horizonEndpoints,
        currentIndex: this.currentHorizonIndex,
        currentUrl: this.horizonEndpoints[this.currentHorizonIndex]?.url,
      },
    };
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Request timeout after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

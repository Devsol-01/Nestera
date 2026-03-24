# RPC Fallback & Retry - Usage Examples

## Quick Start

### 1. Configure Environment Variables

```bash
# .env file
STELLAR_NETWORK=testnet
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
HORIZON_URL=https://horizon-testnet.stellar.org

# Add fallback endpoints
SOROBAN_RPC_FALLBACK_URLS=https://rpc-backup1.stellar.org,https://rpc-backup2.stellar.org
HORIZON_FALLBACK_URLS=https://horizon-backup1.stellar.org

# Configure retry behavior
RPC_MAX_RETRIES=3
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=10000
```

### 2. Use Stellar Service (Automatic Retry)

All existing Stellar service methods automatically use retry and failover:

```typescript
import { StellarService } from './stellar.service';

// Inject the service
constructor(private stellarService: StellarService) {}

// All methods automatically retry on failure
async getTransactions() {
  // Automatically retries with fallback endpoints
  const transactions = await this.stellarService.getRecentTransactions(
    'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN'
  );
  return transactions;
}

async checkHealth() {
  // Automatically retries with fallback endpoints
  const health = await this.stellarService.getHealth();
  return health;
}
```

### 3. Monitor RPC Status

```typescript
// Get current endpoint status
const status = this.stellarService.getEndpointsStatus();
console.log('Current RPC endpoint:', status.rpc.currentUrl);
console.log('Current Horizon endpoint:', status.horizon.currentUrl);
```

## API Examples

### Check RPC Status via HTTP

```bash
# Get status of all configured endpoints
curl http://localhost:3001/blockchain/rpc/status
```

Response:
```json
{
  "rpc": {
    "endpoints": [
      {
        "url": "https://soroban-testnet.stellar.org",
        "priority": 0,
        "type": "rpc"
      },
      {
        "url": "https://rpc-backup1.stellar.org",
        "priority": 1,
        "type": "rpc"
      }
    ],
    "currentIndex": 0,
    "currentUrl": "https://soroban-testnet.stellar.org"
  },
  "horizon": {
    "endpoints": [
      {
        "url": "https://horizon-testnet.stellar.org",
        "priority": 0,
        "type": "horizon"
      }
    ],
    "currentIndex": 0,
    "currentUrl": "https://horizon-testnet.stellar.org"
  }
}
```

### Get Wallet Transactions (with automatic retry)

```bash
curl http://localhost:3001/blockchain/wallets/GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN/transactions
```

If the primary Horizon endpoint fails, the request automatically retries with fallback endpoints.

## Adding Custom Methods with Retry

When adding new methods to `StellarService`, wrap RPC/Horizon operations with `executeWithRetry`:

```typescript
// In stellar.service.ts

async getAccountBalance(publicKey: string): Promise<string> {
  return await this.rpcClient.executeWithRetry(
    async (client) => {
      const horizonServer = client as Horizon.Server;
      const account = await horizonServer.loadAccount(publicKey);
      
      // Find XLM balance
      const xlmBalance = account.balances.find(
        (balance) => balance.asset_type === 'native'
      );
      
      return xlmBalance?.balance || '0';
    },
    'horizon', // Specify 'rpc' or 'horizon'
  );
}

async submitTransaction(transaction: Transaction): Promise<any> {
  return await this.rpcClient.executeWithRetry(
    async (client) => {
      const rpcServer = client as rpc.Server;
      return await rpcServer.sendTransaction(transaction);
    },
    'rpc',
  );
}
```

## Testing Failover Behavior

### Simulate Primary Endpoint Failure

```typescript
// Test by temporarily using an invalid primary endpoint
// .env.test
SOROBAN_RPC_URL=https://invalid-endpoint.stellar.org
SOROBAN_RPC_FALLBACK_URLS=https://soroban-testnet.stellar.org

// The system will automatically failover to the backup
```

### Monitor Logs

```bash
# Watch logs for failover events
npm run start:dev

# Look for these log patterns:
# [StellarService] RPC request failed on https://invalid-endpoint.stellar.org (attempt 1/3): Network error
# [StellarService] Successfully failed over to rpc endpoint: https://soroban-testnet.stellar.org after 4 attempts
```

## Error Handling

### Graceful Degradation

```typescript
async getTransactionsWithFallback(publicKey: string) {
  try {
    // Attempt to get transactions with automatic retry
    return await this.stellarService.getRecentTransactions(publicKey);
  } catch (error) {
    // All endpoints failed - provide fallback behavior
    this.logger.error('All RPC endpoints failed, using cached data');
    return this.getCachedTransactions(publicKey);
  }
}
```

### Circuit Breaker Pattern

```typescript
import { Injectable } from '@nestjs/common';

@Injectable()
export class BlockchainHealthService {
  private failureCount = 0;
  private readonly threshold = 5;
  private circuitOpen = false;

  async executeWithCircuitBreaker<T>(
    operation: () => Promise<T>
  ): Promise<T> {
    if (this.circuitOpen) {
      throw new Error('Circuit breaker is open - service unavailable');
    }

    try {
      const result = await operation();
      this.failureCount = 0; // Reset on success
      return result;
    } catch (error) {
      this.failureCount++;
      
      if (this.failureCount >= this.threshold) {
        this.circuitOpen = true;
        this.logger.error('Circuit breaker opened due to repeated failures');
        
        // Auto-reset after 60 seconds
        setTimeout(() => {
          this.circuitOpen = false;
          this.failureCount = 0;
        }, 60000);
      }
      
      throw error;
    }
  }
}
```

## Performance Optimization

### Parallel Requests

```typescript
// Execute multiple requests in parallel
async getBatchData(publicKeys: string[]) {
  const results = await Promise.all(
    publicKeys.map(key => 
      this.stellarService.getRecentTransactions(key)
    )
  );
  return results;
}
```

### Caching Strategy

```typescript
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class CachedStellarService {
  constructor(
    private stellarService: StellarService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async getTransactionsWithCache(publicKey: string) {
    const cacheKey = `transactions:${publicKey}`;
    
    // Try cache first
    const cached = await this.cacheManager.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch with automatic retry
    const transactions = await this.stellarService.getRecentTransactions(publicKey);
    
    // Cache for 5 minutes
    await this.cacheManager.set(cacheKey, transactions, 300000);
    
    return transactions;
  }
}
```

## Production Checklist

- [ ] Configure at least 2-3 fallback endpoints
- [ ] Set appropriate retry and timeout values
- [ ] Set up log monitoring and alerts
- [ ] Test failover behavior in staging
- [ ] Monitor `/blockchain/rpc/status` endpoint
- [ ] Implement caching for frequently accessed data
- [ ] Set up health checks for all endpoints
- [ ] Document endpoint maintenance procedures
- [ ] Configure geographic distribution of endpoints
- [ ] Set up automated endpoint health monitoring

## Troubleshooting

### Issue: Slow Response Times

```typescript
// Reduce timeout for faster failover
RPC_TIMEOUT=5000  // 5 seconds instead of 10

// Reduce retries
RPC_MAX_RETRIES=2  // 2 retries instead of 3
```

### Issue: Too Many Failovers

```typescript
// Check endpoint health
const status = await stellarService.getEndpointsStatus();
console.log('Current endpoints:', status);

// Consider promoting a more reliable backup to primary
SOROBAN_RPC_URL=https://reliable-backup.stellar.org
SOROBAN_RPC_FALLBACK_URLS=https://old-primary.stellar.org
```

### Issue: All Endpoints Failing

```typescript
// Implement exponential backoff at application level
async retryWithBackoff<T>(
  operation: () => Promise<T>,
  maxAttempts = 5
): Promise<T> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await operation();
    } catch (error) {
      if (i === maxAttempts - 1) throw error;
      
      const delay = Math.pow(2, i) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('Max attempts exceeded');
}
```

## Related Documentation

- [RPC_FALLBACK.md](./RPC_FALLBACK.md) - Complete feature documentation
- [Stellar SDK Documentation](https://stellar.github.io/js-stellar-sdk/)
- [NestJS Documentation](https://docs.nestjs.com/)

# Web3 RPC Fallback & Retry Strategy

## Overview

This implementation provides automatic failover and retry capabilities for Stellar Horizon and Soroban RPC endpoints. When the primary endpoint fails, the system automatically retries and falls back to backup endpoints, ensuring high availability for critical blockchain operations.

## Features

- **Multiple RPC Endpoints**: Configure primary and multiple fallback endpoints
- **Automatic Retry**: Configurable retry attempts with exponential backoff
- **Seamless Failover**: Automatic switching to backup endpoints on failure
- **Request Timeout**: Configurable timeout to prevent hanging requests
- **Comprehensive Logging**: Detailed logs for monitoring and alerting DevOps
- **Priority-Based Routing**: Endpoints are tried in priority order
- **Separate RPC and Horizon Pools**: Independent endpoint management for RPC and Horizon

## Configuration

### Environment Variables

Add the following to your `.env` file:

```env
# Primary endpoints
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
HORIZON_URL=https://horizon-testnet.stellar.org

# Fallback endpoints (comma-separated, in priority order)
SOROBAN_RPC_FALLBACK_URLS=https://rpc-backup1.stellar.org,https://rpc-backup2.stellar.org
HORIZON_FALLBACK_URLS=https://horizon-backup1.stellar.org,https://horizon-backup2.stellar.org

# Retry configuration
RPC_MAX_RETRIES=3          # Number of retries per endpoint
RPC_RETRY_DELAY=1000       # Initial delay between retries (ms)
RPC_TIMEOUT=10000          # Request timeout (ms)
```

### Configuration Details

- **SOROBAN_RPC_FALLBACK_URLS**: Comma-separated list of backup Soroban RPC endpoints
- **HORIZON_FALLBACK_URLS**: Comma-separated list of backup Horizon endpoints
- **RPC_MAX_RETRIES**: Number of retry attempts per endpoint before moving to next (default: 3)
- **RPC_RETRY_DELAY**: Initial delay between retries in milliseconds, uses exponential backoff (default: 1000ms)
- **RPC_TIMEOUT**: Maximum time to wait for a response before timing out (default: 10000ms)

## How It Works

### Retry Logic

1. **Initial Attempt**: Request is sent to the primary endpoint
2. **Retry on Failure**: If the request fails, it retries up to `RPC_MAX_RETRIES` times with exponential backoff
3. **Failover**: After exhausting retries on one endpoint, moves to the next endpoint in priority order
4. **Success**: Returns result as soon as any endpoint succeeds
5. **Complete Failure**: Throws error only after all endpoints and retries are exhausted

### Exponential Backoff

Retry delays increase exponentially:
- 1st retry: 1000ms (RPC_RETRY_DELAY)
- 2nd retry: 2000ms (RPC_RETRY_DELAY × 2)
- 3rd retry: 4000ms (RPC_RETRY_DELAY × 4)

### Example Scenario

With 3 RPC endpoints and 3 retries per endpoint:

```
Primary Endpoint (priority 0):
  ├─ Attempt 1: FAIL (wait 1s)
  ├─ Attempt 2: FAIL (wait 2s)
  └─ Attempt 3: FAIL → Move to next endpoint

Backup 1 (priority 1):
  ├─ Attempt 1: FAIL (wait 1s)
  ├─ Attempt 2: SUCCESS ✓
  └─ Return result
```

Total attempts before success: 5
Total time: ~4 seconds

## Logging

The system provides detailed logging at different levels:

### Debug Logs
```
Attempting rpc request on https://soroban-testnet.stellar.org (attempt 1)
```

### Warning Logs
```
RPC request failed on https://soroban-testnet.stellar.org (attempt 1/3): Network error
Successfully failed over to rpc endpoint: https://rpc-backup1.stellar.org after 5 attempts
```

### Error Logs (Critical)
```
CRITICAL: All retries exhausted for rpc endpoint https://soroban-testnet.stellar.org. Moving to next endpoint.
CRITICAL: All rpc endpoints failed after 9 total attempts. System may be experiencing network issues.
```

## Monitoring

### RPC Status Endpoint

Monitor the health and status of all configured endpoints:

```bash
GET /blockchain/rpc/status
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

### DevOps Alerts

Set up alerts based on log patterns:

1. **Warning Alert**: Multiple retries occurring
   - Pattern: `"RPC request failed"`
   - Action: Investigate endpoint health

2. **Critical Alert**: Endpoint exhausted
   - Pattern: `"CRITICAL: All retries exhausted"`
   - Action: Check endpoint availability, consider adding more backups

3. **Emergency Alert**: All endpoints failed
   - Pattern: `"CRITICAL: All .* endpoints failed"`
   - Action: Immediate investigation, system may be down

## Usage in Code

The retry logic is automatically applied to all Stellar service methods:

```typescript
// Automatically uses retry and failover
const health = await stellarService.getHealth();

// Automatically uses retry and failover for Horizon
const transactions = await stellarService.getRecentTransactions(publicKey);
```

### Adding New Methods with Retry

When adding new methods to `StellarService`, wrap RPC/Horizon calls with `executeWithRetry`:

```typescript
async myNewRpcMethod() {
  return await this.rpcClient.executeWithRetry(
    async (client) => {
      const rpcServer = client as rpc.Server;
      return await rpcServer.someMethod();
    },
    'rpc', // or 'horizon'
  );
}
```

## Testing

Run the test suite:

```bash
# Unit tests for RPC wrapper
npm test rpc-client.wrapper.spec.ts

# Unit tests for Stellar service
npm test stellar.service.spec.ts
```

## Best Practices

1. **Use Multiple Fallbacks**: Configure at least 2-3 fallback endpoints for production
2. **Monitor Logs**: Set up log aggregation and alerting for critical failures
3. **Test Failover**: Periodically test failover by temporarily disabling primary endpoints
4. **Geographic Distribution**: Use endpoints in different regions for better reliability
5. **Update Endpoints**: Keep fallback URLs updated as new public endpoints become available

## Production Recommendations

### Mainnet Configuration

```env
STELLAR_NETWORK=mainnet
SOROBAN_RPC_URL=https://mainnet.sorobanrpc.com
HORIZON_URL=https://horizon.stellar.org

# Multiple fallbacks for production
SOROBAN_RPC_FALLBACK_URLS=https://soroban-rpc.creit.tech,https://rpc.stellar.org
HORIZON_FALLBACK_URLS=https://horizon.stellar.lobstr.co,https://horizon-backup.stellar.org

# More aggressive retries for production
RPC_MAX_RETRIES=5
RPC_RETRY_DELAY=500
RPC_TIMEOUT=15000
```

### Testnet Configuration

```env
STELLAR_NETWORK=testnet
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
HORIZON_URL=https://horizon-testnet.stellar.org

# Fewer fallbacks for testnet
SOROBAN_RPC_FALLBACK_URLS=https://rpc-testnet-backup.stellar.org
HORIZON_FALLBACK_URLS=https://horizon-testnet-backup.stellar.org

RPC_MAX_RETRIES=3
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=10000
```

## Troubleshooting

### All Endpoints Failing

1. Check network connectivity
2. Verify endpoint URLs are correct and accessible
3. Check if Stellar network is experiencing issues
4. Review firewall/proxy settings

### Slow Response Times

1. Reduce `RPC_TIMEOUT` if endpoints are consistently slow
2. Reduce `RPC_MAX_RETRIES` to fail faster
3. Add faster endpoints to the fallback list
4. Consider geographic proximity of endpoints

### Frequent Failovers

1. Check primary endpoint health
2. Consider promoting a more reliable backup to primary
3. Increase `RPC_MAX_RETRIES` if transient failures are common
4. Review logs to identify patterns

## Architecture

```
┌─────────────────┐
│ StellarService  │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│ RpcClientWrapper    │
│                     │
│ - executeWithRetry  │
│ - Retry Logic       │
│ - Failover Logic    │
└────────┬────────────┘
         │
         ├─────────────┬─────────────┬─────────────┐
         ▼             ▼             ▼             ▼
    ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
    │Primary │   │Backup 1│   │Backup 2│   │Backup 3│
    │RPC/    │   │RPC/    │   │RPC/    │   │RPC/    │
    │Horizon │   │Horizon │   │Horizon │   │Horizon │
    └────────┘   └────────┘   └────────┘   └────────┘
```

## Related Files

- `rpc-client.wrapper.ts` - Core retry and failover logic
- `stellar.service.ts` - Stellar service using the wrapper
- `configuration.ts` - Configuration loading
- `rpc-client.wrapper.spec.ts` - Unit tests
- `stellar.service.spec.ts` - Service tests

## Issue Reference

Implements: Issue #195 - Implement Web3 RPC Fallback & Retry Strategy

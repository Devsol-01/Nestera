# RPC Fallback Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                           │
│  (Controllers, Services, Business Logic)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    StellarService                               │
│                                                                 │
│  • getHealth()                                                  │
│  • getRecentTransactions()                                      │
│  • generateKeypair()                                            │
│  • getEndpointsStatus()                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  RpcClientWrapper                               │
│                                                                 │
│  Core Features:                                                 │
│  • executeWithRetry(operation, clientType)                      │
│  • Automatic retry with exponential backoff                     │
│  • Seamless failover to backup endpoints                        │
│  • Request timeout protection                                   │
│  • Comprehensive logging                                        │
│                                                                 │
│  Configuration:                                                 │
│  • maxRetries: 3                                                │
│  • retryDelay: 1000ms (exponential)                             │
│  • timeoutMs: 10000ms                                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌──────────────────┐           ┌──────────────────┐
│  RPC Endpoints   │           │ Horizon Endpoints│
│  (Priority Pool) │           │  (Priority Pool) │
└────────┬─────────┘           └────────┬─────────┘
         │                               │
    ┌────┴────┬────────┬────────┐       │
    ▼         ▼        ▼        ▼       ▼
┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐
│Primary ││Backup 1││Backup 2││Backup 3││Primary │
│RPC     ││RPC     ││RPC     ││RPC     ││Horizon │
│        ││        ││        ││        ││        │
│Priority││Priority││Priority││Priority││Priority│
│   0    ││   1    ││   2    ││   3    ││   0    │
└────────┘└────────┘└────────┘└────────┘└────────┘
```

## Request Flow

### Successful Request (No Retry Needed)

```
User Request
    │
    ▼
StellarService.getRecentTransactions()
    │
    ▼
RpcClientWrapper.executeWithRetry()
    │
    ▼
Primary Horizon Endpoint
    │
    ▼ (Success)
Return Result to User
```

### Request with Retry (Same Endpoint)

```
User Request
    │
    ▼
StellarService.getRecentTransactions()
    │
    ▼
RpcClientWrapper.executeWithRetry()
    │
    ├─► Primary Horizon Endpoint (Attempt 1)
    │   └─► FAIL (Network Error)
    │       └─► Wait 1000ms
    │
    ├─► Primary Horizon Endpoint (Attempt 2)
    │   └─► FAIL (Timeout)
    │       └─► Wait 2000ms
    │
    └─► Primary Horizon Endpoint (Attempt 3)
        └─► SUCCESS ✓
            └─► Return Result to User
```

### Request with Failover (Multiple Endpoints)

```
User Request
    │
    ▼
StellarService.getRecentTransactions()
    │
    ▼
RpcClientWrapper.executeWithRetry()
    │
    ├─► Primary Horizon (Priority 0)
    │   ├─► Attempt 1: FAIL (wait 1s)
    │   ├─► Attempt 2: FAIL (wait 2s)
    │   └─► Attempt 3: FAIL
    │       └─► Log: "CRITICAL: All retries exhausted"
    │
    ├─► Backup 1 Horizon (Priority 1)
    │   ├─► Attempt 1: FAIL (wait 1s)
    │   └─► Attempt 2: SUCCESS ✓
    │       └─► Log: "Successfully failed over"
    │       └─► Update currentIndex = 1
    │
    └─► Return Result to User
```

## Component Responsibilities

### StellarService
- **Purpose**: High-level blockchain operations
- **Responsibilities**:
  - Expose blockchain functionality to application
  - Manage Stellar SDK interactions
  - Delegate retry/failover to RpcClientWrapper
- **Dependencies**: RpcClientWrapper, ConfigService

### RpcClientWrapper
- **Purpose**: Resilient RPC/Horizon client management
- **Responsibilities**:
  - Maintain endpoint pools (RPC and Horizon)
  - Execute operations with retry logic
  - Handle failover between endpoints
  - Log all retry and failover events
  - Track current active endpoint
- **Dependencies**: Stellar SDK (rpc.Server, Horizon.Server)

### Configuration
- **Purpose**: Centralized configuration management
- **Responsibilities**:
  - Load environment variables
  - Parse fallback URL lists
  - Provide retry configuration
  - Validate configuration values

## Data Flow

### Configuration Loading

```
.env file
    │
    ▼
ConfigService.get()
    │
    ├─► stellar.rpcUrl → Primary RPC URL
    ├─► stellar.rpcFallbackUrls → Array of backup RPC URLs
    ├─► stellar.horizonUrl → Primary Horizon URL
    ├─► stellar.horizonFallbackUrls → Array of backup Horizon URLs
    ├─► stellar.rpcMaxRetries → Retry count
    ├─► stellar.rpcRetryDelay → Initial delay
    └─► stellar.rpcTimeout → Request timeout
        │
        ▼
RpcClientWrapper constructor
    │
    ├─► Build RPC endpoints array with priorities
    ├─► Build Horizon endpoints array with priorities
    ├─► Sort by priority (0 = highest)
    └─► Initialize retry configuration
```

### Retry Logic Flow

```
executeWithRetry(operation, clientType)
    │
    ├─► Select endpoint pool (RPC or Horizon)
    │
    └─► For each endpoint (in priority order):
        │
        └─► For each retry (1 to maxRetries):
            │
            ├─► Create client instance
            ├─► Execute operation with timeout
            │
            ├─► If SUCCESS:
            │   ├─► Update currentIndex
            │   ├─► Log if failover occurred
            │   └─► Return result
            │
            └─► If FAILURE:
                ├─► Log warning
                ├─► Wait (exponential backoff)
                └─► Continue to next retry
        │
        └─► If all retries exhausted:
            ├─► Log CRITICAL error
            └─► Move to next endpoint
    │
    └─► If all endpoints exhausted:
        └─► Throw error with details
```

## Logging Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│ DEBUG Level                                                 │
│ • Each attempt on each endpoint                             │
│ • "Attempting rpc request on URL (attempt N)"               │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ WARN Level                                                  │
│ • Retry failures (not critical yet)                         │
│ • Successful failovers                                      │
│ • "RPC request failed on URL (attempt N/M)"                 │
│ • "Successfully failed over to URL after N attempts"        │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ ERROR Level (CRITICAL)                                      │
│ • Endpoint exhaustion                                       │
│ • All endpoints failed                                      │
│ • "CRITICAL: All retries exhausted for endpoint"            │
│ • "CRITICAL: All endpoints failed after N attempts"         │
└─────────────────────────────────────────────────────────────┘
```

## Monitoring Points

### 1. Endpoint Status
```
GET /blockchain/rpc/status

Returns:
{
  rpc: {
    endpoints: [...],
    currentIndex: 0,
    currentUrl: "https://..."
  },
  horizon: {
    endpoints: [...],
    currentIndex: 0,
    currentUrl: "https://..."
  }
}
```

### 2. Log Monitoring
- **Pattern**: `"CRITICAL: All retries exhausted"`
- **Action**: Alert DevOps, check endpoint health

### 3. Metrics (Future Enhancement)
- Request success rate per endpoint
- Average response time per endpoint
- Failover frequency
- Total retry count

## Scalability Considerations

### Horizontal Scaling
```
┌──────────┐  ┌──────────┐  ┌──────────┐
│Instance 1│  │Instance 2│  │Instance 3│
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
    ┌────▼────┐         ┌────▼────┐
    │RPC Pool │         │Horizon  │
    │         │         │Pool     │
    └─────────┘         └─────────┘
```

Each instance maintains its own:
- Current endpoint index
- Retry state
- Failover logic

This ensures:
- No shared state between instances
- Independent failover decisions
- Better fault isolation

### Load Distribution
- Each instance independently selects endpoints
- Natural load distribution across endpoint pool
- Failed endpoints avoided by all instances

## Security Considerations

### Endpoint Validation
- URLs validated at configuration load time
- Only HTTPS endpoints recommended for production
- Endpoint authentication via SDK configuration

### Timeout Protection
- Prevents hanging requests
- Configurable per environment
- Default: 10 seconds

### Error Information
- Logs contain endpoint URLs (for debugging)
- No sensitive data in error messages
- Stack traces only in development mode

## Performance Characteristics

### Best Case (Primary Endpoint Healthy)
- **Latency**: Network latency only
- **Overhead**: Minimal (wrapper function call)
- **Time**: ~100-500ms (typical RPC call)

### Retry Case (Primary Endpoint Flaky)
- **Latency**: Network latency + retry delays
- **Overhead**: Multiple connection attempts
- **Time**: ~1-7 seconds (with 3 retries)

### Failover Case (Primary Endpoint Down)
- **Latency**: Network latency + all retries + failover
- **Overhead**: Multiple endpoints tried
- **Time**: ~4-15 seconds (depends on retry config)

### Worst Case (All Endpoints Down)
- **Latency**: All retries on all endpoints
- **Overhead**: Maximum connection attempts
- **Time**: ~30-60 seconds (with 3 endpoints, 3 retries each)

## Configuration Tuning

### Low Latency (Fast Fail)
```env
RPC_MAX_RETRIES=1
RPC_RETRY_DELAY=500
RPC_TIMEOUT=3000
```
- Fails fast if endpoint is down
- Lower total latency
- Less resilient to transient failures

### High Reliability (More Retries)
```env
RPC_MAX_RETRIES=5
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=15000
```
- More resilient to transient failures
- Higher total latency on failures
- Better for critical operations

### Balanced (Recommended)
```env
RPC_MAX_RETRIES=3
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=10000
```
- Good balance of speed and reliability
- Reasonable failover time
- Suitable for most use cases

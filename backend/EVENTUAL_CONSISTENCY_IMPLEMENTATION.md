# Eventual Consistency Handling Implementation

## Overview

This implementation provides standardized handling for "Not Found Yet" scenarios in eventual consistency flows. When clients query for entities before the indexer/event handler has persisted them, the system now returns appropriate HTTP status codes with retry guidance.

## Implementation Details

### 1. New Error Codes

Added three new error codes to `src/common/enums/error-code.enum.ts`:

- `RESOURCE_NOT_YET_AVAILABLE` - Resource is being processed and will be available shortly
- `RESOURCE_PENDING_INDEXING` - Resource is pending blockchain indexing
- `RESOURCE_SYNC_IN_PROGRESS` - Resource sync is in progress

### 2. New Exception Classes

Added three new exception classes in `src/common/exceptions/domain.exception.ts`:

#### ResourceNotYetAvailableException
- **Status Code**: 202 (ACCEPTED)
- **Use Case**: Resource is being processed and will be available shortly
- **Parameters**: resource name, optional ID, optional retryAfterSeconds, optional additional details

#### ResourcePendingIndexingException
- **Status Code**: 202 (ACCEPTED)
- **Use Case**: Resource is pending blockchain indexing
- **Parameters**: resource name, optional ID, optional retryAfterSeconds, optional additional details

#### ResourceSyncInProgressException
- **Status Code**: 409 (CONFLICT)
- **Use Case**: Resource sync is in progress (conflict state)
- **Parameters**: resource name, optional ID, optional retryAfterSeconds, optional additional details

### 3. HTTP Exception Filter Enhancement

Updated `src/common/filters/http-exception.filter.ts` to:
- Extract `retryAfterSeconds` from exception details
- Add `Retry-After` HTTP header when present
- Automatically calculate ceiling value for header

### 4. Eventual Consistency Service

Created `src/common/services/eventual-consistency.service.ts` to provide:
- `calculateRetryAfter(multiplier)` - Calculate retry timing based on indexer poll interval
- `getDefaultRetryAfter()` - Get global default retry-after value
- `isLikelyPendingIndexing(createdAt, maxAgeSeconds)` - Determine if resource is likely pending indexing
- `getRetryAfterForRecentCreation(createdAt)` - Calculate retry-after for recently created resources

### 5. Service Integration

Updated services to use new exceptions:
- `ClaimsService` - Uses `ResourceNotFoundException` for claim lookups
- `SavingsService` - Uses `ResourceNotFoundException` for product lookups, injected `EventualConsistencyService`

## Response Semantics

### 404 Not Found
**Use Case**: Resource definitively does not exist
**Example**: Querying for a claim that was never created
```json
{
  "success": false,
  "statusCode": 404,
  "errorCode": "NOT_FOUND",
  "message": "Claim '123' not found",
  "requestId": "abc-123",
  "timestamp": "2024-01-01T00:00:00Z",
  "path": "/claims/123"
}
```

### 202 Accepted
**Use Case**: Resource exists but is not yet available (being processed/indexed)
**Example**: Querying for a transaction that was just submitted
```json
{
  "success": false,
  "statusCode": 202,
  "errorCode": "RESOURCE_NOT_YET_AVAILABLE",
  "message": "Transaction 'tx-123' is being processed and will be available shortly",
  "details": {
    "retryAfterSeconds": 30
  },
  "requestId": "abc-123",
  "timestamp": "2024-01-01T00:00:00Z",
  "path": "/transactions/tx-123"
}
```
**Headers**: `Retry-After: 30`

### 409 Conflict
**Use Case**: Resource exists but is in a conflicting state (sync in progress)
**Example**: Querying for a proposal that is being synced from blockchain
```json
{
  "success": false,
  "statusCode": 409,
  "errorCode": "RESOURCE_SYNC_IN_PROGRESS",
  "message": "Proposal 'prop-456' sync is in progress",
  "details": {
    "retryAfterSeconds": 60
  },
  "requestId": "abc-123",
  "timestamp": "2024-01-01T00:00:00Z",
  "path": "/governance/proposals/prop-456"
}
```
**Headers**: `Retry-After: 60`

## Configuration

Add to `.env`:

```env
# Default retry-after seconds for eventual consistency scenarios
EVENTUAL_CONSISTENCY_DEFAULT_RETRY_AFTER_SECONDS=30

# Stellar event poll interval (used for retry calculation)
STELLAR_EVENT_POLL_INTERVAL=10000
```

## Usage Examples

### Basic Usage

```typescript
import { ResourceNotYetAvailableException } from '../../common/exceptions/domain.exception';
import { EventualConsistencyService } from '../../common/services/eventual-consistency.service';

@Injectable()
export class MyService {
  constructor(
    private readonly eventualConsistencyService: EventualConsistencyService,
  ) {}

  async getTransaction(id: string) {
    const transaction = await this.transactionRepository.findOne({ where: { id } });
    
    if (!transaction) {
      // Check if it might be pending indexing
      const recentTransaction = await this.transactionRepository.findOne({
        where: { txHash: id },
        order: { createdAt: 'DESC' }
      });
      
      if (recentTransaction && this.eventualConsistencyService.isLikelyPendingIndexing(recentTransaction.createdAt)) {
        const retryAfter = this.eventualConsistencyService.getRetryAfterForRecentCreation(recentTransaction.createdAt);
        throw new ResourceNotYetAvailableException('Transaction', id, retryAfter);
      }
      
      throw new ResourceNotFoundException('Transaction', id);
    }
    
    return transaction;
  }
}
```

### With Additional Context

```typescript
throw new ResourcePendingIndexingException('SavingsProduct', productId, 45, {
  contractId: 'CXXXXXXX...',
  lastIndexedLedger: 12345,
  targetLedger: 12350,
});
```

## Testing

### Unit Tests

- `src/common/services/eventual-consistency.service.spec.ts` - Tests for EventualConsistencyService
- `src/common/exceptions/domain.exception.spec.ts` - Tests for new exception classes

Run tests:
```bash
pnpm test eventual-consistency.service.spec
pnpm test domain.exception.spec
```

### Integration Testing

To test the full flow:

1. Create a resource (e.g., submit a transaction)
2. Immediately query for it
3. Verify 202 response with Retry-After header
4. Wait for retry-after seconds
5. Query again
6. Verify 200 response with resource data

## Migration Guide

### For Existing Services

1. Import the new exceptions:
```typescript
import { 
  ResourceNotFoundException,
  ResourceNotYetAvailableException,
  ResourcePendingIndexingException 
} from '../../common/exceptions/domain.exception';
```

2. Replace generic `NotFoundException` or `Error` with appropriate exception:
```typescript
// Before
if (!resource) {
  throw new NotFoundException('Resource not found');
}

// After
if (!resource) {
  throw new ResourceNotFoundException('ResourceType', id);
}
```

3. For eventual consistency scenarios, use 202 exceptions:
```typescript
if (!resource && isLikelyPending) {
  const retryAfter = this.eventualConsistencyService.calculateRetryAfter();
  throw new ResourceNotYetAvailableException('ResourceType', id, retryAfter);
}
```

## Benefits

1. **Clear Semantics**: Distinguishes between "not found" and "not found yet"
2. **Retry Guidance**: Provides clients with explicit retry timing via Retry-After header
3. **Standardization**: Consistent error handling across all modules
4. **Better UX**: Clients can implement intelligent retry logic
5. **Monitoring**: Distinct error codes allow for better monitoring and alerting

## Future Enhancements

1. Add automatic retry logic in client SDKs
2. Implement exponential backoff for repeated retries
3. Add metrics for tracking eventual consistency scenarios
4. Create middleware to automatically detect pending indexing scenarios
5. Add webhook notifications when resources become available

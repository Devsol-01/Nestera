# Async Response Semantics Implementation

## Overview
Implemented standardized async response fields for endpoints returning 202 Accepted status, providing clients with consistent polling guidance and operation tracking.

## Standard Response Schema

### AsyncResponseDto
Located at: `backend/src/common/dto/async-response.dto.ts`

**Required Fields:**
- `statusCode`: HTTP status code (always 202 for async operations)
- `message`: Human-readable message describing the operation
- `operationId`: Unique identifier for tracking this operation
- `retryAfterSeconds`: Recommended seconds to wait before polling the status endpoint
- `statusEndpoint`: Endpoint to poll for operation status updates

**Optional Fields:**
- `operationType`: Type of operation being performed (for client categorization)
- `status`: Initial status of the operation
- `metadata`: Additional operation-specific metadata

### AsyncResponseBuilder
Helper class for constructing async responses with fluent API:
- `setMessage(message)`: Set the response message
- `setRetryAfterSeconds(seconds)`: Set polling interval
- `setOperationType(type)`: Set operation type
- `setStatus(status)`: Set initial status
- `setMetadata(metadata)`: Set additional metadata

## Migrated Endpoints

### 1. Data Export Endpoint
**File:** `backend/src/modules/data-export/data-export.controller.ts`
**Endpoint:** `POST /users/data/export`

**Response Example:**
```json
{
  "statusCode": 202,
  "message": "Export request received and queued. You will receive an email when your data is ready.",
  "operationId": "550e8400-e29b-41d4-a716-446655440000",
  "retryAfterSeconds": 10,
  "statusEndpoint": "/users/data/export/550e8400-e29b-41d4-a716-446655440000/status",
  "operationType": "data-export",
  "status": "pending"
}
```

### 2. Analytics Export Endpoints
**File:** `backend/src/modules/statistics/statistics.controller.ts`
**Endpoints:**
- `POST /admin/statistics/export/:dataType/jobs`
- `GET /admin/statistics/export/:dataType` (legacy route)

**Response Example:**
```json
{
  "statusCode": 202,
  "message": "Analytics export job queued successfully",
  "operationId": "550e8400-e29b-41d4-a716-446655440000",
  "retryAfterSeconds": 15,
  "statusEndpoint": "/admin/statistics/export/jobs/550e8400-e29b-41d4-a716-446655440000",
  "operationType": "analytics-export",
  "status": "pending",
  "metadata": {
    "dataType": "all",
    "format": "json"
  }
}
```

### 3. Tax Report Generation Endpoint
**File:** `backend/src/modules/reports/reports.controller.ts`
**Endpoint:** `POST /reports/tax/:year/async`

**Response Example:**
```json
{
  "statusCode": 202,
  "message": "Tax report generation queued successfully",
  "operationId": "12345",
  "retryAfterSeconds": 10,
  "statusEndpoint": "/reports/jobs/12345/status",
  "operationType": "report-generation",
  "status": "pending",
  "metadata": {
    "reportType": "tax",
    "year": 2024,
    "format": "csv"
  }
}
```

## Tests

### Unit Tests
**File:** `backend/src/common/dto/async-response.dto.spec.ts`
- Validates AsyncResponseDto structure
- Tests AsyncResponseBuilder fluent API
- Verifies method chaining
- Tests error handling for missing required fields

### Controller Tests
**File:** `backend/src/modules/data-export/data-export.controller.spec.ts`
- Validates async response schema from data export endpoint
- Verifies correct field values (statusCode, operationId, retryAfterSeconds, statusEndpoint)
- Tests status endpoint construction with operation ID
- Validates service integration

## Usage Pattern

```typescript
import { AsyncResponseBuilder } from '../../common/dto';

const result = await someService.queueOperation(params);
return new AsyncResponseBuilder(
  result.operationId,
  `/operations/${result.operationId}/status`,
)
  .setMessage('Operation queued successfully')
  .setRetryAfterSeconds(10)
  .setOperationType('operation-type')
  .setStatus('pending')
  .setMetadata({ /* operation-specific data */ })
  .build();
```

## Consistency Across Async Operations

The implementation ensures consistency across:
- **Exports**: Data export, analytics export
- **Background Processing**: Report generation, backup operations
- **Webhook-triggered Jobs**: Can be extended to webhook-triggered async operations

All async endpoints now return the same response structure, enabling clients to:
1. Poll at consistent intervals based on `retryAfterSeconds`
2. Track operations using `operationId`
3. Query status using the provided `statusEndpoint`
4. Categorize operations using `operationType`

## Acceptance Criteria Met

✅ Standard response schema implemented with required fields (retryAfterSeconds, operationId, statusEndpoint)
✅ At least 2 async endpoints migrated (3 endpoints migrated: data export, analytics export, report generation)
✅ Tests validate schema and values (unit tests for DTO/builder, integration tests for controller)

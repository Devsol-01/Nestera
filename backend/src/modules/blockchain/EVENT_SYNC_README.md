# Stellar Event Synchronization System

## Overview

This system keeps the off-chain PostgreSQL database synchronized with on-chain Soroban smart contract events. When a smart contract updates a medical claim status, the database is automatically updated to reflect the change.

## Architecture

### Components

1. **StellarEventListenerService**: Core service that polls Stellar Horizon for contract events
2. **ProcessedStellarEvent Entity**: Tracks processed events for idempotency
3. **StellarEventListenerController**: REST API for managing the listener
4. **Database Migration**: Creates the processed_stellar_events table

### How It Works

```
┌─────────────────┐
│ Soroban Smart   │
│ Contract        │
│ (On-Chain)      │
└────────┬────────┘
         │ Emits Event
         │ (AdjudicationComplete)
         ▼
┌─────────────────┐
│ Stellar Horizon │
│ RPC Server      │
└────────┬────────┘
         │ Polls every 10s
         ▼
┌─────────────────┐
│ Event Listener  │
│ Service         │
└────────┬────────┘
         │ Processes Event
         ▼
┌─────────────────┐
│ PostgreSQL      │
│ Database        │
│ - medical_claims│
│ - processed_    │
│   stellar_events│
└─────────────────┘
```

## Features

### 1. Long-Polling

The service polls the Stellar RPC server at configurable intervals (default: 10 seconds) to fetch new contract events.

```typescript
// Configuration
STELLAR_EVENT_POLL_INTERVAL=10000  // milliseconds
```

### 2. Event Filtering

Events are filtered by:
- **Contract ID**: Only events from your deployed smart contract
- **Event Type**: Specifically looking for `AdjudicationComplete` or `ClaimStatusUpdated` events

### 3. Idempotency

Each processed event is recorded in the `processed_stellar_events` table with a unique constraint on `(contractId, eventId)`. This ensures:
- Events are never processed twice
- Service can safely restart without duplicating updates
- Historical event processing is tracked

### 4. Cursor-Based Resumption

The service maintains a cursor (paging token) of the last processed event:
- On startup, loads the last cursor from the database
- Resumes from where it left off
- No events are missed during restarts

### 5. Status Mapping

Contract statuses are mapped to database enum values:

| Contract Status | Database Status |
|----------------|-----------------|
| approved       | APPROVED        |
| rejected       | REJECTED        |
| pending        | PENDING         |
| processing     | PROCESSING      |

## Configuration

### Environment Variables

```env
# Required
CONTRACT_ID=your_deployed_contract_id
SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
HORIZON_URL=https://horizon-testnet.stellar.org

# Optional
STELLAR_EVENT_POLL_INTERVAL=10000  # Poll interval in milliseconds
STELLAR_NETWORK=testnet            # testnet or mainnet
```

### Database Schema

```sql
CREATE TABLE processed_stellar_events (
  "eventId" VARCHAR PRIMARY KEY,
  "contractId" VARCHAR NOT NULL,
  "transactionHash" VARCHAR NOT NULL,
  "ledger" INTEGER NOT NULL,
  "eventType" VARCHAR NOT NULL,
  "eventData" JSONB NOT NULL,
  "claimId" VARCHAR,
  "processedAt" TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IDX_CONTRACT_EVENT 
  ON processed_stellar_events("contractId", "eventId");
CREATE INDEX IDX_CLAIM_ID 
  ON processed_stellar_events("claimId");
CREATE INDEX IDX_PROCESSED_AT 
  ON processed_stellar_events("processedAt");
```

## API Endpoints

### Get Listener Status

```http
GET /stellar-events/status
```

Response:
```json
{
  "isRunning": true,
  "contractId": "CXXXXXXX...",
  "lastCursor": "123456-1",
  "pollInterval": 10000
}
```

### Manual Sync Trigger

```http
POST /stellar-events/sync
```

Response:
```json
{
  "message": "Manual sync completed",
  "processed": 1,
  "errors": 0
}
```

### Start Listener

```http
POST /stellar-events/start
```

### Stop Listener

```http
POST /stellar-events/stop
```

## Event Structure

### Expected Contract Event Format

The service expects events with the following structure:

```typescript
{
  id: string;              // Unique event ID
  type: 'contract';        // Event type
  ledger: number;          // Ledger number
  contractId: string;      // Your contract ID
  topic: [                 // Event topics (XDR encoded)
    'AdjudicationComplete', // Event name
    'claim-uuid',           // Claim ID
    'approved'              // New status
  ],
  value: any;              // Event value (XDR encoded)
  txHash: string;          // Transaction hash
  inSuccessfulContractCall: boolean;
}
```

### Parsing Custom Events

If your contract uses a different event structure, modify these methods:

```typescript
// Extract claim ID from event
private extractClaimIdFromEvent(event): string | null {
  // Customize based on your contract's event structure
}

// Extract status from event
private extractStatusFromEvent(event): string | null {
  // Customize based on your contract's event structure
}
```

## Lifecycle

### Startup

1. Service initializes on module init
2. Loads last processed cursor from database
3. Starts polling immediately
4. Sets up recurring poll interval

### Processing

1. Fetch events from RPC server
2. For each event:
   - Check if already processed (idempotency)
   - Parse event type and data
   - If claim status update:
     - Find claim in database
     - Update status and add notes
     - Save claim
   - Record event as processed

### Shutdown

1. Clears polling interval
2. Stops accepting new events
3. Cursor is persisted in database

## Error Handling

### Transient Errors

- Network failures: Logged and retried on next poll
- RPC server errors: Logged and retried on next poll

### Permanent Errors

- Event parsing errors: Logged, event skipped
- Database errors: Logged, event skipped
- Missing claim: Logged, event recorded as processed

### Recovery

The service is designed to be resilient:
- Automatic retry on transient failures
- Cursor-based resumption after crashes
- Idempotency prevents duplicate processing

## Monitoring

### Logs

The service logs:
- Startup and configuration
- Each event processed
- Status updates applied
- Errors and warnings

### Metrics to Monitor

- Events processed per minute
- Processing lag (time between event emission and processing)
- Error rate
- Cursor position vs. latest ledger

## Testing

### Unit Tests

```bash
pnpm test stellar-event-listener.service.spec.ts
```

### Manual Testing

1. Deploy a test claim
2. Update status via smart contract
3. Check logs for event processing
4. Verify database updated
5. Check `processed_stellar_events` table

### Integration Testing

```bash
# Start the service
pnpm run start:dev

# Trigger manual sync
curl -X POST http://localhost:3001/stellar-events/sync

# Check status
curl http://localhost:3001/stellar-events/status
```

## Troubleshooting

### Events Not Being Processed

1. Check CONTRACT_ID is set correctly
2. Verify RPC_URL is accessible
3. Check service is running: `GET /stellar-events/status`
4. Review logs for errors

### Duplicate Processing

1. Check database unique constraint exists
2. Verify `processed_stellar_events` table is accessible
3. Review logs for idempotency checks

### Missing Events

1. Check cursor position vs. latest ledger
2. Verify event structure matches expected format
3. Review event parsing logic
4. Check contract is emitting events correctly

## Performance Considerations

### Poll Interval

- Lower interval = faster updates, more RPC calls
- Higher interval = slower updates, fewer RPC calls
- Recommended: 10-30 seconds for production

### Batch Size

- Default limit: 100 events per poll
- Adjust based on event volume
- Consider rate limits from RPC provider

### Database Indexes

Ensure indexes exist on:
- `processed_stellar_events(contractId, eventId)` - Unique constraint
- `processed_stellar_events(claimId)` - Fast claim lookups
- `processed_stellar_events(processedAt)` - Time-based queries

## Future Enhancements

1. **Webhook Support**: Alternative to polling
2. **Event Replay**: Reprocess historical events
3. **Multi-Contract Support**: Monitor multiple contracts
4. **Event Filtering**: More granular event type filtering
5. **Metrics Export**: Prometheus/Grafana integration
6. **Dead Letter Queue**: Handle permanently failed events
7. **Event Transformation**: Custom event data transformations

# Sandbox / Developer Mode

> **⚠️ IMPORTANT — Not for production use**
>
> The Sandbox module must only be enabled in `development` and `test`
> environments. Register it conditionally in `app.module.ts`:
>
> ```typescript
> // app.module.ts – guard sandbox behind environment check
> ...(process.env.NODE_ENV !== 'production' ? [SandboxModule] : []),
> ```

---

## Overview

The Sandbox module provides a structured developer / training mode for the
Nestera backend. It exposes HTTP endpoints that allow authorised administrators
to:

1. **Generate configurable test data** – users, wallets, transactions, and
   savings goals with customisable counts.
2. **Simulate Soroban contract events** – inject synthetic `Deposit`,
   `Withdraw`, or `Yield` events without touching the real Stellar ledger.
3. **Reset sandbox state** – truncate sandbox tables back to a clean slate
   (requires a confirmation token to prevent accidental triggers).
4. **Manage sandbox API keys** – create and list API keys used by automated
   test suites.
5. **Inspect usage analytics** – review what endpoints have been called during
   a sandbox session.

---

## Access Control

All sandbox endpoints are protected by **two layers** of authentication and
authorisation:

| Guard | Purpose |
|---|---|
| `JwtAuthGuard` | Validates the JWT bearer token sent in the `Authorization` header |
| `RolesGuard` + `@Roles(Role.ADMIN)` | Ensures the authenticated user holds the `ADMIN` role |

Any request that lacks a valid JWT or that belongs to a non-admin user will
receive a `401 Unauthorized` or `403 Forbidden` response respectively.

### Obtaining a token

```bash
# Authenticate as an admin user
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "yourpassword"}'
```

Use the `access_token` value from the response as the bearer token for all
sandbox requests:

```bash
export TOKEN="<access_token>"
```

---

## Base URL

```
/sandbox
```

---

## Endpoints

### `POST /sandbox/api-keys`

Create a new sandbox API key.

**Request body**

```json
{
  "name": "my-ci-key",
  "userId": "optional-uuid"
}
```

**Response** `201 Created`

```json
{
  "id": "uuid",
  "key": "sb_xxxx-xxxx-xxxx",
  "name": "my-ci-key",
  "isActive": true,
  "requestCount": 0,
  "createdAt": "2026-06-30T00:00:00.000Z"
}
```

---

### `GET /sandbox/api-keys`

List all sandbox API keys.

**Response** `200 OK` — array of `SandboxApiKey` objects.

---

### `POST /sandbox/test-data`

Generate configurable test data.

**Request body** (all fields optional)

```json
{
  "userCount": 5,
  "transactionsPerUser": 5,
  "savingsGoalsPerUser": 2
}
```

| Field | Type | Default | Range | Description |
|---|---|---|---|---|
| `userCount` | integer | `5` | 1–50 | Number of test users to create |
| `transactionsPerUser` | integer | `5` | 1–20 | Transactions per user |
| `savingsGoalsPerUser` | integer | `2` | 1–10 | Savings goals per user |

**Response** `201 Created`

```json
{
  "users": [...],
  "transactions": [...],
  "savingsGoals": [...],
  "summary": {
    "usersCreated": 5,
    "transactionsCreated": 25,
    "savingsGoalsCreated": 10,
    "options": { "userCount": 5, "transactionsPerUser": 5, "savingsGoalsPerUser": 2 }
  }
}
```

---

### `POST /sandbox/simulate-event`

Simulate a Soroban contract event.

**Request body**

```json
{
  "eventType": "Deposit",
  "publicKey": "GABC...XYZ",
  "amount": "250.00",
  "ledger": 1234567,
  "contractId": "CABC...DEF"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `eventType` | `"Deposit" \| "Withdraw" \| "Yield"` | ✅ | Type of contract event to simulate |
| `publicKey` | string | ✅ | Stellar public key (or wallet address) of the target user |
| `amount` | string | ✅ | Token amount as a string (preserves decimal precision) |
| `ledger` | integer | ❌ | Simulated ledger sequence (random if omitted) |
| `contractId` | string | ❌ | Simulated contract ID (random if omitted) |

**Response** `200 OK`

```json
{
  "simulated": true,
  "eventType": "Deposit",
  "eventId": "sandbox:deposit:uuid",
  "ledgerSequence": 1234567,
  "contractId": "CABC...DEF",
  "publicKey": "GABC...XYZ",
  "amount": "250.00",
  "message": "Deposit event simulation completed for sandbox. Use the eventId to look up downstream processing results."
}
```

---

### `POST /sandbox/reset`

Reset all sandbox data.

> **⚠️ Destructive operation.** This truncates the `sandbox_api_keys` and
> `sandbox_usage_analytics` tables. A confirmation token is required.

**Request body**

```json
{
  "confirm": "CONFIRM_RESET"
}
```

Omitting the confirmation token or providing any other value returns `400 Bad Request`.

**Response** `200 OK`

```json
{
  "message": "Sandbox data reset successfully"
}
```

---

### `GET /sandbox/usage-analytics`

Retrieve sandbox usage analytics (recent calls first).

**Response** `200 OK` — array of `SandboxUsageAnalytics` objects.

```json
[
  {
    "id": "uuid",
    "apiKeyId": "sandbox-simulate",
    "endpoint": "/sandbox/simulate-event",
    "method": "POST",
    "statusCode": 200,
    "responseTimeMs": 0,
    "userAgent": "SandboxSimulator/Deposit",
    "createdAt": "2026-06-30T00:00:00.000Z"
  }
]
```

---

## Curl Examples

All examples use `$TOKEN` set from the login step above.

```bash
# Generate 3 users with 10 transactions each
curl -X POST http://localhost:3001/sandbox/test-data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userCount": 3, "transactionsPerUser": 10, "savingsGoalsPerUser": 2}'

# Simulate a Deposit event
curl -X POST http://localhost:3001/sandbox/simulate-event \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "Deposit",
    "publicKey": "GABC123XYZ",
    "amount": "500.00",
    "ledger": 9999999
  }'

# Simulate a Withdraw event
curl -X POST http://localhost:3001/sandbox/simulate-event \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"eventType": "Withdraw", "publicKey": "GABC123XYZ", "amount": "100.00"}'

# Reset the sandbox (requires confirmation)
curl -X POST http://localhost:3001/sandbox/reset \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm": "CONFIRM_RESET"}'

# List usage analytics
curl http://localhost:3001/sandbox/usage-analytics \
  -H "Authorization: Bearer $TOKEN"
```

---

## Architecture Notes

- **Isolation**: The sandbox module uses its own database tables
  (`sandbox_api_keys`, `sandbox_usage_analytics`). It does NOT write to
  production-domain tables during simulation; the `simulateContractEvent`
  endpoint returns a description of what the blockchain event handlers *would*
  do, enabling integration testing without side effects.
- **Guards**: `JwtAuthGuard` + `RolesGuard(ADMIN)` are applied at the
  controller class level so every route inherits the same access policy.
- **Structured logging**: All sandbox operations emit structured log entries
  compatible with the project-wide pino logger, making it easy to correlate
  sandbox activity with other backend logs.
- **Closing issues**: This module resolves GitHub issue
  [#1066](https://github.com/Devsol-01/Nestera/issues/1066) — *Add Structured
  Training/Developer Mode Endpoints (Sandbox)*.

# Admin Idempotency Conflict Observability

This task adds an **admin-only** view into idempotency conflicts so that operators can understand and troubleshoot repeated client requests without exposing sensitive request payloads.

## Why this exists
When clients send mutating requests with an `idempotency-key`, the system replays stored outcomes for duplicates. However, two conflict scenarios can happen:

1. **Payload mismatch**: the same idempotency key is reused with a *different* request body.
2. **Concurrent processing**: another request with the same key is currently being processed.

Both cases return **HTTP 409 Conflict** to the client. Previously, admins had limited visibility into *what* conflicted (route + fingerprint), *when* it happened, and how frequently certain keys are involved.

## What the admin endpoint provides
The admin endpoints live under:

- `GET /api/admin/idempotency/conflicts`
- `GET /api/admin/idempotency/conflicts/summary`
- `GET /api/admin/idempotency/usage`

They provide:

- **Recent conflicts** (or aggregated statistics)
- **Request fingerprint hash**
  - Computed as **SHA-256** over the request body (normalized via JSON stringification)
  - Used purely for correlation and does **not** include raw payloads
- **Timestamps**
  - ISO 8601 timestamps indicating when conflicts/events were detected
- **Related entity linking (best-effort)**
  - The service infers a `relatedEntityType` from the request path (example: `/savings/123` → `savings`)

## Sensitive data handling
A core requirement is that **no sensitive payload data** is stored or exposed via the admin endpoints.

- Admin responses include only identifiers/metadata (e.g., `idempotencyKey`, `requestFingerprintHash`, route info, timestamps).
- The monitoring buffers are in-memory and store **only**:
  - `idempotencyKey`
  - `requestFingerprintHash`
  - routing metadata (`method`, `path`)
  - timestamps and conflict type
- Payload redaction is enforced by DTO shape: conflict DTOs do **not** include any raw request body fields.

## Implementation overview (where to look)
- `backend/src/modules/admin/admin-idempotency.controller.ts`
  - Admin HTTP controllers + Swagger metadata
- `backend/src/modules/admin/dto/admin-idempotency.dto.ts`
  - DTOs defining the payload-safe response schema
- `backend/src/common/interceptors/idempotency.interceptor.ts`
  - Detects conflicts and emits `idempotency.conflict` events with fingerprint + timestamps
- `backend/src/common/services/idempotency-monitor.service.ts`
  - Collects emitted events into in-memory circular buffers
  - Provides query methods used by the admin controller

## Notes
- This observability is designed for operator visibility, not for payload inspection.
- Because monitoring uses in-memory buffers, the data is **recent only** and resets on application restart.


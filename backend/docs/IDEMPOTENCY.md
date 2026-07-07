# Idempotency — Endpoint Reference

> Issue [#1116](https://github.com/Devsol-01/Nestera/issues/1116)
>
> All mutating (non-transaction) endpoints now require an `Idempotency-Key` header
> to guarantee safe retries.  The key is **optional** — omitting it disables
> idempotency protection for that call.

---

## How it works

1. Client sends `Idempotency-Key: <uuid>` with any mutating request.
2. On the first call the server processes the request normally, then stores
   `{ payloadHash, statusCode, body }` in the cache with the configured TTL.
3. A duplicate call with the **same key and identical payload** receives the
   stored response immediately — the handler is not re-executed.
4. A duplicate call with the **same key but a different payload** receives
   `409 Conflict` (`IDEMPOTENCY_CONFLICT`).
5. If a request with the same key is currently in-flight (lock held), a second
   concurrent call receives `409 Conflict`.
6. For async/job endpoints the stored body contains the **job correlation id**
   so the client can poll for status rather than trigger a duplicate job.

---

## Default TTL

| Endpoint category            | TTL       |
|------------------------------|-----------|
| All endpoints below          | 24 hours  |
| `POST /governance/proposals/:id/vote` | 1 hour |

---

## Endpoints that require an Idempotency-Key

### Disputes

| Method | Path | Handler |
|--------|------|---------|
| POST | `/disputes` | `createDispute` |
| POST | `/disputes/:id/messages` | `addMessage` |
| PATCH | `/disputes/:id/investigate` | `startInvestigation` |
| PATCH | `/disputes/:id/resolve` | `resolveDispute` |
| PATCH | `/disputes/:id/close` | `closeDispute` |
| PATCH | `/disputes/:id/escalate` | `escalateDispute` |
| POST | `/disputes/:id/evidence` | `uploadEvidence` *(async job)* |

### Governance

| Method | Path | Handler |
|--------|------|---------|
| POST | `/governance/proposals/create` | `createProposal` |
| POST | `/governance/proposals/:id/vote` | `castVote` |
| POST | `/governance/proposals/:id/queue` | `queueProposal` |
| POST | `/governance/proposals/:id/execute` | `executeProposal` |
| POST | `/governance/proposals/:id/cancel` | `cancelProposal` |
| POST | `/governance/proposals/:id/finalize` | `finalizeProposal` |
| POST | `/user/governance/delegate` | `delegate` |
| DELETE | `/user/governance/delegate` | `revokeDelegate` |

### Referrals

| Method | Path | Handler |
|--------|------|---------|
| POST | `/referrals/generate` | `generateReferralCode` |
| POST | `/referrals/check-completion` | `checkReferralCompletion` |
| POST | `/users/referrals/code/generate` | `generateCode` |

### Notifications

| Method | Path | Handler |
|--------|------|---------|
| PATCH | `/notifications/:id/read` | `markAsRead` |
| PATCH | `/notifications/mark-all-read` | `markAllAsRead` |
| POST | `/notifications/preferences` | `createPreferences` |
| PATCH | `/notifications/preferences` | `updatePreferences` |

### Claims

| Method | Path | Handler |
|--------|------|---------|
| POST | `/claims` | `submitClaim` |
| POST | `/claims/:id/verify` | `verifyClaimWithHospital` *(external call)* |

### KYC

| Method | Path | Handler |
|--------|------|---------|
| POST | `/user/kyc/initiate` | `initiate` |
| POST | `/user/kyc/documents` | `uploadDocument` |
| PATCH | `/admin/kyc/documents/:id/review` | `reviewDocument` |

### Savings (pre-existing)

| Method | Path | Handler |
|--------|------|---------|
| POST | `/savings/subscribe` | `subscribe` |
| POST | `/savings/withdraw` | `withdraw` |

### Webhooks (pre-existing)

| Method | Path | Handler |
|--------|------|---------|
| POST | `/webhooks/stellar` | `handleStellarWebhook` |

---

## Admin endpoints

### Admin — Disputes

| Method | Path | Handler |
|--------|------|---------|
| POST | `/admin/disputes/:id/assign` | `assignDispute` |
| POST | `/admin/disputes/:id/resolve` | `resolveDispute` |
| POST | `/admin/disputes/:id/escalate` | `escalateDispute` |
| POST | `/admin/disputes/:id/evidence` | `addEvidence` |
| PATCH | `/admin/disputes/:id` | `updateDispute` |

### Admin — KYC

| Method | Path | Handler |
|--------|------|---------|
| PATCH | `/admin/users/:id/kyc/approve` | `approveKyc` |
| PATCH | `/admin/users/:id/kyc/reject` | `rejectKyc` |
| PATCH | `/admin/users/:id/kyc` | `updateKycStatus` |

### Admin — Withdrawals

| Method | Path | Handler |
|--------|------|---------|
| POST | `/admin/withdrawals/:id/approve` | `approve` |
| POST | `/admin/withdrawals/:id/reject` | `reject` |

### Admin — Savings Products

| Method | Path | Handler |
|--------|------|---------|
| POST | `/admin/savings/products` | `createProduct` |
| POST | `/admin/savings/products/:id/subscriptions/override` | `createSubscriptionOverride` |
| POST | `/admin/savings/products/experiments` | `createExperiment` |

### Admin — Transactions

| Method | Path | Handler |
|--------|------|---------|
| POST | `/admin/transactions/export/async` | `exportAsync` *(async job)* |
| POST | `/admin/transactions/:id/notes` | `addNote` |

### Admin — Users

| Method | Path | Handler |
|--------|------|---------|
| PATCH | `/admin/users/:id/role` | `updateRole` |
| PATCH | `/admin/users/:id/status` | `updateStatus` |
| POST | `/admin/users/bulk-action` | `bulkAction` |

### Admin — Notifications

| Method | Path | Handler |
|--------|------|---------|
| POST | `/admin/notifications/broadcast` | `broadcastNotification` |
| POST | `/admin/notifications/targeted` | `sendTargetedNotification` |
| POST | `/admin/notifications/schedule` | `scheduleNotification` |

---

## Error responses

| Status | `errorCode` | Meaning |
|--------|-------------|---------|
| `409 Conflict` | `IDEMPOTENCY_CONFLICT` | Key reused with different payload, or concurrent in-flight request |

---

## Notes on async endpoints

Endpoints marked *(async job)* enqueue a background job on first call and store
the job correlation id in the idempotency record.  Replay returns that id so
the client can poll `/.../:jobId` for status without triggering a duplicate job.

Endpoints marked *(external call)* store the idempotency result **only after**
the external side-effect is confirmed, ensuring compensation is not needed for
cached replays.

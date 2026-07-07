# Pagination

This document describes the pagination contract for all Nestera API list endpoints.

---

## Default Sort Order

All list endpoints default to **`createdAt DESC, id DESC`** unless the endpoint
documentation states otherwise. This is a *stable* sort: the `id` column acts as
a tie-breaker so that any two records with the same `createdAt` timestamp are
always returned in the same, deterministic order.

| Column     | Direction | Purpose                                          |
|------------|-----------|--------------------------------------------------|
| `createdAt`| DESC      | Primary sort — newest records first              |
| `id`       | DESC      | Tie-breaker — deterministic ordering on ties     |

### Why two columns?

PostgreSQL does not guarantee row order for rows with identical values in the
sort key. When records are inserted concurrently (or bulk-seeded) they can share
the same `createdAt` millisecond. Without a tie-breaker:

- **Offset-based pages** can return the same record on two consecutive pages if a
  new record is inserted between requests.
- **Cursor-based pages** must encode the *full* sort key so the compound
  predicate can resume correctly.

Adding `id` as a tie-breaker eliminates both problems because `id` is a UUID and
globally unique.

---

## Offset-Based Pagination

Used by most read endpoints. Clients supply `page` and `limit` query parameters.

```
GET /api/v2/transactions?page=2&limit=20&order=DESC
```

### Query Parameters

| Parameter      | Type    | Default | Description                               |
|----------------|---------|---------|-------------------------------------------|
| `page`         | integer | `1`     | 1-based page number                       |
| `limit`        | integer | `10`    | Items per page (max `100`)                |
| `order`        | enum    | `DESC`  | `ASC` or `DESC` — applied to `createdAt` |
| `includeTotal` | boolean | `false` | Set `true` to receive `totalCount`        |

### Response Envelope

```json
{
  "items": [...],
  "meta": {
    "page": 2,
    "pageSize": 20,
    "totalItemCount": 145,
    "pageCount": 8,
    "hasPreviousPage": true,
    "hasNextPage": true,
    "nextCursor": null
  }
}
```

### Limitations

Offset pagination is inherently sensitive to dataset changes between page
requests:

- A record **inserted** between page 1 and page 2 requests will push an item
  from the "old" page 1 into page 2, causing it to appear **twice**.
- A record **deleted** between page 1 and page 2 requests will cause an item to
  be **skipped**.

Mitigation: use cursor pagination for infinite-scroll or high-write workloads.

---

## Cursor-Based Pagination

Available on endpoints that support the `cursor` query parameter. Cursor
pagination is immune to insert/delete skew because it uses a positional
predicate rather than an offset.

```
# First page (no cursor)
GET /api/v2/transactions?limit=20

# Next page (use nextCursor from previous response)
GET /api/v2/transactions?limit=20&cursor=<nextCursor>
```

### How the Cursor Works

The cursor is an **opaque, URL-safe base64 string**. Clients MUST NOT parse or
construct cursor values — treat it as a black box. Pass the exact string
returned in `meta.nextCursor` to fetch the next page.

Internally the cursor encodes the full sort key of the last item on the current
page:

```json
{ "createdAt": "2024-03-15T12:00:00.000Z", "id": "550e8400-e29b-41d4-a716-446655440000" }
```

This two-field payload allows the query to use the **compound seek predicate**:

```sql
-- For DESC order (newest first):
WHERE (createdAt < :cursorCreatedAt)
   OR (createdAt = :cursorCreatedAt AND id < :cursorId)

-- For ASC order (oldest first):
WHERE (createdAt > :cursorCreatedAt)
   OR (createdAt = :cursorCreatedAt AND id > :cursorId)
```

This predicate is index-friendly when a composite index on `(createdAt, id)`
exists on the table.

### Response Envelope

```json
{
  "items": [...],
  "meta": {
    "page": 1,
    "pageSize": 20,
    "nextCursor": "eyJjcmVhdGVkQXQiOiIyMDI0LTAzLTE1VDEyOjAwOjAwLjAwMFoiLCJpZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCJ9",
    "hasNextPage": true,
    "hasPreviousPage": false
  }
}
```

When `nextCursor` is `null` there are no more pages.

---

## Endpoint-Specific Sort Notes

| Endpoint                          | Sort Key(s)                           | Tie-breaker  |
|-----------------------------------|---------------------------------------|--------------|
| `GET /api/v2/transactions`        | `createdAt` (or user-chosen `sortBy`) | `id`         |
| `GET /api/v2/notifications`       | `createdAt`                           | `id`         |
| `GET /api/v2/savings/goals`       | `createdAt`                           | `id`         |
| `GET /api/v2/savings/products`    | `createdAt` (or `apy`/`tvl`)          | `id`         |
| `GET /api/v2/claims`              | `createdAt`                           | `id`         |
| `GET /api/v2/disputes`            | `createdAt`                           | `id`         |
| `GET /api/v2/transactions/saved-searches` | `isDefault DESC, updatedAt DESC` | `id ASC`  |
| `GET /api/v2/admin/users`         | `createdAt`                           | `id`         |
| `GET /api/v2/admin/transactions`  | `createdAt`                           | `id`         |

---

## Recommendations for Clients

1. **Always use `nextCursor`** for sequential page traversal. Do not construct
   the next page URL by incrementing `page`.
2. **Do not decode cursors.** Their format is an internal implementation detail
   and may change across API versions.
3. **Use `includeTotal=true` sparingly.** The total count requires a separate
   `COUNT(*)` query and adds latency. Omit it unless you need to display a
   total-page count UI.
4. **Expect eventual consistency.** When the dataset changes between page
   requests, cursor pagination eliminates duplicates/skips, but offset-based
   pagination cannot fully prevent them. Design UIs that refresh gracefully.

---

## Developer Notes

- `cursor-pagination.helper.ts` — `encodeCursor` / `decodeCursor` utilities.
  `decodeCursor` throws `BadRequestException` on invalid input.
- `pagination.helper.ts` — `paginate()` utility for offset-based
  `SelectQueryBuilder` queries; automatically applies `createdAt + id` ordering.
- `page-options.dto.ts` — shared `PageOptionsDto` with `page`, `limit`,
  `order`, `cursor`, `includeTotal` fields.

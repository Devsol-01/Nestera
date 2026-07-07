# Request Body Compression

The API accepts **compressed request bodies** so clients sending large JSON
payloads (bulk operations, evidence metadata) can reduce upload bandwidth.
Support is opt-in for the client (via the `Content-Encoding` header) and is
guarded with strict safety limits to prevent zip-bomb attacks.

> Note: this is **inbound** decompression (request bodies). Outbound
> **response** compression (gzip/brotli) is configured separately in
> `main.ts` via the `compression` middleware.

## Sending a compressed request

Compress the body with `gzip` or `deflate` and set the matching header:

```bash
# Compress a JSON file and POST it
gzip -c payload.json | \
  curl -X POST https://api.nestera.io/api/v2/<endpoint> \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -H "Content-Encoding: gzip" \
    --data-binary @-
```

The server inflates the body transparently; controllers and validation see the
decoded JSON exactly as if it had been sent uncompressed.

### Supported encodings

| `Content-Encoding` | Behaviour                                              |
| ------------------ | ----------------------------------------------------- |
| _(absent)_         | Body read as-is.                                       |
| `identity`         | Treated as uncompressed.                               |
| `gzip`             | Inflated, subject to the decompressed-size limit.     |
| `deflate`          | Inflated, subject to the decompressed-size limit.     |
| anything else      | Rejected with **415 Unsupported Media Type**.         |
| stacked (`a, b`)   | Rejected with **415** (nested-bomb vector).           |

## Safety limits (zip-bomb protection)

A small compressed payload can inflate to gigabytes. Two layers protect the
server:

1. **Encoding allow-list** — the `RequestDecompressionGuard`
   (`src/common/middleware/request-decompression.middleware.ts`) runs before the
   body parser and rejects any encoding that is not `gzip`/`deflate`/`identity`,
   as well as stacked encodings, with **415**. It can also disable compressed
   bodies entirely.
2. **Decompressed-size cap** — the body parser inflates the stream and enforces
   the configured limit against the **decompressed** bytes, aborting with
   **413 Payload Too Large** the moment the inflated output exceeds the limit.
   The payload is never fully buffered, so a bomb cannot exhaust memory.

## Configuration

| Env var                         | Default            | Description                                                                 |
| ------------------------------- | ------------------ | --------------------------------------------------------------------------- |
| `REQUEST_DECOMPRESSION_ENABLED` | `true`             | When `false`, any non-identity `Content-Encoding` is rejected with **415**. |
| `REQUEST_ALLOWED_ENCODINGS`     | `gzip,deflate`     | Comma-separated allow-list of accepted request encodings.                   |
| `REQUEST_MAX_DECOMPRESSED_SIZE` | `JSON_BODY_LIMIT`  | Max decompressed body size (e.g. `1mb`, `512kb`). Enforced with **413**.    |
| `JSON_BODY_LIMIT`               | `1mb`              | Max JSON body size; default cap for decompressed bodies.                    |
| `URLENCODED_BODY_LIMIT`         | `1mb`              | Max urlencoded body size.                                                   |

## Error responses

| Status | When                                                                 |
| ------ | -------------------------------------------------------------------- |
| `413`  | Decompressed body exceeds `REQUEST_MAX_DECOMPRESSED_SIZE`.           |
| `415`  | Unsupported encoding, stacked encoding, or feature disabled.         |

`415` responses follow the standard error envelope with one of these
`errorCode` values:

- `REQ_COMPRESSION_DISABLED`
- `REQ_COMPRESSION_UNSUPPORTED`
- `REQ_COMPRESSION_STACKED`

## Tests

Behaviour is covered by
`src/common/middleware/request-decompression.middleware.spec.ts`, including
zip-bomb rejection (gzip and deflate payloads that inflate past the limit must
return **413**) and unsupported/disabled-encoding handling.

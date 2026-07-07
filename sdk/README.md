# Nestera Typed SDK

Generated TypeScript SDK for the Nestera backend OpenAPI contract.

## Workflow

1. Generate the versioned OpenAPI documents from `backend/`.
2. Generate the typed SDK in `sdk/src/generated`.
3. Generate the SDK into `sdk/src/generated` locally or in CI.
4. CI regenerates the SDK and publishes it as an artifact for downstream consumers.

## Commands

```sh
pnpm run generate:api-sdk
pnpm --dir sdk install
pnpm --dir sdk run verify
```

## Features

- Deterministic generation from `backend/openapi-v2.json`
- Fetch-based client with middleware hooks
- Auth header injection via token/provider support
- Correlation ID propagation using `X-Correlation-Id`
- Request timeout support
- Retry support for idempotent `GET` requests
- Stable typed error helpers based on backend `errorCode`
- SDK metadata that embeds the OpenAPI version

## Example

See `sdk/examples/frontend-consumer.ts`.

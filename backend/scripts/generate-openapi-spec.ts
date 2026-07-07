/**
 * generate-openapi-spec.ts
 *
 * Bootstraps the NestJS app without listening on a port and dumps the
 * OpenAPI document to JSON and YAML files for each supported API version.
 *
 * Usage:
 *   npx ts-node -r tsconfig-paths/register scripts/generate-openapi-spec.ts
 *
 * Output:
 *   openapi-v2.json / openapi-v2.yaml  — v2 (current, stable)
 *   openapi-v1.json / openapi-v1.yaml  — v1 (deprecated, sunset 2026-09-01)
 *   openapi.json / openapi.yaml        — symlink/alias for v2 (backwards compat)
 */

import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { VersioningType } from '@nestjs/common';
import { writeFileSync } from 'fs';
import { join } from 'path';
import { AppModule } from '../src/app.module';
import { ValidationPipe } from '@nestjs/common';
import { PageDto, PaginatedResponseDto } from '../src/common/dto/page.dto';
import { PageMetaDto } from '../src/common/dto/page-meta.dto';
import { PageOptionsDto } from '../src/common/dto/page-options.dto';
import {
  ApiErrorResponseDto,
  ConflictErrorDto,
  ForbiddenErrorDto,
  NotFoundErrorDto,
  UnauthorizedErrorDto,
  ValidationErrorDto,
} from '../src/common/dto/api-error-response.dto';
import { StandardErrorResponseDto } from '../src/common/dto/standard-error-response.dto';
import { TransactionResponseDto } from '../src/modules/transactions/dto/transaction-response.dto';
import {
  VersioningMiddleware,
  CURRENT_VERSION,
} from '../src/common/versioning/versioning.middleware';

const RATE_LIMIT_DESCRIPTION = `
## Authentication

All protected endpoints require a **Bearer JWT** in the \`Authorization\` header:

\`\`\`
Authorization: Bearer <token>
\`\`\`

Obtain a token via:
- \`POST /api/v2/auth/register\` — email/password registration
- \`POST /api/v2/auth/login\` — email/password login
- \`POST /api/v2/auth/verify-signature\` — Stellar wallet login (Web3)

---

## Rate Limits

| Tier       | Default (req/min) | Auth (req/15 min) | RPC (req/min) |
|------------|:-----------------:|:-----------------:|:-------------:|
| Free       | 60                | 5                 | 5             |
| Verified   | 150               | 10                | 15            |
| Premium    | 300               | 15                | 30            |
| Enterprise | 1000              | 30                | 100           |
| Admin      | 1000              | 50                | 100           |

**Rate limit response headers:** \`X-RateLimit-Limit\`, \`X-RateLimit-Tier\`, \`X-RateLimit-Remaining\`, \`X-RateLimit-Reset\`, \`Retry-After\`

---

## Common Error Codes

| HTTP | Meaning |
|------|---------|
| 400  | Validation failure |
| 401  | Missing or invalid JWT |
| 403  | Insufficient permissions |
| 404  | Resource not found |
| 409  | Conflict |
| 429  | Rate limit exceeded |
| 503  | Service temporarily unavailable |
`;

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortObject(entry));
  }

  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>)
      .sort((left, right) => left.localeCompare(right))
      .reduce<Record<string, unknown>>((acc, key) => {
        acc[key] = sortObject((value as Record<string, unknown>)[key]);
        return acc;
      }, {});
  }

  return value;
}

async function generate() {
  const app = await NestFactory.create(AppModule, { logger: false });

  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: CURRENT_VERSION,
  });

  const versioningMiddleware = new VersioningMiddleware();
  app.use(versioningMiddleware.use.bind(versioningMiddleware));

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  const outDir = join(__dirname, '..');

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const yaml = require('js-yaml') as typeof import('js-yaml');

  for (const version of ['1', '2']) {
    const isDeprecated = version === '1';

    const config = new DocumentBuilder()
      .setTitle(`Nestera API v${version}`)
      .setDescription(
        isDeprecated
          ? `> ⚠️ **DEPRECATED** — Sunset: 2026-09-01. Migrate to v2.\n\n${RATE_LIMIT_DESCRIPTION}`
          : `Nestera decentralized savings & investment platform API.\n\n${RATE_LIMIT_DESCRIPTION}`,
      )
      .setVersion(version)
      .setContact('Nestera', 'https://nestera.io', 'support@nestera.io')
      .setLicense('MIT', 'https://opensource.org/licenses/MIT')
      .addServer('http://localhost:3001', 'Local development')
      .addServer('https://api.nestera.io', 'Production')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT token (without the "Bearer " prefix)',
        },
        'JWT',
      )
      .build();

    const document = SwaggerModule.createDocument(app, config, {
      extraModels: [
        PageDto,
        PaginatedResponseDto,
        PageMetaDto,
        PageOptionsDto,
        TransactionResponseDto,
        StandardErrorResponseDto,
        ApiErrorResponseDto,
        ValidationErrorDto,
        UnauthorizedErrorDto,
        ForbiddenErrorDto,
        NotFoundErrorDto,
        ConflictErrorDto,
      ],
    });

    const sortedDocument = sortObject(document);

    const jsonPath = join(outDir, `openapi-v${version}.json`);
    writeFileSync(jsonPath, JSON.stringify(sortedDocument, null, 2), 'utf-8');
    console.log(`✅  OpenAPI v${version} JSON  → ${jsonPath}`);

    const yamlPath = join(outDir, `openapi-v${version}.yaml`);
    writeFileSync(
      yamlPath,
      yaml.dump(sortedDocument, { lineWidth: 120, sortKeys: true }),
      'utf-8',
    );
    console.log(`✅  OpenAPI v${version} YAML  → ${yamlPath}`);
  }

  // Backwards-compat aliases (openapi.json / openapi.yaml point to v2)
  for (const ext of ['json', 'yaml']) {
    const src = join(outDir, `openapi-v2.${ext}`);
    const dest = join(outDir, `openapi.${ext}`);
    // Read and re-write rather than symlink for cross-platform portability
    const { readFileSync } = await import('fs');
    writeFileSync(dest, readFileSync(src, 'utf-8'), 'utf-8');
    console.log(`✅  openapi.${ext} alias       → ${dest}`);
  }

  await app.close();
  console.log(
    '\nDone. Import openapi.json into Postman / Insomnia for interactive testing.',
  );
}

generate().catch((err) => {
  console.error('Failed to generate OpenAPI spec:', err);
  process.exit(1);
});

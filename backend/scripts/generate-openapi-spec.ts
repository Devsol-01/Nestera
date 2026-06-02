/**
 * generate-openapi-spec.ts
 *
 * Bootstraps the NestJS app without listening on a port and dumps the
 * OpenAPI document to JSON and YAML files.
 *
 * Usage:
 *   npx ts-node -r tsconfig-paths/register scripts/generate-openapi-spec.ts
 *
 * Output:
 *   openapi.json   — machine-readable spec (import into Postman, Insomnia, etc.)
 *   openapi.yaml   — human-readable spec
 */

import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { writeFileSync } from 'fs';
import { join } from 'path';
import { AppModule } from '../src/app.module';
import { ValidationPipe } from '@nestjs/common';
import { PageDto } from '../src/common/dto/page.dto';
import { PageMetaDto } from '../src/common/dto/page-meta.dto';
import { TransactionResponseDto } from '../src/modules/transactions/dto/transaction-response.dto';

async function generate() {
  const app = await NestFactory.create(AppModule, { logger: false });

  app.setGlobalPrefix('api');
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  const config = new DocumentBuilder()
    .setTitle('Nestera API')
    .setDescription(
      'Nestera is a decentralized savings & investment platform on Stellar. ' +
        'Amounts include currency metadata and use currency-specific precision.',
    )
    .setVersion('2')
    .setContact(
      'Nestera Team',
      'https://github.com/Devsol-01/Nestera',
      'support@nestera.io',
    )
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .addServer('http://localhost:3001', 'Local development')
    .addServer('https://api.nestera.io', 'Production')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config, {
    extraModels: [PageDto, PageMetaDto, TransactionResponseDto],
  });

  const outDir = join(__dirname, '..');

  // JSON
  const jsonPath = join(outDir, 'openapi.json');
  writeFileSync(jsonPath, JSON.stringify(document, null, 2), 'utf-8');
  console.log(`✅  OpenAPI JSON written to ${jsonPath}`);

  // YAML (built-in js-yaml is available via @nestjs/swagger)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const yaml = require('js-yaml') as typeof import('js-yaml');
  const yamlPath = join(outDir, 'openapi.yaml');
  writeFileSync(yamlPath, yaml.dump(document, { lineWidth: 120 }), 'utf-8');
  console.log(`✅  OpenAPI YAML written to ${yamlPath}`);

  await app.close();
}

generate().catch((err) => {
  console.error('Failed to generate OpenAPI spec:', err);
  process.exit(1);
});

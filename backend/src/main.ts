import { NestFactory } from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import {
  VersioningMiddleware,
  CURRENT_VERSION,
} from './common/versioning/versioning.middleware';
import { VersionAnalyticsInterceptor } from './common/versioning/version-analytics.interceptor';
import { VersionAnalyticsService } from './common/versioning/version-analytics.service';
import { GracefulShutdownService } from './common/services/graceful-shutdown.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));
  const configService = app.get(ConfigService);
  const port = configService.get<number>('port');

  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: CURRENT_VERSION,
  });

  // Register header-based version negotiation + deprecation warnings
  const versioningMiddleware = new VersioningMiddleware();
  app.use(versioningMiddleware.use.bind(versioningMiddleware));

  // Register version analytics interceptor globally
  const versionAnalytics = app.get(VersionAnalyticsService);
  app.useGlobalInterceptors(new VersionAnalyticsInterceptor(versionAnalytics));

  app.useGlobalFilters(new AllExceptionsFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Swagger setup — one document per supported version + canonical /api/docs
  const swaggerBearerAuth = {
    type: 'http' as const,
    scheme: 'bearer',
    bearerFormat: 'JWT',
    description:
      'Enter the JWT access token returned by POST /api/v2/auth/login or POST /api/v2/auth/verify-signature.',
  };

  const sharedDescription = [
    '## Authentication',
    'Most endpoints require a Bearer JWT. Obtain one via:',
    '- `POST /api/v2/auth/login` — email/password',
    '- `POST /api/v2/auth/verify-signature` — Stellar wallet signature',
    '',
    '## Rate Limiting',
    '| Tier | Limit | Window | Applies to |',
    '|------|-------|--------|------------|',
    '| `general` | 100 req | 1 min | All routes |',
    '| `auth` | 5 req | 15 min | Login, register, nonce, verify |',
    '| `rpc` | 10–30 req | 1 min | On-chain read routes |',
    '',
    'Rate-limited responses return **HTTP 429** with a `Retry-After` header.',
    '',
    '## Common Error Responses',
    '| Status | Meaning |',
    '|--------|---------|',
    '| 400 | Validation failure — check the `message` array |',
    '| 401 | Missing or invalid JWT |',
    '| 403 | Insufficient role (admin routes) |',
    '| 404 | Resource not found |',
    '| 429 | Rate limit exceeded |',
    '| 500 | Internal server error |',
  ].join('\n');

  for (const version of ['1', '2']) {
    const isDeprecated = version === '1';
    const swaggerConfig = new DocumentBuilder()
      .setTitle('Nestera API')
      .setDescription(
        `${isDeprecated ? '**⚠️ v1 is DEPRECATED — Sunset: 2026-09-01. Please migrate to v2.**\n\n' : ''}${sharedDescription}`,
      )
      .setVersion(version)
      .setContact('Nestera Team', 'https://github.com/Devsol-01/Nestera', '')
      .setLicense('MIT', 'https://opensource.org/licenses/MIT')
      .addBearerAuth(swaggerBearerAuth)
      .addTag('auth', 'Authentication — register, login, 2FA, wallet linking')
      .addTag(
        'savings',
        'Savings products, subscriptions, goals, auto-deposits',
      )
      .addTag('users', 'User profile, avatar, KYC documents, net worth')
      .addTag('Transactions', 'Transaction history, CSV export, tagging')
      .addTag(
        'analytics',
        'Portfolio timeline, asset allocation, yield breakdown',
      )
      .addTag('notifications', 'In-app notifications and preferences')
      .addTag('referrals', 'Referral codes and stats')
      .addTag('rewards', 'Leaderboards and reward visibility')
      .addTag('governance', 'Voting power, delegation')
      .addTag('kyc', 'KYC verification flow and compliance')
      .addTag('claims', 'Medical claims submission and verification')
      .addTag('disputes', 'Dispute creation and resolution')
      .addTag(
        'Blockchain',
        'Stellar on-chain data, wallet generation, RPC status',
      )
      .addTag('admin', 'Admin-only user and KYC management')
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup(`api/v${version}/docs`, app, document);

    // Canonical /api/docs always points to v2
    if (version === '2') {
      SwaggerModule.setup('api/docs', app, document);
    }
  }

  const server = await app.listen(port || 3001);
  const logger = app.get(Logger);
  logger.log(`Application is running on: http://localhost:${port}/api`);
  logger.log(`Swagger docs (canonical): http://localhost:${port}/api/docs`);
  logger.log(
    `Swagger v1 docs (deprecated): http://localhost:${port}/api/v1/docs`,
  );
  logger.log(`Swagger v2 docs: http://localhost:${port}/api/v2/docs`);

  // Setup graceful shutdown
  const gracefulShutdown = app.get(GracefulShutdownService);

  const signals = ['SIGTERM', 'SIGINT'];
  signals.forEach((signal) => {
    process.on(signal, async () => {
      logger.log(`Received ${signal}, starting graceful shutdown...`);
      server.close(async () => {
        await app.close();
        process.exit(0);
      });
    });
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
  });
}

bootstrap().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[Bootstrap] Application startup failed: ${message}`);
  process.exit(1);
});

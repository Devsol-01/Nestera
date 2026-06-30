import { NestFactory } from '@nestjs/core';
import {
  INestApplication,
  ValidationPipe,
  VersioningType,
  BadRequestException,
} from '@nestjs/common';
import compression from 'compression';
import helmet from 'helmet';
import express from 'express';
import { constants as zlibConstants } from 'zlib';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { EnhancedExceptionFilter } from './common/filters/enhanced-exception.filter';
import { ErrorCodeRegistry } from './common/services/error-code-registry.service';
import { ContractValidationService } from './common/services/contract-validation.service';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import {
  VersioningMiddleware,
  CURRENT_VERSION,
} from './common/versioning/versioning.middleware';
import { VersionAnalyticsInterceptor } from './common/versioning/version-analytics.interceptor';
import { VersionAnalyticsService } from './common/versioning/version-analytics.service';
import { GracefulShutdownService } from './common/services/graceful-shutdown.service';
import { ContractCompatibilityService } from './common/services/contract-compatibility.service';
import type { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';
import { flattenValidationErrors } from './common/validators/validation-error.utils';
import type { ValidationError as ClassValidatorError } from 'class-validator';

type AppCorsConfig = {
  enabled: boolean;
  origins: string[];
  methods: string[];
  allowedHeaders: string[];
  credentials: boolean;
  maxAge: number;
};

async function flushApplicationLogs(
  app: INestApplication,
  logger: Logger,
): Promise<void> {
  const nestApp = app as INestApplication & {
    flushLogs?: () => Promise<void> | void;
  };

  if (typeof nestApp.flushLogs === 'function') {
    await Promise.resolve(nestApp.flushLogs());
    return;
  }

  const pinoLogger = logger as Logger & {
    flush?: () => void;
    logger?: { flush?: () => void };
  };

  pinoLogger.flush?.();
  pinoLogger.logger?.flush?.();
  await new Promise((resolve) => setTimeout(resolve, 50));
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));
  const configService = app.get(ConfigService);
  const port = configService.get<number>('port');
  const corsConfig = configService.get<AppCorsConfig>('cors');

  // Perform contract-backend compatibility check on startup
  try {
    const contractCompatibility = app.get(ContractCompatibilityService);
    await contractCompatibility.performStartupCheck();
  } catch (error) {
    console.error(
      '[Bootstrap] Contract compatibility check failed. Application will exit.',
      error,
    );
    process.exit(1);
  }

  // API Response Compression with brotli support and binary payload exclusion
  const compressionThreshold = parseInt(
    process.env.COMPRESSION_THRESHOLD || '1024',
    10,
  );
  app.use(
    compression({
      threshold: compressionThreshold,
      brotli: {
        params: {
          [zlibConstants.BROTLI_PARAM_QUALITY]: 4,
        },
      },
      filter: (req, res) => {
        const contentType = res.getHeader('Content-Type') as string;
        // Don't compress binary payloads
        if (
          contentType?.includes('application/pdf') ||
          contentType?.includes('image/') ||
          contentType?.includes('video/') ||
          contentType?.includes('audio/') ||
          contentType?.includes('application/octet-stream')
        ) {
          return false;
        }
        return compression.filter(req, res);
      },
    }),
  );

  // Request body size limits
  const jsonBodyLimit = process.env.JSON_BODY_LIMIT || '1mb';
  const urlencodedLimit = process.env.URLENCODED_BODY_LIMIT || '1mb';
  app.use(express.json({ limit: jsonBodyLimit }));
  app.use(express.urlencoded({ limit: urlencodedLimit, extended: true }));

  app.use(
    helmet({
      // API serves JSON; disable CSP to avoid breaking Swagger UI assets.
      contentSecurityPolicy: false,
      frameguard: { action: 'deny' }, // clickjacking protection
      noSniff: true, // MIME sniffing protection
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginResourcePolicy: { policy: 'same-site' },
    }),
  );
  app.use((_req, res, next) => {
    // Legacy browser signal for additional reflected-XSS mitigation.
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  if (corsConfig?.enabled) {
    const allowedOrigins = corsConfig.origins;
    const methods = corsConfig.methods;
    const allowedHeaders = corsConfig.allowedHeaders;
    const credentials =
      corsConfig.credentials &&
      !allowedOrigins.some((origin) => origin === '*');

    const corsOptions: CorsOptions = {
      origin: (origin, callback) => {
        // Allow non-browser clients (no Origin header).
        if (!origin) {
          callback(null, true);
          return;
        }

        if (allowedOrigins.includes(origin)) {
          callback(null, true);
          return;
        }

        callback(new Error(`Origin ${origin} is not allowed by CORS`), false);
      },
      credentials,
      methods,
      allowedHeaders,
      optionsSuccessStatus: 204,
      maxAge: corsConfig.maxAge,
    };

    app.enableCors(corsOptions);
  }

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

  // Register enhanced exception filter with error code registry
  const errorRegistry = new ErrorCodeRegistry();
  app.useGlobalFilters(new EnhancedExceptionFilter(errorRegistry));
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const result = flattenValidationErrors(errors as ClassValidatorError[]);
        return new BadRequestException({
          message: 'Validation failed',
          errors: result,
        });
      },
    }),
  );

  // Swagger / OpenAPI setup
  const rateLimitDescription = `
## Authentication

All protected endpoints require a **Bearer JWT** in the \`Authorization\` header:

\`\`\`
Authorization: Bearer <token>
\`\`\`

Obtain a token via:
- \`POST /api/v2/auth/register\` — email/password registration
- \`POST /api/v2/auth/login\` — email/password login
- \`POST /api/v2/auth/verify-signature\` — Stellar wallet login (Web3)

If 2FA is enabled, complete login via \`POST /api/v2/auth/2fa/validate\`.

---

## Rate Limits

Rate limits are enforced per **user tier** and returned in response headers:

| Tier       | Default (req/min) | Auth (req/15 min) | RPC (req/min) |
|------------|:-----------------:|:-----------------:|:-------------:|
| Free       | 60                | 5                 | 5             |
| Verified   | 150               | 10                | 15            |
| Premium    | 300               | 15                | 30            |
| Enterprise | 1000              | 30                | 100           |
| Admin      | 1000              | 50                | 100           |

**Headers returned on every response:**
- \`X-RateLimit-Limit\` — current limit for the active throttler
- \`X-RateLimit-Tier\` — resolved tier for the request
- \`X-RateLimit-Remaining\` — requests remaining (set on 429)
- \`X-RateLimit-Reset\` — ISO timestamp when the window resets (set on 429)
- \`Retry-After\` — seconds to wait before retrying (set on 429)

---

## Versioning

The API supports URI-based versioning (\`/api/v1/...\` and \`/api/v2/...\`).

> ⚠️ **v1 is deprecated** and will be sunset on **2026-09-01**. Migrate to v2.

---

## Common Error Codes

| HTTP Status | Meaning                          |
|-------------|----------------------------------|
| 400         | Bad request / validation failure |
| 401         | Missing or invalid JWT           |
| 403         | Insufficient permissions (RBAC)  |
| 404         | Resource not found               |
| 409         | Conflict (e.g. duplicate wallet) |
| 429         | Rate limit exceeded              |
| 503         | Service temporarily unavailable  |
`;

  for (const version of ['1', '2']) {
    const isDeprecated = version === '1';
    const swaggerConfig = new DocumentBuilder()
      .setTitle(`Nestera API v${version}`)
      .setDescription(
        isDeprecated
          ? `> ⚠️ **DEPRECATED** — Sunset: 2026-09-01. Migrate to v2.\n\n${rateLimitDescription}`
          : `Nestera decentralized savings & investment platform API.\n\n${rateLimitDescription}`,
      )
      .setVersion(version)
      .addBearerAuth()
      .addApiKey(
        { type: 'apiKey', name: 'X-API-Version', in: 'header' },
        'api-version',
      )
      .setContact('Nestera', 'https://nestera.io', 'support@nestera.io')
      .setLicense('MIT', 'https://opensource.org/licenses/MIT')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT token (without the "Bearer " prefix)',
        },
        'JWT',
      )
      .addServer(`http://localhost:${port || 3001}`, 'Local development')
      .build();
    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup(`api/v${version}/docs`, app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'alpha',
        docExpansion: 'none',
        filter: true,
        showRequestDuration: true,
      },
      customSiteTitle: `Nestera API v${version} Docs`,
    });
  }

  // Combined Swagger doc at /api/docs
  const combinedConfig = new DocumentBuilder()
    .setTitle('Nestera API')
    .setDescription(
      'Nestera platform API — all versions. ' +
        'Use the versioned docs at /api/v1/docs or /api/v2/docs for version-specific views.',
    )
    .setVersion(CURRENT_VERSION)
    .addBearerAuth()
    .build();
  const combinedDoc = SwaggerModule.createDocument(app, combinedConfig);
  SwaggerModule.setup('api/docs', app, combinedDoc);

  app.enableShutdownHooks();
  await app.listen(port || 3001);
  const logger = app.get(Logger);
  const gracefulShutdown = app.get(GracefulShutdownService);
  gracefulShutdown.registerHttpServer(app.getHttpServer());
  logger.log(`Application is running on: http://localhost:${port}/api`);
  logger.log(`Swagger docs (current):    http://localhost:${port}/api/docs`);
  logger.log(`Swagger v1 docs:           http://localhost:${port}/api/v1/docs`);
  logger.log(`Swagger v2 docs:           http://localhost:${port}/api/v2/docs`);

  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT'];
  for (const signal of signals) {
    process.once(signal, () => {
      void gracefulShutdown
        .shutdownApplication(
          signal,
          () => app.close(),
          () => flushApplicationLogs(app, logger),
        )
        .then((exitCode) => {
          process.exit(exitCode);
        });
    });
  }

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

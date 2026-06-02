import { Module, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { CorrelationIdInterceptor } from './common/interceptors/correlation-id.interceptor';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { RequestLoggingInterceptor } from './common/interceptors/request-logging.interceptor';
import { GracefulShutdownInterceptor } from './common/interceptors/graceful-shutdown.interceptor';
import { TieredThrottlerGuard } from './common/guards/tiered-throttler.guard';
import { CommonModule } from './common/common.module';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { LoggerModule } from 'nestjs-pino';
import * as Joi from 'joi';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import configuration from './config/configuration';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { HealthModule } from './modules/health/health.module';
import { BlockchainModule } from './modules/blockchain/blockchain.module';
import { UserModule } from './modules/user/user.module';
import { KycModule } from './modules/kyc/kyc.module';
import { ChallengesModule } from './modules/challenges/challenges.module';
import { AlertsModule } from './modules/alerts/alerts.module';
import { AdminModule } from './modules/admin/admin.module';
import { MailModule } from './modules/mail/mail.module';
import { CacheModule } from './modules/cache/cache.module';
import { WebhooksModule } from './modules/webhooks/webhooks.module';
import { ClaimsModule } from './modules/claims/claims.module';
import { DisputesModule } from './modules/disputes/disputes.module';
import { AdminAnalyticsModule } from './modules/admin-analytics/admin-analytics.module';
import { AnalyticsModule } from './modules/analytics/analytics.module';
import { SavingsModule } from './modules/savings/savings.module';
import { GovernanceModule } from './modules/governance/governance.module';
import { NotificationsModule } from './modules/notifications/notifications.module';
import { TransactionsModule } from './modules/transactions/transactions.module';
import { ReportsModule } from './modules/reports/reports.module';
import { ReferralsModule } from './modules/referrals/referrals.module';
import { CurrencyModule } from './modules/currency/currency.module';
import { TestRbacModule } from './test-rbac/test-rbac.module';
import { TestThrottlingModule } from './test-throttling/test-throttling.module';
import { ApiVersioningModule } from './common/versioning/api-versioning.module';
import { BackupModule } from './modules/backup/backup.module';
import { DataExportModule } from './modules/data-export/data-export.module';
import { ConnectionPoolModule } from './common/database/connection-pool.module';
import { CircuitBreakerModule } from './common/circuit-breaker/circuit-breaker.module';
import { PostmanModule } from './common/postman/postman.module';
import { CorrelationIdMiddleware } from './common/middleware/correlation-id.middleware';
import { PerformanceModule } from './modules/performance/performance.module';
import { GracefulShutdownService } from './common/services/graceful-shutdown.service';

const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  PORT: Joi.number().port().default(3001).required(),

  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().port().required(),
  DB_NAME: Joi.string().optional(),
  DB_USER: Joi.string().optional(),
  DB_PASS: Joi.string().optional(),
  DATABASE_URL: Joi.string().uri().optional(),

  JWT_SECRET: Joi.string().min(10).required(),
  JWT_EXPIRATION: Joi.string().required(),

  STELLAR_NETWORK: Joi.string().valid('testnet', 'mainnet').default('testnet'),
  SOROBAN_RPC_URL: Joi.string().uri().required(),
  HORIZON_URL: Joi.string().uri().required(),
  SOROBAN_RPC_FALLBACK_URLS: Joi.string().required(),
  HORIZON_FALLBACK_URLS: Joi.string().required(),

  CONTRACT_ID: Joi.string().required(),
  STELLAR_WEBHOOK_SECRET: Joi.string().min(16).required(),
  STELLAR_EVENT_POLL_INTERVAL: Joi.number().integer().min(1000).default(10000),

  RPC_MAX_RETRIES: Joi.number().integer().min(0).default(3),
  RPC_RETRY_DELAY: Joi.number().integer().min(0).default(1000),
  RPC_TIMEOUT: Joi.number().integer().min(0).default(10000),

  REDIS_URL: Joi.string().uri().optional(),
  MAIL_HOST: Joi.string().optional(),
  MAIL_PORT: Joi.number().port().default(587),
  MAIL_USER: Joi.string().optional(),
  MAIL_PASS: Joi.string().optional(),
  MAIL_FROM: Joi.string().optional(),
  KYC_PROVIDER_BASE_URL: Joi.string().uri().optional(),
  KYC_PROVIDER_API_KEY: Joi.string().optional(),
  KYC_PII_ENCRYPTION_KEY: Joi.string().min(16).optional(),

  BACKUP_S3_BUCKET: Joi.string().optional(),
  BACKUP_S3_REGION: Joi.string().optional(),
  BACKUP_AWS_ACCESS_KEY_ID: Joi.string().optional(),
  BACKUP_AWS_SECRET_ACCESS_KEY: Joi.string().optional(),
  BACKUP_ENCRYPTION_KEY: Joi.string().length(64).optional(), // 32-byte key as hex
  BACKUP_RETENTION_DAYS: Joi.number().integer().min(1).default(30).optional(),
  BACKUP_TMP_DIR: Joi.string().optional(),
  BASE_CURRENCY: Joi.string()
    .valid('USDC', 'USDT', 'XLM', 'EURC')
    .default('USDC'),
  CURRENCY_CONFIG_JSON: Joi.string().optional(),
});

@Module({
  imports: [
    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const isProduction =
          configService.get<string>('NODE_ENV') === 'production';
        return {
          pinoHttp: {
            transport: isProduction
              ? undefined
              : { target: 'pino-pretty', options: { singleLine: true } },
            level: isProduction ? 'info' : 'debug',
          },
        };
      },
    }),
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema: envValidationSchema,
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
      validate: (config) => {
        const { error, value } = envValidationSchema.validate(config, {
          allowUnknown: true,
          abortEarly: false,
        });

        if (error) {
          const issues = error.details
            .map((detail) => `- ${detail.message}`)
            .join('\n');
          console.error(
            `[Config] Environment validation failed. Application will exit.\n${issues}`,
          );
          process.exit(1);
        }

        return value;
      },
    }),
    EventEmitterModule.forRoot(),
    ScheduleModule.forRoot(),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const dbUrl = configService.get<string>('database.url');
        const dbHost = configService.get<string>('database.host');

        if (dbUrl) {
          // URL-based connection (e.g. DATABASE_URL on cloud platforms)
          return {
            type: 'postgres' as const,
            url: dbUrl,
            autoLoadEntities: true,
            synchronize: configService.get<string>('NODE_ENV') !== 'production',
          };
        }

        // Host-based connection (uses DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS)
        if (!dbHost) {
          throw new Error(
            'Database configuration error: set either DATABASE_URL or DB_HOST in your environment.',
          );
        }

        return {
          type: 'postgres' as const,
          host: dbHost,
          port: configService.get<number>('database.port') ?? 5432,
          database: configService.get<string>('database.name'),
          username: configService.get<string>('database.user'),
          password: configService.get<string>('database.pass'),
          autoLoadEntities: true,
          synchronize: configService.get<string>('NODE_ENV') !== 'production',
        };
      },
    }),
    ScheduleModule.forRoot(),
    AuthModule,
    CacheModule,
    HealthModule,
    BlockchainModule,
    UserModule,
    KycModule,
    ChallengesModule,
    AlertsModule,
    AdminModule,
    MailModule,
    WebhooksModule,
    ClaimsModule,
    DisputesModule,
    AdminAnalyticsModule,
    AnalyticsModule,
    SavingsModule,
    GovernanceModule,
    NotificationsModule,
    TransactionsModule,
    ReportsModule,
    ReferralsModule,
    CurrencyModule,
    TestRbacModule,
    TestThrottlingModule,
    ApiVersioningModule,
    BackupModule,
    DataExportModule,
    ConnectionPoolModule,
    CircuitBreakerModule,
    PostmanModule,
    PerformanceModule,
    CommonModule,
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: 60000,
        limit: 100,
      },
      {
        name: 'auth',
        ttl: 15 * 60 * 1000, // 15 minutes
        limit: 5,
      },
      {
        name: 'rpc',
        ttl: 60000, // 1 minute
        limit: 10,
      },
    ]),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    GracefulShutdownService,
    {
      provide: APP_GUARD,
      useClass: TieredThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: RequestLoggingInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: CorrelationIdInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: GracefulShutdownInterceptor,
    },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}

import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { CorrelationIdInterceptor } from './common/interceptors/correlation-id.interceptor';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { LoggerModule } from 'nestjs-pino';
import * as Joi from 'joi';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import configuration from './config/configuration';
import { createTypeOrmModuleOptions } from './config/typeorm-options.factory';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { HealthModule } from './modules/health/health.module';
import { BlockchainModule } from './modules/blockchain/blockchain.module';
import { UserModule } from './modules/user/user.module';
import { AdminModule } from './modules/admin/admin.module';
import { MailModule } from './modules/mail/mail.module';
import { RedisCacheModule } from './modules/cache/cache.module';
import { WebhooksModule } from './modules/webhooks/webhooks.module';
import { ClaimsModule } from './modules/claims/claims.module';
import { DisputesModule } from './modules/disputes/disputes.module';
import { AdminAnalyticsModule } from './modules/admin-analytics/admin-analytics.module';
import { AnalyticsModule } from './modules/analytics/analytics.module';
import { SavingsModule } from './modules/savings/savings.module';
import { GovernanceModule } from './modules/governance/governance.module';
import { NotificationsModule } from './modules/notifications/notifications.module';
import { TransactionsModule } from './modules/transactions/transactions.module';
import { TestRbacModule } from './test-rbac/test-rbac.module';
import { TestThrottlingModule } from './test-throttling/test-throttling.module';
import { CustomThrottlerGuard } from './common/guards/custom-throttler.guard';

const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  PORT: Joi.number().port().default(3001).required(),

  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().port().required(),
  DB_NAME: Joi.string().optional(),
  DB_USER: Joi.string().optional(),
  DB_PASS: Joi.string().optional(),
  DATABASE_URL: Joi.string().uri().optional(),
  DATABASE_READ_URL: Joi.string().uri().optional(),
  DB_POOL_MAX: Joi.number().integer().min(1).max(500).optional(),
  DB_POOL_MIN: Joi.number().integer().min(0).max(200).optional(),
  DB_POOL_CONNECTION_TIMEOUT_MS: Joi.number().integer().min(0).optional(),
  DB_POOL_IDLE_TIMEOUT_MS: Joi.number().integer().min(0).optional(),

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
});

@Module({
  imports: [
    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const isProduction = configService.get<string>('NODE_ENV') === 'production';
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
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) =>
        createTypeOrmModuleOptions(configService),
    }),
    AuthModule,
    RedisCacheModule,
    HealthModule,
    BlockchainModule,
    UserModule,
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
    TestRbacModule,
    TestThrottlingModule,
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
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: CorrelationIdInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor,
    },
  ],
})
export class AppModule { }

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import configuration from './config/configuration';
import { envValidationSchema } from './config/env.validation';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { HealthModule } from './modules/health/health.module';
import { BlockchainModule } from './modules/blockchain/blockchain.module';
import { UserModule } from './modules/user/user.module';
import { AdminModule } from './modules/admin/admin.module';
import { MailModule } from './modules/mail/mail.module';
// import { RedisCacheModule } from './modules/cache/cache.module';
import { WebhooksModule } from './modules/webhooks/webhooks.module';
import { ClaimsModule } from './modules/claims/claims.module';
import { DisputesModule } from './modules/disputes/disputes.module';
import { AdminAnalyticsModule } from './modules/admin-analytics/admin-analytics.module';
import { SavingsModule } from './modules/savings/savings.module';
import { GovernanceModule } from './modules/governance/governance.module';
import { TestRbacModule } from './test-rbac/test-rbac.module';
import { TestThrottlingModule } from './test-throttling/test-throttling.module';
import { CustomThrottlerGuard } from './common/guards/custom-throttler.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema: envValidationSchema,
      validationOptions: {
        allowUnknown: true,
        abortEarly: true,
      },
    }),
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
    AuthModule,
    // RedisCacheModule,
    HealthModule,
    BlockchainModule,
    UserModule,
    AdminModule,
    MailModule,
    WebhooksModule,
    ClaimsModule,
    DisputesModule,
    AdminAnalyticsModule,
    SavingsModule,
    GovernanceModule,
    TestRbacModule,
    TestThrottlingModule,
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 100,
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
  ],
})
export class AppModule {}

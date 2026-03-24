import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AdminAnalyticsModule } from '../src/modules/admin-analytics/admin-analytics.module';
import { ClaimsModule } from '../src/modules/claims/claims.module';
import { DisputesModule } from '../src/modules/disputes/disputes.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MedicalClaim } from '../src/modules/claims/entities/medical-claim.entity';
import { Dispute, DisputeMessage } from '../src/modules/disputes/entities/dispute.entity';
import { RolesGuard } from '../src/common/guards/roles.guard';

describe('Admin Analytics E2E', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'postgres',
          host: 'localhost',
          port: 5432,
          username: 'test',
          password: 'test',
          database: 'test_db',
          entities: [MedicalClaim, Dispute, DisputeMessage],
          synchronize: true,
        }),
        ClaimsModule,
        DisputesModule,
        AdminAnalyticsModule,
      ],
    })
      .overrideGuard(RolesGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /admin/analytics/overview', () => {
    it('should return analytics overview', () => {
      return request(app.getHttpServer())
        .get('/admin/analytics/overview')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('totalProcessedSweeps');
          expect(res.body).toHaveProperty('activeDisputes');
          expect(res.body).toHaveProperty('pendingMedicalClaims');
          expect(res.body).toHaveProperty('totalUsers');
          expect(res.body).toHaveProperty('totalClaimAmount');
        });
    });
  });
});

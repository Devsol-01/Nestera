import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { DisputesModule } from '../src/modules/disputes/disputes.module';
import { ClaimsModule } from '../src/modules/claims/claims.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Dispute, DisputeMessage } from '../src/modules/disputes/entities/dispute.entity';
import { MedicalClaim } from '../src/modules/claims/entities/medical-claim.entity';

describe('Disputes E2E', () => {
  let app: INestApplication;
  let claimId: string;

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
          entities: [Dispute, DisputeMessage, MedicalClaim],
          synchronize: true,
        }),
        ClaimsModule,
        DisputesModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    await app.init();

    // Create a claim first
    const claimResponse = await request(app.getHttpServer())
      .post('/claims')
      .send({
        patientName: 'Test Patient',
        patientId: 'PAT-TEST',
        patientDateOfBirth: '1990-01-01',
        hospitalName: 'Test Hospital',
        hospitalId: 'HOSP-TEST01',
        diagnosisCodes: ['A09'],
        claimAmount: 1000,
      });
    claimId = claimResponse.body.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /disputes', () => {
    it('should create dispute for valid claim', () => {
      return request(app.getHttpServer())
        .post('/disputes')
        .send({
          claimId,
          disputedBy: 'Hospital Admin',
          reason: 'Claim amount was incorrectly calculated',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.status).toBe('OPEN');
        });
    });

    it('should reject invalid claim ID', () => {
      return request(app.getHttpServer())
        .post('/disputes')
        .send({
          claimId: 'invalid-uuid',
          disputedBy: 'User',
          reason: 'Test reason',
        })
        .expect(400);
    });
  });

  describe('GET /disputes', () => {
    it('should return all disputes', () => {
      return request(app.getHttpServer())
        .get('/disputes')
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });
  });

  describe('PATCH /disputes/:id', () => {
    it('should update dispute status', async () => {
      const createRes = await request(app.getHttpServer())
        .post('/disputes')
        .send({
          claimId,
          disputedBy: 'Admin',
          reason: 'Test dispute',
        });

      return request(app.getHttpServer())
        .patch(`/disputes/${createRes.body.id}`)
        .send({ status: 'UNDER_REVIEW' })
        .expect(200)
        .expect((res) => {
          expect(res.body.status).toBe('UNDER_REVIEW');
        });
    });
  });

  describe('POST /disputes/:id/messages', () => {
    it('should add message to dispute', async () => {
      const createRes = await request(app.getHttpServer())
        .post('/disputes')
        .send({
          claimId,
          disputedBy: 'Admin',
          reason: 'Test',
        });

      return request(app.getHttpServer())
        .post(`/disputes/${createRes.body.id}/messages`)
        .send({
          author: 'Support Team',
          message: 'We are reviewing your case',
          evidenceUrl: 'https://example.com/evidence.pdf',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.message).toBe('We are reviewing your case');
        });
    });
  });
});

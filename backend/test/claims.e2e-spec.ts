import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { ClaimsModule } from '../src/modules/claims/claims.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MedicalClaim } from '../src/modules/claims/entities/medical-claim.entity';

describe('Claims E2E', () => {
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
          entities: [MedicalClaim],
          synchronize: true,
        }),
        ClaimsModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /claims', () => {
    it('should submit a valid claim', () => {
      return request(app.getHttpServer())
        .post('/claims')
        .send({
          patientName: 'Jane Smith',
          patientId: 'PAT-456789',
          patientDateOfBirth: '1985-05-20',
          hospitalName: 'General Hospital',
          hospitalId: 'HOSP-GH2024',
          diagnosisCodes: ['J18.9', 'A09'],
          claimAmount: 2500.75,
          notes: 'Emergency treatment',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.status).toBe('PENDING');
          expect(res.body.patientName).toBe('Jane Smith');
        });
    });

    it('should reject invalid diagnosis codes', () => {
      return request(app.getHttpServer())
        .post('/claims')
        .send({
          patientName: 'John Doe',
          patientId: 'PAT-123',
          patientDateOfBirth: '1990-01-15',
          hospitalName: 'City Hospital',
          hospitalId: 'HOSP-ABC123',
          diagnosisCodes: ['INVALID'],
          claimAmount: 1000,
        })
        .expect(400);
    });

    it('should reject invalid hospital ID format', () => {
      return request(app.getHttpServer())
        .post('/claims')
        .send({
          patientName: 'John Doe',
          patientId: 'PAT-123',
          patientDateOfBirth: '1990-01-15',
          hospitalName: 'City Hospital',
          hospitalId: 'INVALID-ID',
          diagnosisCodes: ['A09'],
          claimAmount: 1000,
        })
        .expect(400);
    });

    it('should reject negative claim amounts', () => {
      return request(app.getHttpServer())
        .post('/claims')
        .send({
          patientName: 'John Doe',
          patientId: 'PAT-123',
          patientDateOfBirth: '1990-01-15',
          hospitalName: 'City Hospital',
          hospitalId: 'HOSP-ABC123',
          diagnosisCodes: ['A09'],
          claimAmount: -100,
        })
        .expect(400);
    });
  });
});

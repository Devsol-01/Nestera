import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { HospitalIntegrationService } from './hospital-integration.service';
import { of, throwError } from 'rxjs';
import { AxiosResponse, AxiosError } from 'axios';
import { HttpException, HttpStatus } from '@nestjs/common';

describe('HospitalIntegrationService', () => {
    let service: HospitalIntegrationService;
    let httpService: HttpService;
    let configService: ConfigService;

    const mockClaimData = {
        claimId: 'claim-123',
        patient: {
            patientId: 'patient-456',
            name: 'John Doe',
            dateOfBirth: '1990-01-01',
        },
        diagnoses: [{ code: 'A00', description: 'Test diagnosis' }],
        treatments: [{ treatmentId: 'tx-1', description: 'Test treatment', cost: 1000, date: '2024-01-01' }],
        totalAmount: 1000,
        admissionDate: '2024-01-01',
        hospitalId: 'hospital-1',
        hospitalName: 'Test Hospital',
        status: 'verified' as const,
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                HospitalIntegrationService,
                {
                    provide: HttpService,
                    useValue: {
                        get: jest.fn(),
                    },
                },
                {
                    provide: ConfigService,
                    useValue: {
                        get: jest.fn((key: string, defaultValue?: any) => {
                            const config = {
                                'hospital.endpoints.hospital-1': 'https://api.hospital1.com',
                                'hospital.maxRetries': 3,
                                'hospital.retryDelay': 100,
                                'hospital.requestTimeout': 5000,
                                'hospital.circuitBreakerThreshold': 5,
                                'hospital.circuitBreakerTimeout': 60000,
                            };
                            return config[key] ?? defaultValue;
                        }),
                    },
                },
            ],
        }).compile();

        service = module.get<HospitalIntegrationService>(HospitalIntegrationService);
        httpService = module.get<HttpService>(HttpService);
        configService = module.get<ConfigService>(ConfigService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('fetchClaimData', () => {
        it('should successfully fetch claim data', async () => {
            const mockResponse: AxiosResponse = {
                data: mockClaimData,
                status: 200,
                statusText: 'OK',
                headers: {},
                config: {} as any,
            };

            jest.spyOn(httpService, 'get').mockReturnValue(of(mockResponse));

            const result = await service.fetchClaimData('hospital-1', 'claim-123');

            expect(result).toEqual(mockClaimData);
            expect(httpService.get).toHaveBeenCalledWith(
                'https://api.hospital1.com/claims/claim-123',
                undefined,
            );
        });

        it('should throw error for unconfigured hospital', async () => {
            await expect(
                service.fetchClaimData('unknown-hospital', 'claim-123'),
            ).rejects.toThrow(HttpException);
        });
    });

    describe('circuit breaker', () => {
        it('should open circuit after threshold failures', async () => {
            const error = new Error('Network error') as AxiosError;
            jest.spyOn(httpService, 'get').mockReturnValue(throwError(() => error));

            // Trigger failures up to threshold
            for (let i = 0; i < 5; i++) {
                try {
                    await service.fetchClaimData('hospital-1', 'claim-123');
                } catch (e) {
                    // Expected to fail
                }
            }

            const status = service.getCircuitBreakerStatus('hospital-1');
            expect(status.state).toBe('OPEN');
        });

        it('should reset circuit breaker manually', () => {
            service.resetCircuitBreaker('hospital-1');
            const status = service.getCircuitBreakerStatus('hospital-1');

            expect(status.state).toBe('CLOSED');
            expect(status.failures).toBe(0);
        });
    });
});

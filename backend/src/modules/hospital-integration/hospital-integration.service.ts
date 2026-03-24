import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';
import { catchError, retry, timeout, map } from 'rxjs/operators';
import { Observable, throwError, timer, firstValueFrom } from 'rxjs';
import {
  HospitalClaimDataDto,
  HospitalVerificationDto,
} from './dto/hospital-data.dto';

export interface CircuitBreakerState {
  failures: number;
  lastFailureTime: number;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
}

@Injectable()
export class HospitalIntegrationService {
  private readonly logger = new Logger(HospitalIntegrationService.name);
  private readonly circuitBreakers = new Map<string, CircuitBreakerState>();

  private readonly maxRetries: number;
  private readonly retryDelay: number;
  private readonly requestTimeout: number;
  private readonly circuitBreakerThreshold: number;
  private readonly circuitBreakerTimeout: number;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.maxRetries = this.configService.get<number>('hospital.maxRetries', 3);
    this.retryDelay = this.configService.get<number>(
      'hospital.retryDelay',
      1000,
    );
    this.requestTimeout = this.configService.get<number>(
      'hospital.requestTimeout',
      10000,
    );
    this.circuitBreakerThreshold = this.configService.get<number>(
      'hospital.circuitBreakerThreshold',
      5,
    );
    this.circuitBreakerTimeout = this.configService.get<number>(
      'hospital.circuitBreakerTimeout',
      60000,
    );
  }

  private getCircuitBreakerState(hospitalId: string): CircuitBreakerState {
    if (!this.circuitBreakers.has(hospitalId)) {
      this.circuitBreakers.set(hospitalId, {
        failures: 0,
        lastFailureTime: 0,
        state: 'CLOSED',
      });
    }
    return this.circuitBreakers.get(hospitalId)!;
  }

  private checkCircuitBreaker(hospitalId: string): void {
    const state = this.getCircuitBreakerState(hospitalId);

    if (state.state === 'OPEN') {
      const timeSinceLastFailure = Date.now() - state.lastFailureTime;

      if (timeSinceLastFailure > this.circuitBreakerTimeout) {
        this.logger.log(
          `Circuit breaker for ${hospitalId} transitioning to HALF_OPEN`,
        );
        state.state = 'HALF_OPEN';
        state.failures = 0;
      } else {
        throw new HttpException(
          `Circuit breaker is OPEN for hospital ${hospitalId}. Service temporarily unavailable.`,
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }
    }
  }

  private recordSuccess(hospitalId: string): void {
    const state = this.getCircuitBreakerState(hospitalId);

    if (state.state === 'HALF_OPEN') {
      this.logger.log(
        `Circuit breaker for ${hospitalId} transitioning to CLOSED`,
      );
      state.state = 'CLOSED';
    }

    state.failures = 0;
  }

  private recordFailure(hospitalId: string): void {
    const state = this.getCircuitBreakerState(hospitalId);
    state.failures++;
    state.lastFailureTime = Date.now();

    if (state.failures >= this.circuitBreakerThreshold) {
      this.logger.warn(
        `Circuit breaker for ${hospitalId} transitioning to OPEN`,
      );
      state.state = 'OPEN';
    }
  }

  private makeRequest<T>(
    url: string,
    hospitalId: string,
    config?: AxiosRequestConfig,
  ): Observable<T> {
    this.checkCircuitBreaker(hospitalId);

    return this.httpService.get<T>(url, config).pipe(
      timeout(this.requestTimeout),
      retry({
        count: this.maxRetries,
        delay: (error, retryCount) => {
          this.logger.warn(
            `Retry attempt ${retryCount} for ${url} due to: ${error.message}`,
          );
          return timer(this.retryDelay * retryCount);
        },
      }),
      map((response: AxiosResponse<T>) => {
        this.recordSuccess(hospitalId);
        return response.data;
      }),
      catchError((error: AxiosError) => {
        this.recordFailure(hospitalId);
        this.logger.error(
          `Request failed for ${url}: ${error.message}`,
          error.stack,
        );

        if (error.code === 'ECONNABORTED') {
          return throwError(
            () =>
              new HttpException('Request timeout', HttpStatus.REQUEST_TIMEOUT),
          );
        }

        return throwError(
          () =>
            new HttpException(
              error.response?.data || 'External service error',
              error.response?.status || HttpStatus.BAD_GATEWAY,
            ),
        );
      }),
    );
  }

  async fetchClaimData(
    hospitalId: string,
    claimId: string,
  ): Promise<HospitalClaimDataDto> {
    const baseUrl = this.configService.get<string>(
      `hospital.endpoints.${hospitalId}`,
    );

    if (!baseUrl) {
      throw new HttpException(
        `No endpoint configured for hospital ${hospitalId}`,
        HttpStatus.NOT_FOUND,
      );
    }

    const url = `${baseUrl}/claims/${claimId}`;
    this.logger.log(`Fetching claim data from ${url}`);

    return firstValueFrom(
      this.makeRequest<HospitalClaimDataDto>(url, hospitalId),
    );
  }

  async verifyClaimWithHospital(
    hospitalId: string,
    claimId: string,
  ): Promise<HospitalVerificationDto> {
    const baseUrl = this.configService.get<string>(
      `hospital.endpoints.${hospitalId}`,
    );

    if (!baseUrl) {
      throw new HttpException(
        `No endpoint configured for hospital ${hospitalId}`,
        HttpStatus.NOT_FOUND,
      );
    }

    const url = `${baseUrl}/claims/${claimId}/verify`;
    this.logger.log(`Verifying claim with hospital at ${url}`);

    return firstValueFrom(
      this.makeRequest<HospitalVerificationDto>(url, hospitalId),
    );
  }

  async fetchPatientHistory(
    hospitalId: string,
    patientId: string,
  ): Promise<HospitalClaimDataDto[]> {
    const baseUrl = this.configService.get<string>(
      `hospital.endpoints.${hospitalId}`,
    );

    if (!baseUrl) {
      throw new HttpException(
        `No endpoint configured for hospital ${hospitalId}`,
        HttpStatus.NOT_FOUND,
      );
    }

    const url = `${baseUrl}/patients/${patientId}/claims`;
    this.logger.log(`Fetching patient history from ${url}`);

    return firstValueFrom(
      this.makeRequest<HospitalClaimDataDto[]>(url, hospitalId),
    );
  }

  getCircuitBreakerStatus(hospitalId: string): CircuitBreakerState {
    return this.getCircuitBreakerState(hospitalId);
  }

  resetCircuitBreaker(hospitalId: string): void {
    this.logger.log(`Manually resetting circuit breaker for ${hospitalId}`);
    this.circuitBreakers.set(hospitalId, {
      failures: 0,
      lastFailureTime: 0,
      state: 'CLOSED',
    });
  }
}

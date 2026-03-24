# Hospital Integration Module

This module provides typed TypeScript integration services for fetching real-world hospital data from external HTTP portals.

## Features

- **Strongly Typed DTOs**: All hospital data is strongly typed using TypeScript interfaces
- **Circuit Breaker Pattern**: Prevents cascading failures when external services are down
- **Retry Logic**: Automatically retries failed requests with exponential backoff
- **Timeout Handling**: Configurable request timeouts to prevent hanging requests
- **Environment-Based Configuration**: Hospital endpoints configured via environment variables

## Configuration

Add hospital endpoints to your `.env` file:

```env
# Hospital Integration
HOSPITAL_1_ENDPOINT=https://api.hospital1.com
HOSPITAL_2_ENDPOINT=https://api.hospital2.com
HOSPITAL_3_ENDPOINT=https://api.hospital3.com
HOSPITAL_MAX_RETRIES=3
HOSPITAL_RETRY_DELAY=1000
HOSPITAL_REQUEST_TIMEOUT=10000
HOSPITAL_CIRCUIT_BREAKER_THRESHOLD=5
HOSPITAL_CIRCUIT_BREAKER_TIMEOUT=60000
```

## Usage

### Import the Module

```typescript
import { HospitalIntegrationModule } from './modules/hospital-integration';

@Module({
  imports: [HospitalIntegrationModule],
})
export class YourModule {}
```

### Inject the Service

```typescript
import { HospitalIntegrationService } from './modules/hospital-integration';

@Injectable()
export class YourService {
  constructor(
    private readonly hospitalIntegrationService: HospitalIntegrationService,
  ) {}

  async verifyClaimWithHospital(hospitalId: string, claimId: string) {
    return await this.hospitalIntegrationService.verifyClaimWithHospital(
      hospitalId,
      claimId,
    );
  }
}
```

## API Methods

### `fetchClaimData(hospitalId: string, claimId: string)`

Fetches complete claim data from a hospital's external API.

**Returns**: `Promise<HospitalClaimDataDto>`

### `verifyClaimWithHospital(hospitalId: string, claimId: string)`

Verifies a claim with the hospital's verification endpoint.

**Returns**: `Promise<HospitalVerificationDto>`

### `fetchPatientHistory(hospitalId: string, patientId: string)`

Fetches all claims for a specific patient from a hospital.

**Returns**: `Promise<HospitalClaimDataDto[]>`

### `getCircuitBreakerStatus(hospitalId: string)`

Gets the current circuit breaker state for a hospital.

**Returns**: `CircuitBreakerState`

### `resetCircuitBreaker(hospitalId: string)`

Manually resets the circuit breaker for a hospital.

## Circuit Breaker States

- **CLOSED**: Normal operation, requests are allowed
- **OPEN**: Too many failures, requests are blocked
- **HALF_OPEN**: Testing if service has recovered

## Error Handling

The service throws `HttpException` with appropriate status codes:

- `404 NOT_FOUND`: Hospital endpoint not configured
- `408 REQUEST_TIMEOUT`: Request exceeded timeout
- `502 BAD_GATEWAY`: External service error
- `503 SERVICE_UNAVAILABLE`: Circuit breaker is open

## Testing

Run the unit tests:

```bash
pnpm test hospital-integration.service.spec.ts
```

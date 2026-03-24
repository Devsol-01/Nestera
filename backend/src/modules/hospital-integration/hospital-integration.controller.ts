import { Controller, Get, Param, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { HospitalIntegrationService, CircuitBreakerState } from './hospital-integration.service';
import { HospitalClaimDataDto, HospitalVerificationDto } from './dto/hospital-data.dto';

@ApiTags('hospital-integration')
@Controller('hospital-integration')
export class HospitalIntegrationController {
    constructor(
        private readonly hospitalIntegrationService: HospitalIntegrationService,
    ) { }

    @Get(':hospitalId/claims/:claimId')
    @ApiOperation({ summary: 'Fetch claim data from hospital' })
    @ApiParam({ name: 'hospitalId', description: 'Hospital identifier' })
    @ApiParam({ name: 'claimId', description: 'Claim identifier' })
    @ApiResponse({ status: 200, description: 'Claim data retrieved successfully' })
    @ApiResponse({ status: 404, description: 'Hospital endpoint not configured' })
    @ApiResponse({ status: 503, description: 'Circuit breaker is open' })
    async fetchClaimData(
        @Param('hospitalId') hospitalId: string,
        @Param('claimId') claimId: string,
    ): Promise<HospitalClaimDataDto> {
        return await this.hospitalIntegrationService.fetchClaimData(hospitalId, claimId);
    }

    @Post(':hospitalId/claims/:claimId/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Verify claim with hospital' })
    @ApiParam({ name: 'hospitalId', description: 'Hospital identifier' })
    @ApiParam({ name: 'claimId', description: 'Claim identifier' })
    @ApiResponse({ status: 200, description: 'Claim verified successfully' })
    @ApiResponse({ status: 404, description: 'Hospital endpoint not configured' })
    @ApiResponse({ status: 503, description: 'Circuit breaker is open' })
    async verifyClaimWithHospital(
        @Param('hospitalId') hospitalId: string,
        @Param('claimId') claimId: string,
    ): Promise<HospitalVerificationDto> {
        return await this.hospitalIntegrationService.verifyClaimWithHospital(hospitalId, claimId);
    }

    @Get(':hospitalId/patients/:patientId/claims')
    @ApiOperation({ summary: 'Fetch patient claim history from hospital' })
    @ApiParam({ name: 'hospitalId', description: 'Hospital identifier' })
    @ApiParam({ name: 'patientId', description: 'Patient identifier' })
    @ApiResponse({ status: 200, description: 'Patient history retrieved successfully' })
    @ApiResponse({ status: 404, description: 'Hospital endpoint not configured' })
    @ApiResponse({ status: 503, description: 'Circuit breaker is open' })
    async fetchPatientHistory(
        @Param('hospitalId') hospitalId: string,
        @Param('patientId') patientId: string,
    ): Promise<HospitalClaimDataDto[]> {
        return await this.hospitalIntegrationService.fetchPatientHistory(hospitalId, patientId);
    }

    @Get(':hospitalId/circuit-breaker/status')
    @ApiOperation({ summary: 'Get circuit breaker status for a hospital' })
    @ApiParam({ name: 'hospitalId', description: 'Hospital identifier' })
    @ApiResponse({ status: 200, description: 'Circuit breaker status retrieved' })
    getCircuitBreakerStatus(@Param('hospitalId') hospitalId: string): CircuitBreakerState {
        return this.hospitalIntegrationService.getCircuitBreakerStatus(hospitalId);
    }

    @Post(':hospitalId/circuit-breaker/reset')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: 'Reset circuit breaker for a hospital' })
    @ApiParam({ name: 'hospitalId', description: 'Hospital identifier' })
    @ApiResponse({ status: 204, description: 'Circuit breaker reset successfully' })
    resetCircuitBreaker(@Param('hospitalId') hospitalId: string): void {
        this.hospitalIntegrationService.resetCircuitBreaker(hospitalId);
    }
}

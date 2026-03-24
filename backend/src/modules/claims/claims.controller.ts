import { Controller, Post, Body, Get, Param, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { ClaimsService } from './claims.service';
import { CreateClaimDto } from './dto/create-claim.dto';
import { MedicalClaim } from './entities/medical-claim.entity';

@ApiTags('claims')
@Controller('claims')
export class ClaimsController {
  constructor(private readonly claimsService: ClaimsService) { }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Submit a new medical claim' })
  @ApiBody({ type: CreateClaimDto })
  @ApiResponse({ status: 201, description: 'Claim successfully submitted', type: MedicalClaim })
  @ApiResponse({ status: 400, description: 'Invalid claim data' })
  async submitClaim(@Body() createClaimDto: CreateClaimDto): Promise<MedicalClaim> {
    return await this.claimsService.createClaim(createClaimDto);
  }

  @Get()
  @ApiOperation({ summary: 'Get all claims' })
  @ApiResponse({ status: 200, description: 'List of all claims', type: [MedicalClaim] })
  async getAllClaims(): Promise<MedicalClaim[]> {
    return await this.claimsService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific claim by ID' })
  @ApiResponse({ status: 200, description: 'Claim details', type: MedicalClaim })
  @ApiResponse({ status: 404, description: 'Claim not found' })
  async getClaim(@Param('id') id: string): Promise<MedicalClaim | null> {
    return await this.claimsService.findOne(id);
  }

  @Post(':id/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify claim with hospital' })
  @ApiResponse({ status: 200, description: 'Claim verified with hospital', type: MedicalClaim })
  @ApiResponse({ status: 404, description: 'Claim not found' })
  @ApiResponse({ status: 503, description: 'Hospital service unavailable' })
  async verifyClaimWithHospital(@Param('id') id: string): Promise<MedicalClaim> {
    return await this.claimsService.verifyClaimWithHospital(id);
  }

  @Get(':id/hospital-data')
  @ApiOperation({ summary: 'Fetch claim data from hospital' })
  @ApiResponse({ status: 200, description: 'Hospital claim data retrieved' })
  @ApiResponse({ status: 404, description: 'Claim not found or hospital endpoint not configured' })
  async fetchHospitalClaimData(@Param('id') id: string) {
    const claim = await this.claimsService.findOne(id);
    if (!claim) {
      throw new Error('Claim not found');
    }
    return await this.claimsService.fetchHospitalClaimData(claim.hospitalId, id);
  }
}
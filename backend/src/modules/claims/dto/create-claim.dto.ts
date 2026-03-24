import { IsString, IsNotEmpty, IsDateString, IsArray, ArrayMinSize, IsNumber, IsOptional, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { IsICD10Code, IsPositiveAmount, IsValidHospitalId } from '../validators/claim.validators';

export class CreateClaimDto {
  @ApiProperty({ example: 'John Doe', description: 'Patient full name' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(100)
  patientName: string;

  @ApiProperty({ example: 'PAT-123456', description: 'Unique patient identifier' })
  @IsString()
  @IsNotEmpty()
  patientId: string;

  @ApiProperty({ example: '1990-01-15', description: 'Patient date of birth (ISO 8601)' })
  @IsDateString()
  @IsNotEmpty()
  patientDateOfBirth: string;

  @ApiProperty({ example: 'City General Hospital', description: 'Hospital name' })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(200)
  hospitalName: string;

  @ApiProperty({ example: 'HOSP-ABC123', description: 'Hospital identifier' })
  @IsValidHospitalId()
  @IsNotEmpty()
  hospitalId: string;

  @ApiProperty({ example: ['A09', 'J18.9'], description: 'ICD-10 diagnosis codes' })
  @IsArray()
  @ArrayMinSize(1)
  @IsICD10Code()
  diagnosisCodes: string[];

  @ApiProperty({ example: 5000.50, description: 'Claim amount in USD' })
  @IsNumber()
  @IsPositiveAmount()
  claimAmount: number;

  @ApiProperty({ example: 'Emergency admission', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  notes?: string;
}

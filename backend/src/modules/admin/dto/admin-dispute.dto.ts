import { IsString, IsOptional, IsEnum, IsNotEmpty } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  DisputeStatus,
  DisputePriority,
} from '../../disputes/entities/dispute.entity';

export class DisputeFilterDto {
  @ApiPropertyOptional({ enum: DisputeStatus, example: 'OPEN' })
  @IsOptional()
  @IsEnum(DisputeStatus)
  status?: DisputeStatus;

  @ApiPropertyOptional({ enum: DisputePriority, example: 'HIGH' })
  @IsOptional()
  @IsEnum(DisputePriority)
  priority?: DisputePriority;

  @ApiPropertyOptional({ example: '550e8400-e29b-41d4-a716-446655440000' })
  @IsOptional()
  @IsString()
  assignedTo?: string;

  @ApiPropertyOptional({ example: '2024-01-01T00:00:00.000Z' })
  @IsOptional()
  @IsString()
  fromDate?: string;

  @ApiPropertyOptional({ example: '2024-12-31T23:59:59.999Z' })
  @IsOptional()
  @IsString()
  toDate?: string;
}

export class AssignDisputeDto {
  @ApiProperty({ description: 'Admin ID to assign the dispute to', example: '550e8400-e29b-41d4-a716-446655440000' })
  @IsString()
  @IsNotEmpty()
  assignedTo: string;
}

export class ResolveDisputeDto {
  @ApiProperty({ description: 'Resolution details', example: 'Dispute resolved after reviewing provided evidence. Claim approved.' })
  @IsString()
  @IsNotEmpty()
  resolution: string;

  @ApiPropertyOptional({
    enum: DisputeStatus,
    description: 'Final status after resolution',
    example: 'RESOLVED',
  })
  @IsOptional()
  @IsEnum(DisputeStatus)
  status?: DisputeStatus;
}

export class EscalateDisputeDto {
  @ApiProperty({ description: 'Senior admin ID to escalate to' })
  @IsString()
  @IsNotEmpty()
  escalatedTo: string;

  @ApiPropertyOptional({ description: 'Reason for escalation' })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class AddEvidenceDto {
  @ApiProperty({ description: 'Evidence/document name', example: 'medical_report_2024.pdf' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'URL to the evidence/document', example: 'https://cdn.example.com/evidence/medical_report_2024.pdf' })
  @IsString()
  @IsNotEmpty()
  url: string;

  @ApiPropertyOptional({
    description: 'Type of evidence (e.g., document, image, pdf)',
    example: 'pdf',
  })
  @IsOptional()
  @IsString()
  type?: string;

  @ApiPropertyOptional({ description: 'Description of the evidence', example: 'Medical report confirming treatment received' })
  @IsOptional()
  @IsString()
  description?: string;
}

export class UpdateDisputeDto {
  @ApiPropertyOptional({ enum: DisputeStatus })
  @IsOptional()
  @IsEnum(DisputeStatus)
  status?: DisputeStatus;

  @ApiPropertyOptional({ enum: DisputePriority })
  @IsOptional()
  @IsEnum(DisputePriority)
  priority?: DisputePriority;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  assignedTo?: string;
}

export class NotificationDto {
  @ApiProperty({ description: 'Notification message' })
  @IsString()
  @IsNotEmpty()
  message: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  subject?: string;
}

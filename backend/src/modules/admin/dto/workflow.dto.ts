import {
  IsEnum,
  IsString,
  IsOptional,
  IsUUID,
  IsObject,
  IsNotEmpty,
  IsNumber,
  Min,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  WorkflowActionType,
  WorkflowStatus,
} from '../entities/admin-workflow.entity';
import { Role } from '../../../common/enums/role.enum';

export class CreateWorkflowDto {
  @ApiProperty({
    enum: WorkflowActionType,
    description: 'The type of high-risk action being requested',
  })
  @IsEnum(WorkflowActionType)
  actionType: WorkflowActionType;

  @ApiProperty({
    description: 'Human-readable description of what this action will do',
    maxLength: 1000,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(1000)
  description: string;

  @ApiPropertyOptional({
    description:
      'Minimum role required to approve. Defaults to SUPER_ADMIN if omitted.',
    enum: [Role.ADMIN, Role.SUPER_ADMIN],
  })
  @IsOptional()
  @IsEnum(Role)
  requiredApproverRole?: Role;

  @ApiProperty({
    description: 'Action-specific payload (e.g. withdrawal ID, amount, reason)',
    type: Object,
  })
  @IsObject()
  payload: Record<string, any>;

  @ApiPropertyOptional({
    description:
      'Timeout in minutes after which the workflow auto-expires. Defaults to 60.',
    minimum: 5,
  })
  @IsOptional()
  @IsNumber()
  @Min(5)
  timeoutMinutes?: number;

  @ApiPropertyOptional({
    description:
      'Optional idempotency key to prevent duplicate workflow creation.',
  })
  @IsOptional()
  @IsString()
  idempotencyKey?: string;
}

export class ApproveWorkflowDto {
  @ApiPropertyOptional({
    description: 'Optional notes from the approver',
    maxLength: 2000,
  })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  notes?: string;
}

export class RejectWorkflowDto {
  @ApiProperty({ description: 'Reason for rejection', maxLength: 2000 })
  @IsString()
  @IsNotEmpty()
  @MaxLength(2000)
  reason: string;
}

export class CancelWorkflowDto {
  @ApiProperty({
    description: 'Reason for cancellation',
    maxLength: 2000,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(2000)
  reason: string;
}

export class WorkflowFilterDto {
  @ApiPropertyOptional({ enum: WorkflowStatus })
  @IsOptional()
  @IsEnum(WorkflowStatus)
  status?: WorkflowStatus;

  @ApiPropertyOptional({ enum: WorkflowActionType })
  @IsOptional()
  @IsEnum(WorkflowActionType)
  actionType?: WorkflowActionType;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  initiatorId?: string;

  @ApiPropertyOptional({
    description: 'ISO timestamp lower bound for createdAt',
  })
  @IsOptional()
  @IsString()
  fromDate?: string;

  @ApiPropertyOptional({
    description: 'ISO timestamp upper bound for createdAt',
  })
  @IsOptional()
  @IsString()
  toDate?: string;

  @ApiPropertyOptional({ minimum: 1, default: 1 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  page?: number;

  @ApiPropertyOptional({ minimum: 1, default: 20 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  limit?: number;
}

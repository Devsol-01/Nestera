import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  AuditLog,
  AuditAction,
  AuditResourceType,
} from '../entities/audit-log.entity';

export interface CreateAuditLogDto {
  correlationId?: string;
  requestId?: string;
  /** Background job ID (Bull/BullMQ job.id). Only set for system-initiated entries. */
  jobId?: string;
  endpoint?: string;
  method?: string;
  action?: AuditAction;
  actor?: string;
  resourceId?: string | null;
  resourceType?: AuditResourceType;
  statusCode?: number;
  durationMs?: number;
  success?: boolean;
  errorMessage?: string | null;
  previousValue?: Record<string, any> | null;
  newValue?: Record<string, any> | null;
  ipAddress?: string;
  userAgent?: string;
  description?: string;
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);

  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
  ) {}

  async log(dto: CreateAuditLogDto): Promise<void> {
    try {
      const entry = this.auditLogRepository.create({
        ...dto,
        success: dto.success ?? true,
      });
      await this.auditLogRepository.save(entry);
    } catch (error) {
      // Never let audit logging crash the application
      this.logger.error(
        `Failed to persist audit log: ${(error as Error).message}`,
      );
    }
  }
}

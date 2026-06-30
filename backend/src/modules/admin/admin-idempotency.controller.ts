import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { IdempotencyMonitorService } from '../../common/services/idempotency-monitor.service';
import {
  IdempotencyConflictQueryDto,
  IdempotencyConflictDto,
  IdempotencyConflictSummaryDto,
  IdempotencyUsageQueryDto,
  IdempotencyUsageRecordDto,
} from './dto/admin-idempotency.dto';

@ApiTags('admin/idempotency')
@Controller('admin/idempotency')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN, Role.SUPER_ADMIN)
@ApiBearerAuth()
export class AdminIdempotencyController {
  constructor(private readonly idempotencyMonitor: IdempotencyMonitorService) {}

  /**
   * GET /admin/idempotency/conflicts/summary
   * Aggregate statistics: totals, breakdown by type and route, top offending keys.
   * Sensitive payload data is never stored — only key identifiers and fingerprint hashes.
   */
  @Get('conflicts/summary')
  @ApiOperation({
    summary: 'Get idempotency conflict summary statistics',
    description:
      'Returns aggregate statistics about idempotency conflicts. ' +
      'No sensitive payload data is included — only idempotency key identifiers, ' +
      'SHA-256 request fingerprints, and route information.',
  })
  @ApiResponse({
    status: 200,
    description: 'Conflict summary statistics',
    type: IdempotencyConflictSummaryDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getConflictSummary(): IdempotencyConflictSummaryDto {
    return this.idempotencyMonitor.getConflictSummary();
  }

  /**
   * GET /admin/idempotency/conflicts
   * List recent conflicts with optional filtering.
   * Shows request fingerprint hash and timestamps — no sensitive payload data.
   */
  @Get('conflicts')
  @ApiOperation({
    summary: 'List recent idempotency conflicts',
    description:
      'Returns recent idempotency conflicts with request fingerprint hashes, ' +
      'timestamps, conflict types, and related entity links. ' +
      'Sensitive request payloads are never stored or exposed.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Max results (default 50, max 200)',
  })
  @ApiQuery({
    name: 'conflictType',
    required: false,
    enum: ['payload_mismatch', 'concurrent_processing'],
    description: 'Filter by conflict type',
  })
  @ApiQuery({
    name: 'path',
    required: false,
    type: String,
    description: 'Filter by route path (partial match)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of recent idempotency conflicts',
    type: [IdempotencyConflictDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getRecentConflicts(
    @Query() query: IdempotencyConflictQueryDto,
  ): IdempotencyConflictDto[] {
    return this.idempotencyMonitor.getRecentConflicts(
      query.limit ?? 50,
      query.conflictType,
      query.path,
    );
  }

  /**
   * GET /admin/idempotency/usage
   * List recent idempotency key usage (first use + replay counts).
   * Sorted by last-seen descending; useful for spotting high-replay keys.
   */
  @Get('usage')
  @ApiOperation({
    summary: 'List recent idempotency key usage',
    description:
      'Returns recent idempotency key usage records sorted by last-seen date. ' +
      'Each record shows the key identifier, route, first/last seen timestamps, ' +
      'and the number of cache-hit replays. No sensitive payload data is included.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Max results (default 50, max 200)',
  })
  @ApiQuery({
    name: 'path',
    required: false,
    type: String,
    description: 'Filter by route path (partial match)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of recent idempotency key usage records',
    type: [IdempotencyUsageRecordDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getKeyUsage(
    @Query() query: IdempotencyUsageQueryDto,
  ): IdempotencyUsageRecordDto[] {
    return this.idempotencyMonitor.getKeyUsage(query.limit ?? 50, query.path);
  }
}

import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { SandboxService } from './sandbox.service';
import { TestDataGeneratorService } from './test-data-generator.service';
import { SandboxApiKey } from './entities/sandbox-api-key.entity';
import { SandboxUsageAnalytics } from './entities/sandbox-usage-analytics.entity';
import {
  CreateApiKeyDto,
  GenerateTestDataDto,
  ResetSandboxDto,
  SimulateContractEventDto,
} from './dto/sandbox.dto';

/**
 * SandboxController
 *
 * Provides developer / training-mode endpoints for:
 *  - Test data generation (configurable)
 *  - Contract event simulation (Deposit / Withdraw / Yield)
 *  - Sandbox state reset  (admin-only, requires confirmation token)
 *  - API key management
 *  - Usage analytics
 *
 * All endpoints require a valid JWT (JwtAuthGuard) and ADMIN role (RolesGuard).
 * Sandbox endpoints must NEVER be enabled in production without an environment
 * guard; callers are expected to gate the SandboxModule registration behind
 * NODE_ENV !== 'production' in app.module.ts.
 */
@ApiTags('sandbox')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('sandbox')
export class SandboxController {
  constructor(
    private readonly sandboxService: SandboxService,
    private readonly testDataGeneratorService: TestDataGeneratorService,
  ) {}

  // -------------------------------------------------------------------------
  // API Key management
  // -------------------------------------------------------------------------

  @Post('api-keys')
  @ApiOperation({ summary: 'Create a new sandbox API key (admin only)' })
  @ApiResponse({
    status: 201,
    description: 'API key created successfully',
    type: SandboxApiKey,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden – ADMIN role required' })
  async createApiKey(@Body() dto: CreateApiKeyDto): Promise<SandboxApiKey> {
    return this.sandboxService.createApiKey(dto.name, dto.userId);
  }

  @Get('api-keys')
  @ApiOperation({ summary: 'List all sandbox API keys (admin only)' })
  @ApiResponse({
    status: 200,
    description: 'List of API keys',
    type: [SandboxApiKey],
  })
  async getApiKeys(): Promise<SandboxApiKey[]> {
    return this.sandboxService.getApiKeys();
  }

  // -------------------------------------------------------------------------
  // Test data generation
  // -------------------------------------------------------------------------

  @Post('test-data')
  @ApiOperation({
    summary: 'Generate configurable test data for sandbox (admin only)',
    description:
      'Creates synthetic users, wallets, transactions, and savings goals ' +
      'with configurable counts. Useful for integration / load testing.',
  })
  @ApiResponse({
    status: 201,
    description: 'Test data generated successfully',
  })
  async generateTestData(@Body() dto: GenerateTestDataDto) {
    return this.testDataGeneratorService.generateTestData({
      userCount: dto.userCount,
      transactionsPerUser: dto.transactionsPerUser,
      savingsGoalsPerUser: dto.savingsGoalsPerUser,
    });
  }

  // -------------------------------------------------------------------------
  // Contract event simulation
  // -------------------------------------------------------------------------

  @Post('simulate-event')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Simulate a Soroban contract event (admin only)',
    description:
      'Injects a synthetic blockchain event (Deposit, Withdraw, or Yield) ' +
      'into the event-processing pipeline without touching the real ledger. ' +
      'Useful for testing the indexer event handlers end-to-end in sandbox mode.',
  })
  @ApiResponse({
    status: 200,
    description: 'Event simulated and processed',
  })
  @ApiResponse({ status: 400, description: 'Invalid event payload' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden – ADMIN role required' })
  async simulateContractEvent(@Body() dto: SimulateContractEventDto) {
    return this.sandboxService.simulateContractEvent(dto);
  }

  // -------------------------------------------------------------------------
  // Sandbox state reset
  // -------------------------------------------------------------------------

  @Post('reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset all sandbox data (admin only)',
    description:
      'Truncates sandbox-scope data. Requires the body field ' +
      '`confirm: "CONFIRM_RESET"` to guard against accidental invocations.',
  })
  @ApiResponse({
    status: 200,
    description: 'Sandbox data reset successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Missing or invalid confirmation token',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden – ADMIN role required' })
  async resetData(@Body() dto: ResetSandboxDto) {
    if (dto.confirm !== 'CONFIRM_RESET') {
      throw new BadRequestException(
        'Reset aborted: body must include { "confirm": "CONFIRM_RESET" }',
      );
    }
    await this.sandboxService.resetSandboxData();
    return { message: 'Sandbox data reset successfully' };
  }

  // -------------------------------------------------------------------------
  // Usage analytics
  // -------------------------------------------------------------------------

  @Get('usage-analytics')
  @ApiOperation({ summary: 'Get sandbox usage analytics (admin only)' })
  @ApiResponse({
    status: 200,
    description: 'Usage analytics data',
    type: [SandboxUsageAnalytics],
  })
  async getUsageAnalytics(): Promise<SandboxUsageAnalytics[]> {
    return this.sandboxService.getUsageAnalytics();
  }
}

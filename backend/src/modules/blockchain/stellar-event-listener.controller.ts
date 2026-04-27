import {
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  Query,
  Param,
  Body,
  Delete,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { StellarEventListenerService } from './stellar-event-listener.service';

@ApiTags('stellar-events')
@Controller('stellar-events')
export class StellarEventListenerController {
  constructor(
    private readonly eventListenerService: StellarEventListenerService,
  ) {}

  @Get('status')
  @ApiOperation({ summary: 'Get event listener status' })
  @ApiResponse({ status: 200, description: 'Event listener status' })
  getStatus() {
    return this.eventListenerService.getStatus();
  }

  @Post('sync')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually trigger event synchronization' })
  @ApiResponse({ status: 200, description: 'Sync completed' })
  @ApiResponse({ status: 500, description: 'Sync failed' })
  async triggerSync() {
    const result = await this.eventListenerService.triggerManualSync();
    return {
      message: 'Manual sync completed',
      ...result,
    };
  }

  @Post('start')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Start event listener' })
  @ApiResponse({ status: 200, description: 'Listener started' })
  async startListener() {
    await this.eventListenerService.startListening();
    return { message: 'Event listener started' };
  }

  @Post('stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Stop event listener' })
  @ApiResponse({ status: 200, description: 'Listener stopped' })
  stopListener() {
    this.eventListenerService.stopListening();
    return { message: 'Event listener stopped' };
  }

  @Get('dlq')
  @ApiOperation({
    summary: 'Get Dead Letter Queue statistics and recent entries',
  })
  @ApiResponse({ status: 200, description: 'DLQ information' })
  async getDLQ() {
    return this.eventListenerService.getDLQStats();
  }

  @Post('dlq/retry')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Manually trigger retry for all failed events in DLQ',
    description:
      'Processes all events in the dead letter queue that are eligible for retry',
  })
  @ApiResponse({
    status: 200,
    description: 'Retry completed',
    schema: {
      example: {
        message: 'DLQ retry completed',
        processed: 5,
        failed: 2,
        remaining: 3,
      },
    },
  })
  async retryDLQ() {
    const result = await this.eventListenerService.triggerDLQRetry();
    return {
      message: 'DLQ retry completed',
      ...result,
    };
  }

  @Post('replay/:fromLedger')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Replay events starting from a specific ledger number',
    description:
      'Replays all events from the given ledger number forward. Useful for recovering missed events.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        toLedger: {
          type: 'number',
          description: 'Optional upper bound ledger (inclusive)',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Replay completed',
    schema: {
      example: {
        message: 'Replay completed',
        replayed: 15,
        skipped: 3,
      },
    },
  })
  async replayFromLedger(
    @Param('fromLedger') fromLedger: string,
    @Query('toLedger') toLedger?: string,
  ) {
    const result = await this.eventListenerService.replayFromLedger(
      parseInt(fromLedger, 10),
      toLedger ? parseInt(toLedger, 10) : undefined,
    );
    return {
      message: 'Replay completed',
      ...result,
    };
  }

  @Get('dlq/:id')
  @ApiOperation({ summary: 'Get specific DLQ entry details' })
  @ApiResponse({ status: 200, description: 'DLQ entry details' })
  async getDLQEntry(@Param('id') id: string) {
    const entry = await this.eventListenerService.findDLQEntry(id);
    if (!entry) {
      return { error: 'DLQ entry not found' };
    }
    return entry;
  }

  @Delete('dlq/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a specific DLQ entry' })
  @ApiResponse({ status: 204, description: 'DLQ entry deleted' })
  @ApiResponse({ status: 404, description: 'DLQ entry not found' })
  async deleteDLQEntry(@Param('id') id: string) {
    const deleted = await this.eventListenerService.deleteDLQEntry(id);
    if (!deleted) {
      return { error: 'DLQ entry not found' };
    }
    return;
  }

  @Get('metrics')
  @ApiOperation({
    summary: 'Get comprehensive event listener metrics',
    description:
      'Returns processing statistics including success rate and DLQ metrics',
  })
  @ApiResponse({ status: 200, description: 'Metrics data' })
  async getMetrics() {
    return this.eventListenerService.getMetrics();
  }
}

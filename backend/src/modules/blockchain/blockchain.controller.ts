import { Controller, Get, Param, Post } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { StellarService } from './stellar.service';
import { BalanceSyncService } from './balance-sync.service';
import { IndexerService } from './indexer.service';
import { TransactionDto } from './dto/transaction.dto';

import { EventStreamBackpressureService } from './event-stream-backpressure.service';

@ApiTags('Blockchain')
@Controller('blockchain')
export class BlockchainController {
  constructor(
    private readonly stellarService: StellarService,
    private readonly balanceSyncService: BalanceSyncService,
    private readonly indexerService: IndexerService,
    private readonly backpressureService: EventStreamBackpressureService,
  ) {}

  @Post('wallets/generate')
  @Throttle({ rpc: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Generate a new Stellar keypair' })
  generateWallet() {
    return this.stellarService.generateKeypair();
  }

  @Get('wallets/:publicKey/transactions')
  @Throttle({ rpc: { limit: 10, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get recent on-chain transactions for a Stellar wallet',
  })
  @ApiParam({
    name: 'publicKey',
    description: 'The Stellar public key (starting with G) of the wallet',
    example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN',
  })
  @ApiResponse({
    status: 200,
    description: 'Array of recent transactions mapped to sanitized objects',
    type: [TransactionDto],
  })
  getWalletTransactions(
    @Param('publicKey') publicKey: string,
  ): Promise<TransactionDto[]> {
    return this.stellarService.getRecentTransactions(publicKey);
  }

  @Get('rpc/status')
  @Throttle({ rpc: { limit: 10, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get status of all configured RPC endpoints',
    description:
      'Returns information about primary and fallback RPC/Horizon endpoints for monitoring and debugging',
  })
  @ApiResponse({
    status: 200,
    description:
      'Status of all RPC endpoints including current active endpoint',
  })
  getRpcStatus() {
    return this.stellarService.getEndpointsStatus();
  }

  @Get('balance-sync/metrics')
  @ApiOperation({
    summary: 'Get WebSocket connection health metrics for balance sync',
  })
  @ApiResponse({
    status: 200,
    description: 'Connection metrics summary for all subscribed accounts',
  })
  getBalanceSyncMetrics() {
    return this.balanceSyncService.getMetricsSummary();
  }

  @Get('indexer/status')
  @ApiOperation({
    summary: 'Get contract event indexer status for monitoring dashboard',
  })
  @ApiResponse({
    status: 200,
    description:
      'Indexer state including ledger position, event counts, and monitored contracts',
  })
  getIndexerStatus() {
    const state = this.indexerService.getIndexerState();
    return {
      lastProcessedLedger: state?.lastProcessedLedger ?? 0,
      lastProcessedTimestamp: state?.lastProcessedTimestamp ?? null,
      totalEventsProcessed: state?.totalEventsProcessed ?? 0,
      totalEventsFailed: state?.totalEventsFailed ?? 0,
      monitoredContracts: this.indexerService.getMonitoredContracts(),
    };
  }

  @Get('backpressure/status')
  @ApiOperation({
    summary: 'Get event stream backpressure status',
    description:
      'Queue depth, ingestion rate, and pause state for blockchain event processing',
  })
  async getBackpressureStatus() {
    return this.backpressureService.getStatus();
  }
}

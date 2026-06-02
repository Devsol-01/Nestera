import {
  Controller,
  Get,
  Query,
  UseGuards,
  Res,
  Param,
  Post,
  Body,
} from '@nestjs/common';
import { Response } from 'express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { TransactionsService } from './transactions.service';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';
import { TagTransactionDto } from './dto/tag-transaction.dto';
import { BulkTagDto } from './dto/bulk-tag.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { PageDto } from '../../common/dto/page.dto';

@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class TransactionsController {
  constructor(private readonly transactionsService: TransactionsService) {}

  @Get()
  @ApiOperation({
    summary: 'Get paginated transaction history for authenticated user',
    description:
      'Returns a paginated list of transactions with robust filtering by type, date range, and pool ID. ' +
      'Dates are formatted for frontend display to minimize client-side dependencies.',
  })
  @ApiResponse({
    status: 200,
    description: 'Paginated transaction history',
    type: PageDto<TransactionResponseDto>,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  async getTransactions(
    @CurrentUser() user: { id: string },
    @Query() queryDto: TransactionQueryDto,
  ): Promise<PageDto<TransactionResponseDto>> {
    return this.transactionsService.findAllForUser(user.id, queryDto);
  }

  @Get('export')
  @ApiOperation({
    summary: 'Export transaction history as CSV',
    description:
      'Streams transactions as CSV for download with controlled memory usage while respecting query filters.',
  })
  @ApiResponse({ status: 200, description: 'CSV file stream' })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing JWT token',
  })
  async exportTransactions(
    @CurrentUser() user: { id: string },
    @Query() queryDto: TransactionQueryDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="nestera_history.csv"',
    );

    const csvStream = await this.transactionsService.streamTransactionsCsv(
      user.id,
      queryDto,
    );

    csvStream.pipe(res);
  }

  @Post(':id/tag')
  @ApiOperation({ summary: 'Add or update a tag on a transaction' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Transaction ID',
  })
  @ApiBody({ type: TagTransactionDto })
  @ApiResponse({ status: 201, description: 'Tag applied' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Transaction not found' })
  async tagTransaction(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Body() payload: TagTransactionDto,
  ) {
    return this.transactionsService.tagTransaction(user.id, id, payload);
  }

  @Get('categories')
  @ApiOperation({
    summary: 'List distinct transaction categories for the current user',
  })
  @ApiResponse({ status: 200, description: 'List of category strings' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getCategories(@CurrentUser() user: { id: string }) {
    return this.transactionsService.listCategories(user.id);
  }

  @Post('tags/bulk')
  @ApiOperation({ summary: 'Apply tags to multiple transactions at once' })
  @ApiBody({ type: BulkTagDto })
  @ApiResponse({ status: 201, description: 'Bulk tags applied' })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async bulkTag(@CurrentUser() user: { id: string }, @Body() body: BulkTagDto) {
    return this.transactionsService.bulkTag(user.id, body);
  }
}

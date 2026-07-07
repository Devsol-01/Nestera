import {
  Controller,
  Get,
  Query,
  UseGuards,
  Res,
  Param,
  Post,
  Body,
  Delete,
  Patch,
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
import { ReceiptService } from './receipt.service';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';
import { TagTransactionDto } from './dto/tag-transaction.dto';
import { BulkTagDto } from './dto/bulk-tag.dto';
import { CreateSavedSearchDto } from './dto/create-saved-search.dto';
import { UpdateSavedSearchDto } from './dto/update-saved-search.dto';
import { SavedSearchResponseDto } from './dto/saved-search-response.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { PageDto } from '../../common/dto/page.dto';

@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class TransactionsController {
  constructor(
    private readonly transactionsService: TransactionsService,
    private readonly receiptService: ReceiptService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get paginated transaction history for authenticated user',
    description:
      'Returns a paginated list of transactions with server-side filtering by type, date range, pool ID, and free-text search. ' +
      'Search terms use relevance ranking for hashes, memos, reference IDs, and descriptions, then apply deterministic ordering for ties. ' +
      'Search requests are bounded for execution time and capped for result size.',
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
    @Query('format') format: 'csv' | 'json' = 'csv',
    @Res({ passthrough: true }) res: Response,
  ): Promise<void | TransactionResponseDto[]> {
    if (format === 'json') {
      return this.transactionsService.exportTransactions(user.id, queryDto);
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="nestera_search_results.csv"',
    );

    const csvStream = await this.transactionsService.streamTransactionsCsv(
      user.id,
      queryDto,
    );

    csvStream.pipe(res);
  }

  @Post(':id/tag')
  @ApiOperation({ summary: 'Tag a transaction with a label or category' })
  @ApiParam({ name: 'id', description: 'Transaction UUID' })
  @ApiBody({ type: TagTransactionDto })
  @ApiResponse({ status: 201, description: 'Transaction tagged' })
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
    summary: 'List all transaction categories used by the authenticated user',
  })
  @ApiResponse({ status: 200, description: 'List of category strings' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getCategories(@CurrentUser() user: { id: string }) {
    return this.transactionsService.listCategories(user.id);
  }

  @Post('tags/bulk')
  @ApiOperation({
    summary: 'Bulk tag multiple transactions at once',
    description:
      'Apply tags/categories to a list of transaction IDs in a single request.',
  })
  @ApiBody({ type: BulkTagDto })
  @ApiResponse({ status: 201, description: 'Transactions tagged' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async bulkTag(@CurrentUser() user: { id: string }, @Body() body: BulkTagDto) {
    return this.transactionsService.bulkTag(user.id, body);
  }

  @Post(':id/auto-categorize')
  @ApiOperation({ summary: 'Auto-categorize a single transaction' })
  @ApiParam({ name: 'id', description: 'Transaction UUID' })
  @ApiResponse({ status: 200, description: 'Transaction categorized' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Transaction not found' })
  async autoCategorizeTransaction(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
  ) {
    return this.transactionsService.autoCategorizeTransaction(user.id, id);
  }

  @Post('auto-categorize-all')
  @ApiOperation({ summary: 'Auto-categorize all uncategorized transactions' })
  @ApiResponse({ status: 200, description: 'Transactions categorized' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async autoCategorizeAll(@CurrentUser() user: { id: string }) {
    return this.transactionsService.autoCategorizeAll(user.id);
  }

  @Get('analytics')
  @ApiOperation({ summary: 'Get tag and category analytics' })
  @ApiResponse({ status: 200, description: 'Tag and category statistics' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getAnalytics(@CurrentUser() user: { id: string }) {
    return this.transactionsService.getTagAnalytics(user.id);
  }

  @Get('saved-searches')
  @ApiOperation({
    summary: 'List saved transaction searches for the authenticated user',
  })
  @ApiResponse({
    status: 200,
    description: 'Saved searches',
    type: [SavedSearchResponseDto],
  })
  async getSavedSearches(@CurrentUser() user: { id: string }) {
    return this.transactionsService.listSavedSearches(user.id);
  }

  @Post('saved-searches')
  @ApiOperation({ summary: 'Create a saved transaction search' })
  @ApiBody({ type: CreateSavedSearchDto })
  @ApiResponse({
    status: 201,
    description: 'Saved search created',
    type: SavedSearchResponseDto,
  })
  async createSavedSearch(
    @CurrentUser() user: { id: string },
    @Body() body: CreateSavedSearchDto,
  ) {
    return this.transactionsService.createSavedSearch(user.id, body);
  }

  @Patch('saved-searches/:id')
  @ApiOperation({ summary: 'Update a saved transaction search' })
  @ApiParam({ name: 'id', description: 'Saved search UUID' })
  @ApiBody({ type: UpdateSavedSearchDto })
  async updateSavedSearch(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Body() body: UpdateSavedSearchDto,
  ) {
    return this.transactionsService.updateSavedSearch(user.id, id, body);
  }

  @Delete('saved-searches/:id')
  @ApiOperation({ summary: 'Delete a saved transaction search' })
  @ApiParam({ name: 'id', description: 'Saved search UUID' })
  async deleteSavedSearch(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
  ) {
    return this.transactionsService.deleteSavedSearch(user.id, id);
  }

  @Get('saved-searches/:id/results')
  @ApiOperation({ summary: 'Run a saved transaction search' })
  @ApiParam({ name: 'id', description: 'Saved search UUID' })
  async runSavedSearch(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Query() queryDto: TransactionQueryDto,
  ) {
    return this.transactionsService.runSavedSearch(user.id, id, {
      page: queryDto.page,
      limit: queryDto.limit,
    });
  }

  @Post(':id/receipt')
  @ApiOperation({ summary: 'Generate PDF receipt for a transaction' })
  @ApiParam({ name: 'id', description: 'Transaction UUID' })
  @ApiResponse({ status: 200, description: 'PDF receipt generated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Transaction not found' })
  async generateReceipt(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const pdfBuffer = await this.receiptService.generateReceipt(user.id, id);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="nestera-receipt-${id}.pdf"`,
    );
    res.send(pdfBuffer);
  }

  @Get('receipts')
  @ApiOperation({ summary: 'List all receipts for the authenticated user' })
  @ApiResponse({ status: 200, description: 'List of receipts' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async listReceipts(@CurrentUser() user: { id: string }) {
    return this.receiptService.listReceipts(user.id);
  }

  @Get('receipts/:id')
  @ApiOperation({ summary: 'Download a specific receipt' })
  @ApiParam({ name: 'id', description: 'Receipt UUID' })
  @ApiResponse({ status: 200, description: 'PDF receipt' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Receipt not found' })
  async downloadReceipt(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Res({ passthrough: true }) res: Response,
    @Query('accessKey') accessKey?: string,
  ): Promise<void> {
    const { pdfData, contentType } = await this.receiptService.getReceipt(
      user.id,
      id,
      accessKey,
    );

    res.setHeader('Content-Type', contentType);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="nestera-receipt-${id}.pdf"`,
    );
    res.send(pdfData);
  }

  @Delete('receipts/:id')
  @ApiOperation({ summary: 'Delete a receipt' })
  @ApiParam({ name: 'id', description: 'Receipt UUID' })
  @ApiResponse({ status: 200, description: 'Receipt deleted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Receipt not found' })
  async deleteReceipt(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
  ) {
    return this.receiptService.deleteReceipt(user.id, id);
  }
}

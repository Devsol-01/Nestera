import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Query,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  FileTypeValidator,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import { DisputesService } from './disputes.service';
import { CorrelationId } from '../../common/decorators/correlation-id.decorator';
import { RequestId } from '../../common/decorators/request-id.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import {
  CreateDisputeDto,
  UpdateDisputeDto,
  AddDisputeMessageDto,
} from './dto/dispute.dto';
import { UploadEvidenceDto } from './dto/upload-evidence.dto';
import { Dispute, DisputeMessage } from './entities/dispute.entity';
import { DisputeEvidence } from './entities/dispute-evidence.entity';

@ApiTags('disputes')
@Controller('disputes')
export class DisputesController {
  constructor(private readonly disputesService: DisputesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Open a new dispute' })
  @ApiResponse({ status: 201, description: 'Dispute created', type: Dispute })
  @ApiResponse({ status: 400, description: 'Invalid claim ID' })
  async createDispute(
    @Body() createDisputeDto: CreateDisputeDto,
    @CorrelationId() correlationId?: string,
    @RequestId() requestId?: string,
  ): Promise<Dispute> {
    return await this.disputesService.createDispute(
      createDisputeDto,
      correlationId,
      requestId,
    );
  }

  @Get()
  @ApiOperation({ summary: 'Get all disputes' })
  @ApiResponse({
    status: 200,
    description: 'List of disputes',
    type: [Dispute],
  })
  async getAllDisputes(): Promise<Dispute[]> {
    return await this.disputesService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get dispute by ID' })
  @ApiResponse({ status: 200, description: 'Dispute details', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async getDispute(@Param('id') id: string): Promise<Dispute> {
    return await this.disputesService.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update dispute status' })
  @ApiResponse({ status: 200, description: 'Dispute updated', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async updateDispute(
    @Param('id') id: string,
    @Body() updateDisputeDto: UpdateDisputeDto,
  ): Promise<Dispute> {
    return await this.disputesService.updateDispute(id, updateDisputeDto);
  }

  @Post(':id/messages')
  @HttpCode(HttpStatus.CREATED)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Add message/evidence to dispute' })
  @ApiResponse({
    status: 201,
    description: 'Message added',
    type: DisputeMessage,
  })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async addMessage(
    @Param('id') id: string,
    @Body() addMessageDto: AddDisputeMessageDto,
  ): Promise<DisputeMessage> {
    return await this.disputesService.addMessage(id, addMessageDto);
  }

  @Patch(':id/investigate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Start investigation' })
  @ApiResponse({
    status: 200,
    description: 'Investigation started',
    type: Dispute,
  })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async startInvestigation(
    @Param('id') id: string,
    @Query('actor') actor: string,
    @CorrelationId() correlationId?: string,
    @RequestId() requestId?: string,
  ): Promise<Dispute> {
    return await this.disputesService.startInvestigation(
      id,
      actor,
      correlationId,
      requestId,
    );
  }

  @Patch(':id/resolve')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Resolve dispute' })
  @ApiResponse({ status: 200, description: 'Dispute resolved', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async resolveDispute(
    @Param('id') id: string,
    @Query('actor') actor: string,
    @Body('resolution') resolution: string,
    @CorrelationId() correlationId?: string,
    @RequestId() requestId?: string,
  ): Promise<Dispute> {
    return await this.disputesService.resolveDispute(
      id,
      actor,
      resolution,
      correlationId,
      requestId,
    );
  }

  @Patch(':id/close')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Close dispute' })
  @ApiResponse({ status: 200, description: 'Dispute closed', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async closeDispute(
    @Param('id') id: string,
    @Query('actor') actor: string,
    @CorrelationId() correlationId?: string,
    @RequestId() requestId?: string,
  ): Promise<Dispute> {
    return await this.disputesService.closeDispute(
      id,
      actor,
      correlationId,
      requestId,
    );
  }

  @Patch(':id/escalate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Escalate dispute' })
  @ApiResponse({ status: 200, description: 'Dispute escalated', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async escalateDispute(
    @Param('id') id: string,
    @Query('actor') actor: string,
    @CorrelationId() correlationId?: string,
    @RequestId() requestId?: string,
  ): Promise<Dispute> {
    return await this.disputesService.escalateDispute(
      id,
      actor,
      correlationId,
      requestId,
    );
  }

  // ── Evidence endpoints ──────────────────────────────────────────────────────

  @Post(':id/evidence')
  @HttpCode(HttpStatus.CREATED)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary:
      'Upload evidence file for a dispute (triggers background processing)',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['uploadedBy', 'file'],
      properties: {
        uploadedBy: { type: 'string', example: 'Hospital Admin' },
        file: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Evidence uploaded and processing job enqueued',
    type: DisputeEvidence,
  })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  @UseInterceptors(FileInterceptor('file'))
  async uploadEvidence(
    @Param('id') id: string,
    @Body() dto: UploadEvidenceDto,
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 20 * 1024 * 1024 }), // 20 MB
          new FileTypeValidator({
            fileType: /(application\/pdf|image\/jpeg|image\/png|image\/webp)/,
          }),
        ],
      }),
    )
    file: any,
    @CorrelationId() correlationId?: string,
  ): Promise<DisputeEvidence> {
    return this.disputesService.uploadEvidence(id, file, dto, correlationId);
  }

  @Get(':id/evidence')
  @ApiOperation({ summary: 'List all evidence files for a dispute' })
  @ApiResponse({
    status: 200,
    description: 'List of evidence records',
    type: [DisputeEvidence],
  })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async listEvidence(@Param('id') id: string): Promise<DisputeEvidence[]> {
    return this.disputesService.listEvidence(id);
  }

  @Get(':id/evidence/:evidenceId')
  @ApiOperation({
    summary: 'Get processing status for a specific evidence file',
  })
  @ApiResponse({
    status: 200,
    description: 'Evidence processing status',
    type: DisputeEvidence,
  })
  @ApiResponse({ status: 404, description: 'Evidence not found' })
  async getEvidenceStatus(
    @Param('id') id: string,
    @Param('evidenceId') evidenceId: string,
  ): Promise<DisputeEvidence> {
    return this.disputesService.getEvidenceStatus(id, evidenceId);
  }
}

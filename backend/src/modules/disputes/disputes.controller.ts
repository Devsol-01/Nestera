import { Controller, Get, Post, Patch, Body, Param, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { DisputesService } from './disputes.service';
import { CreateDisputeDto, UpdateDisputeDto, AddDisputeMessageDto } from './dto/dispute.dto';
import { Dispute, DisputeMessage } from './entities/dispute.entity';

@ApiTags('disputes')
@Controller('disputes')
export class DisputesController {
  constructor(private readonly disputesService: DisputesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Open a new dispute' })
  @ApiResponse({ status: 201, description: 'Dispute created', type: Dispute })
  @ApiResponse({ status: 400, description: 'Invalid claim ID' })
  async createDispute(@Body() createDisputeDto: CreateDisputeDto): Promise<Dispute> {
    return await this.disputesService.createDispute(createDisputeDto);
  }

  @Get()
  @ApiOperation({ summary: 'Get all disputes' })
  @ApiResponse({ status: 200, description: 'List of disputes', type: [Dispute] })
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
  @ApiOperation({ summary: 'Add message/evidence to dispute' })
  @ApiResponse({ status: 201, description: 'Message added', type: DisputeMessage })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async addMessage(
    @Param('id') id: string,
    @Body() addMessageDto: AddDisputeMessageDto,
  ): Promise<DisputeMessage> {
    return await this.disputesService.addMessage(id, addMessageDto);
  }
}

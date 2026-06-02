import {
  Controller,
  Get,
  Param,
  Query,
  UseGuards,
  ParseIntPipe,
  Post,
  Body,
  Delete,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiBody,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { InjectRepository } from '@nestjs/typeorm';
import { WaitlistEntry } from '../savings/entities/waitlist-entry.entity';
import { WaitlistEvent } from '../savings/entities/waitlist-event.entity';
import { Repository, IsNull } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';

@ApiTags('admin/waitlist')
@Controller('admin/waitlists')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminWaitlistController {
  constructor(
    @InjectRepository(WaitlistEntry)
    private readonly waitlistRepo: Repository<WaitlistEntry>,
    @InjectRepository(WaitlistEvent)
    private readonly waitlistEventRepo: Repository<WaitlistEvent>,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  @Get(':productId')
  @ApiOperation({ summary: 'List waitlist entries for a product (admin)' })
  @ApiParam({ name: 'productId', type: 'string' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiResponse({ status: 200, description: 'Paginated waitlist entries' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async listForProduct(
    @Param('productId') productId: string,
    @Query('page', ParseIntPipe) page = 1,
    @Query('limit', ParseIntPipe) limit = 50,
  ) {
    const [entries, total] = await this.waitlistRepo.findAndCount({
      where: { productId },
      order: { priority: 'DESC', createdAt: 'ASC' },
      skip: (page - 1) * limit,
      take: limit,
    });

    return { entries, total };
  }

  @Post(':productId/entries/:entryId/promote')
  @ApiOperation({ summary: 'Promote a waitlist entry (admin)' })
  @ApiParam({ name: 'productId', type: 'string' })
  @ApiParam({ name: 'entryId', type: 'string' })
  @ApiBody({ schema: { example: { priority: 10 } } })
  @ApiResponse({ status: 201, description: 'Entry promoted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async promoteEntry(
    @Param('productId') productId: string,
    @Param('entryId') entryId: string,
    @Body() body: { priority?: number; bump?: number },
  ) {
    const entry = await this.waitlistRepo.findOneBy({ id: entryId });
    if (!entry || entry.productId !== productId) return { ok: false };

    if (typeof body.priority === 'number') entry.priority = body.priority;
    else if (typeof body.bump === 'number') entry.priority += body.bump;
    else entry.priority += 1;

    await this.waitlistRepo.save(entry);
    return { ok: true, entry };
  }

  @Delete(':productId/entries/:entryId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Remove a waitlist entry (admin)' })
  @ApiParam({ name: 'productId', type: 'string' })
  @ApiParam({ name: 'entryId', type: 'string' })
  @ApiResponse({ status: 204, description: 'Entry removed' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async removeEntry(
    @Param('productId') productId: string,
    @Param('entryId') entryId: string,
  ) {
    const entry = await this.waitlistRepo.findOneBy({ id: entryId });
    if (!entry || entry.productId !== productId) return;
    await this.waitlistRepo.delete({ id: entryId });
  }

  @Post(':productId/release')
  @ApiOperation({
    summary: 'Release spots on a waitlist and notify users (admin)',
  })
  @ApiParam({ name: 'productId', type: 'string' })
  @ApiBody({ schema: { example: { spots: 5 } } })
  @ApiResponse({ status: 201, description: 'Spots released' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async releaseSpots(
    @Param('productId') productId: string,
    @Body() body: { spots?: number },
  ) {
    const spots = body.spots ?? 1;
    this.eventEmitter.emit('waitlist.product.available', { productId, spots });
    return { ok: true };
  }

  @Get(':productId/analytics')
  @ApiOperation({ summary: 'Get waitlist analytics for a product (admin)' })
  @ApiParam({ name: 'productId', type: 'string' })
  @ApiResponse({ status: 200, description: 'Waitlist analytics' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async analyticsForProduct(@Param('productId') productId: string) {
    const waitlistSize = await this.waitlistRepo.count({
      where: { productId, notifiedAt: IsNull() },
    });

    const notifiedCount = await this.waitlistEventRepo.count({
      where: { productId, type: 'NOTIFY' },
    });

    const acceptedCount = await this.waitlistEventRepo.count({
      where: { productId, type: 'ACCEPT' },
    });

    // average time from NOTIFY -> ACCEPT for matching entryId
    const rows = await this.waitlistEventRepo
      .createQueryBuilder('e_notify')
      .select(
        'AVG(EXTRACT(EPOCH FROM (e_accept.createdAt - e_notify.createdAt)))',
        'avgSeconds',
      )
      .innerJoin(
        'waitlist_events',
        'e_accept',
        "e_accept.entryId = e_notify.entryId AND e_accept.type = 'ACCEPT'",
      )
      .where("e_notify.productId = :productId AND e_notify.type = 'NOTIFY'", {
        productId,
      })
      .getRawOne();

    const avgSeconds = rows?.avgseconds ?? rows?.avgSeconds ?? null;

    const conversionRate =
      notifiedCount > 0 ? acceptedCount / notifiedCount : 0;

    return {
      productId,
      waitlistSize,
      notifiedCount,
      acceptedCount,
      conversionRate,
      avgTimeToConvertSeconds: avgSeconds ? Number(avgSeconds) : null,
    };
  }
}

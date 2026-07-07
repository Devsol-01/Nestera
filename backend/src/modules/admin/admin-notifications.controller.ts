import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Body,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { AdminNotificationsService } from './admin-notifications.service';
import {
  BroadcastNotificationDto,
  ScheduleNotificationDto,
  PreviewNotificationDto,
  NotificationFilterDto,
} from './dto/admin-notification.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { Idempotent } from '../../common/decorators/idempotent.decorator';

@ApiTags('admin/notifications')
@Controller('admin/notifications')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminNotificationsController {
  constructor(
    private readonly notificationsService: AdminNotificationsService,
  ) {}

  @Post('broadcast')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Send broadcast notification to all or targeted users',
  })
  @ApiResponse({
    status: 200,
    description: 'Broadcast sent',
    schema: {
      properties: {
        sent: { type: 'number' },
        delivered: { type: 'number' },
        failed: { type: 'number' },
      },
    },
  })
  async broadcastNotification(@Body() dto: BroadcastNotificationDto) {
    return await this.notificationsService.broadcastNotification(dto);
  }

  @Post('targeted')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Send targeted notification to filtered users' })
  @ApiResponse({
    status: 200,
    description: 'Targeted notification sent',
  })
  async sendTargetedNotification(@Body() dto: BroadcastNotificationDto) {
    return await this.notificationsService.broadcastNotification(dto);
  }

  @Post('schedule')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Schedule a notification for future delivery' })
  @ApiResponse({
    status: 201,
    description: 'Notification scheduled',
  })
  async scheduleNotification(@Body() dto: ScheduleNotificationDto) {
    return await this.notificationsService.scheduleNotification(dto);
  }

  @Delete('schedule/:id')
  @ApiOperation({ summary: 'Cancel a scheduled notification' })
  @ApiResponse({ status: 200, description: 'Scheduled notification cancelled' })
  @ApiResponse({ status: 404, description: 'Scheduled notification not found' })
  async cancelScheduledNotification(@Param('id') scheduleId: string) {
    await this.notificationsService.cancelScheduledNotification(scheduleId);
    return { message: 'Scheduled notification cancelled successfully' };
  }

  @Post('preview')
  @ApiOperation({ summary: 'Preview notification before sending' })
  @ApiResponse({
    status: 200,
    description: 'Preview data',
  })
  async previewNotification(@Body() dto: PreviewNotificationDto) {
    return await this.notificationsService.previewNotification(dto);
  }

  @Get('history')
  @ApiOperation({ summary: 'Get notification broadcast history' })
  @ApiQuery({ name: 'fromDate', required: false, type: String })
  @ApiQuery({ name: 'toDate', required: false, type: String })
  @ApiQuery({
    name: 'channel',
    required: false,
    enum: ['EMAIL', 'IN_APP', 'PUSH'],
  })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiResponse({ status: 200, description: 'Notification history' })
  async getNotificationHistory(@Query() filter: NotificationFilterDto) {
    return await this.notificationsService.getNotificationHistory(filter);
  }

  @Get(':id/delivery')
  @ApiOperation({ summary: 'Get delivery statistics for a notification' })
  @ApiResponse({
    status: 200,
    description: 'Delivery statistics',
  })
  async getDeliveryStats(@Param('id') notificationId: string) {
    return await this.notificationsService.getDeliveryStats(notificationId);
  }
}

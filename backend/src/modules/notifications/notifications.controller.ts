import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { NotificationsService } from './notifications.service';
import { UpdateUserPreferenceDto } from './dto/update-notification-preference.dto';
import { User } from '../user/entities/user.entity';
import { PageOptionsDto } from '../../common/dto/page-options.dto';
import { PageDto } from '../../common/dto/page.dto';
import { Notification } from './entities/notification.entity';

@ApiTags('notifications')
@Controller('notifications')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  @ApiOperation({ summary: 'Get paginated user notifications' })
  @ApiResponse({
    status: 200,
    description: 'Paginated notifications',
    type: PageDto,
  })
  async getNotifications(
    @CurrentUser() user: User,
    @Query() pageOptionsDto: PageOptionsDto,
  ): Promise<PageDto<Notification>> {
    return this.notificationsService.getUserNotifications(
      user.id,
      pageOptionsDto,
    );
  }

  @Get('unread-count')
  @ApiOperation({ summary: 'Get unread notification count' })
  async getUnreadCount(@CurrentUser() user: User) {
    const count = await this.notificationsService.getUnreadCount(user.id);
    return { unreadCount: count };
  }

  @Patch(':id/read')
  @HttpCode(HttpStatus.OK)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Mark notification as read' })
  async markAsRead(@Param('id') notificationId: string) {
    return await this.notificationsService.markAsRead(notificationId);
  }

  @Patch('mark-all-read')
  @HttpCode(HttpStatus.OK)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Mark all notifications as read' })
  async markAllAsRead(@CurrentUser() user: User) {
    await this.notificationsService.markAllAsRead(user.id);
    return { message: 'All notifications marked as read' };
  }

  @Get('preferences')
  @ApiOperation({ summary: 'Get notification preferences' })
  async getPreferences(@CurrentUser() user: User) {
    return await this.notificationsService.getOrCreatePreferences(user.id);
  }

  @Post('preferences')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Create or restore user preference settings' })
  async createPreferences(@CurrentUser() user: User) {
    return await this.notificationsService.createPreferences(user.id);
  }

  @Patch('preferences')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary:
      'Update user preferences (notifications, privacy, display, channels, quiet hours, digest)',
  })
  async updatePreferences(
    @CurrentUser() user: User,
    @Body() updateDto: UpdateUserPreferenceDto,
  ) {
    return await this.notificationsService.updatePreferences(
      user.id,
      updateDto,
    );
  }

  @Delete('preferences')
  @ApiOperation({ summary: 'Reset user preferences to defaults' })
  async deletePreferences(@CurrentUser() user: User) {
    await this.notificationsService.deletePreferences(user.id);
    return {
      message:
        'Preferences deleted. Defaults will be recreated on next retrieval.',
    };
  }
}

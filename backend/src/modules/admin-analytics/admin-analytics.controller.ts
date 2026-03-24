import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AdminAnalyticsService } from './admin-analytics.service';
import { AnalyticsOverviewDto } from './dto/analytics-overview.dto';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';

@ApiTags('admin/analytics')
@Controller('admin/analytics')
@UseGuards(RolesGuard)
export class AdminAnalyticsController {
  constructor(private readonly analyticsService: AdminAnalyticsService) {}

  @Get('overview')
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get admin dashboard analytics overview' })
  @ApiResponse({ status: 200, description: 'Analytics overview', type: AnalyticsOverviewDto })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin access required' })
  async getOverview(): Promise<AnalyticsOverviewDto> {
    return await this.analyticsService.getOverview();
  }
}

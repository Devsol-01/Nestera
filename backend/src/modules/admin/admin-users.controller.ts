import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AdminHighRisk } from '../../common/decorators/admin-high-risk.decorator';
import { Role } from '../../common/enums/role.enum';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { AdminUsersService } from './admin-users.service';
import { AdminUsersQueryDto } from './dto/admin-users-query.dto';
import {
  BulkActionDto,
  AdminUserListItemDto,
  UpdateUserRoleDto,
  UpdateUserStatusDto,
} from './dto/admin-user.dto';
import { PageDto } from '../../common/dto/page.dto';

@ApiTags('admin')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller({ path: 'admin/users', version: '1' })
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Get()
  @ApiOperation({ summary: 'List users with pagination, search, and filters' })
  @ApiResponse({
    status: 200,
    description: 'Paginated user list with savings and transaction totals',
  })
  listUsers(
    @Query() query: AdminUsersQueryDto,
  ): Promise<PageDto<AdminUserListItemDto>> {
    return this.adminUsersService.listUsers(query);
  }

  @Get(':id/details')
  @ApiOperation({ summary: 'Full user profile with activity summary' })
  getUserDetails(@Param('id', ParseUUIDPipe) id: string) {
    return this.adminUsersService.getUserDetails(id);
  }

  @Patch(':id/role')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Update user role',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  updateRole(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserRoleDto,
  ) {
    return this.adminUsersService.updateRole(id, dto.role);
  }

  @Patch(':id/status')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Activate or deactivate a user account',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  updateStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserStatusDto,
  ) {
    return this.adminUsersService.updateStatus(id, dto.isActive);
  }

  @Post('bulk-action')
  @AdminHighRisk()
  @HttpCode(HttpStatus.OK)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Bulk activate/deactivate/email/export users',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  bulkAction(@Body() dto: BulkActionDto) {
    return this.adminUsersService.bulkAction(dto);
  }
}

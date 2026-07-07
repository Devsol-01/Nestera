import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Patch,
  Param,
  Body,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { FeatureFlagsService } from './feature-flags.service';
import { CreateFlagDto } from './dto/create-flag.dto';
import { UpdateFlagDto } from './dto/update-flag.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';

@ApiTags('Feature Flags')
@Controller('feature-flags')
export class FeatureFlagsController {
  constructor(private readonly service: FeatureFlagsService) {}

  /** Public: fetch all flags (client-side bootstrap) */
  @Get()
  @ApiOperation({ summary: 'Get all feature flags' })
  @ApiResponse({ status: 200, description: 'List of all feature flags' })
  findAll() {
    return this.service.findAll();
  }

  /** Public: evaluate a specific flag for a user context */
  @Get(':key/evaluate')
  @ApiOperation({ summary: 'Evaluate a flag for a user context' })
  @ApiQuery({ name: 'address', required: false })
  @ApiQuery({ name: 'network', required: false })
  @ApiQuery({ name: 'segments', required: false, type: [String] })
  evaluate(
    @Param('key') key: string,
    @Query('address') address?: string,
    @Query('network') network?: string,
    @Query('segments') segments?: string | string[],
  ) {
    const segmentList = segments
      ? Array.isArray(segments)
        ? segments
        : [segments]
      : undefined;
    return this.service.evaluate(key, {
      address,
      network,
      segments: segmentList,
    });
  }

  /** Admin: get a single flag */
  @Get(':key')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT')
  @ApiOperation({ summary: 'Get a specific feature flag' })
  findOne(@Param('key') key: string) {
    return this.service.findOne(key);
  }

  /** Admin: create a flag */
  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT')
  @ApiOperation({ summary: 'Create a feature flag' })
  @ApiResponse({ status: 201, description: 'Flag created' })
  create(@Body() dto: CreateFlagDto) {
    return this.service.create(dto);
  }

  /** Admin: update a flag */
  @Put(':key')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT')
  @ApiOperation({ summary: 'Update a feature flag' })
  update(@Param('key') key: string, @Body() dto: UpdateFlagDto) {
    return this.service.update(key, dto);
  }

  /** Admin: toggle a flag on/off */
  @Patch(':key/toggle')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT')
  @ApiOperation({ summary: 'Toggle a feature flag on/off' })
  toggle(@Param('key') key: string) {
    return this.service.toggle(key);
  }

  /** Admin: delete a flag */
  @Delete(':key')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a feature flag' })
  @ApiResponse({ status: 204, description: 'Flag deleted' })
  remove(@Param('key') key: string) {
    return this.service.remove(key);
  }
}

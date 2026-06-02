import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiParam,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { WaitlistService } from './waitlist.service';

@ApiTags('savings')
@Controller('savings/products')
export class WaitlistController {
  constructor(private readonly waitlistService: WaitlistService) {}

  @Post(':id/waitlist')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'Product UUID' })
  @ApiOperation({ summary: 'Join waitlist for a savings product' })
  @ApiResponse({
    status: 201,
    description: 'Joined waitlist',
    schema: { example: { id: 'uuid', position: 5 } },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 409, description: 'Already on waitlist' })
  async join(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; email: string },
  ) {
    const { entry, position } = await this.waitlistService.joinWaitlist(
      user.id,
      id,
    );

    return { id: entry.id, position };
  }

  @Get(':id/waitlist/position')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'Product UUID' })
  @ApiOperation({ summary: 'Get current position on waitlist' })
  @ApiResponse({ status: 200, description: 'Waitlist position' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Not on waitlist' })
  async getPosition(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ) {
    const entry = await this.waitlistService.getUserEntry(user.id, id);
    const position = await this.waitlistService.getPosition(entry.id);
    return { id: entry.id, position, status: 'PENDING' };
  }

  @Delete(':id/waitlist/leave')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'Product UUID' })
  @ApiOperation({ summary: 'Leave waitlist for a savings product' })
  @ApiResponse({ status: 204, description: 'Left waitlist' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Not on waitlist' })
  async leaveWaitlist(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ) {
    await this.waitlistService.leaveWaitlist(user.id, id);
  }
}

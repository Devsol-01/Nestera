import {
  Controller,
  Get,
  Post,
  Delete,
  Patch,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { WalletService } from './wallet.service';
import { LinkWalletDto } from './dto/link-wallet.dto';

@ApiTags('users')
@ApiBearerAuth()
@Controller('users/wallets')
@UseGuards(JwtAuthGuard)
export class WalletController {
  constructor(private readonly walletService: WalletService) {}

  @Post('link')
  @ApiOperation({
    summary: 'Link a new Stellar wallet with signature verification',
  })
  @ApiBody({ type: LinkWalletDto })
  @ApiResponse({ status: 201, description: 'Wallet linked successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 409, description: 'Wallet already linked' })
  linkWallet(@CurrentUser() user: { id: string }, @Body() dto: LinkWalletDto) {
    return this.walletService.linkWallet(user.id, dto);
  }

  @Delete(':address/unlink')
  @ApiOperation({ summary: 'Unlink a wallet address' })
  @ApiParam({ name: 'address', description: 'Stellar public key to unlink' })
  @ApiResponse({ status: 200, description: 'Wallet unlinked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Wallet not found' })
  async unlinkWallet(
    @CurrentUser() user: { id: string },
    @Param('address') address: string,
  ) {
    await this.walletService.unlinkWallet(user.id, address);
    return { message: 'Wallet unlinked successfully' };
  }

  @Get()
  @ApiOperation({ summary: 'List all linked wallets' })
  @ApiResponse({ status: 200, description: 'List of linked wallets' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  listWallets(@CurrentUser() user: { id: string }) {
    return this.walletService.listWallets(user.id);
  }

  @Patch(':address/set-primary')
  @ApiOperation({ summary: 'Set a wallet as primary' })
  @ApiParam({
    name: 'address',
    description: 'Stellar public key to set as primary',
  })
  @ApiResponse({ status: 200, description: 'Primary wallet updated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Wallet not found' })
  setPrimary(
    @CurrentUser() user: { id: string },
    @Param('address') address: string,
  ) {
    return this.walletService.setPrimary(user.id, address);
  }
}

import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { IsStellarPublicKey } from '../../../common/validators/is-stellar-key.validator';
import { Trim } from '../../../common/decorators/trim.decorator';

export class LinkWalletDto {
  @ApiProperty({ description: 'Stellar public key (G...)', example: 'GABC1234DEFGH5678IJKL9012MNOP3456QRST7890UVWX' })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @IsStellarPublicKey()
  address: string;

  @ApiProperty({ description: 'Signed message proving wallet ownership', example: 'A1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVWXYZ1234567890ABCDEF' })
  @IsString()
  @IsNotEmpty()
  @Trim()
  signature: string;

  @ApiProperty({ description: 'The message that was signed', example: 'Sign this message to verify wallet ownership' })
  @IsString()
  @IsNotEmpty()
  @Trim()
  message: string;
}

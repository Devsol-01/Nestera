import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'alice@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'supersecret123' })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  password: string;

  @ApiProperty({ example: 'Alice', required: false })
  @IsString()
  name?: string;
}

export class LoginDto {
  @ApiProperty({ example: 'alice@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'supersecret123' })
  @IsString()
  password: string;
}

export class GetNonceDto {
  @ApiProperty({ example: 'GABC...' })
  @IsString()
  publicKey: string;
}

export class VerifySignatureDto {
  @ApiProperty({ example: 'GABC...' })
  @IsString()
  publicKey: string;

  @ApiProperty({ description: 'Hex-encoded Ed25519 signature over the nonce' })
  @IsString()
  signature: string;

  @ApiProperty({ description: 'The nonce returned by GET /auth/nonce' })
  @IsString()
  nonce: string;
}

/**
 * Body accepted by POST /auth/link-wallet.
 * The caller must:
 *  1. Fetch a nonce via GET /auth/nonce?publicKey=<key>
 *  2. Sign the nonce bytes with the wallet's Ed25519 secret key
 *  3. Submit this DTO together with a valid JWT (Bearer token)
 */
export class LinkWalletDto {
  @ApiProperty({
    example: 'GABC1234...',
    description: 'Stellar G... public key to link to the authenticated account',
  })
  @IsString()
  publicKey: string;

  @ApiProperty({
    description: 'The nonce returned by GET /auth/nonce?publicKey=<key>',
  })
  @IsString()
  nonce: string;

  @ApiProperty({
    description: 'Hex-encoded Ed25519 signature of the nonce bytes',
  })
  @IsString()
  signature: string;
}

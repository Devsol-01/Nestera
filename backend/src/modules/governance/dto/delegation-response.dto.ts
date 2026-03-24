import { ApiProperty } from '@nestjs/swagger';

export class DelegationResponseDto {
  @ApiProperty({
    description:
      'The delegated wallet address when an active delegation is configured, otherwise null.',
    nullable: true,
    example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN',
  })
  delegate: string | null;
}

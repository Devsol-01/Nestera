import { ApiProperty } from '@nestjs/swagger';

export class CreateAbTestDto {
  @ApiProperty({ example: 'Summer Welcome Campaign A/B Test' })
  name: string;

  @ApiProperty({ example: 'tpl-550e8400-e29b-41d4-a716-446655440000' })
  templateId: string;

  @ApiProperty({ example: [{ versionId: 'v1', weight: 50, key: 'control' }, { versionId: 'v2', weight: 50, key: 'variant' }], type: Array })
  variants: { versionId: string; weight?: number; key?: string }[];
}

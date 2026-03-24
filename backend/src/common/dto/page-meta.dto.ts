import { ApiProperty } from '@nestjs/swagger';
import { PageOptionsDto } from './page-options.dto';

export interface PageMetaDtoParameters {
  pageOptionsDto: PageOptionsDto;
  totalItemCount: number;
}

export class PageMetaDto {
  @ApiProperty({ description: 'Current page number' })
  readonly page: number;

  @ApiProperty({ description: 'Number of items per page' })
  readonly limit: number;

  @ApiProperty({ description: 'Total number of items' })
  readonly totalItemCount: number;

  @ApiProperty({ description: 'Total number of pages' })
  readonly pageCount: number;

  @ApiProperty({ description: 'Whether there is a previous page' })
  readonly hasPreviousPage: boolean;

  @ApiProperty({ description: 'Whether there is a next page' })
  readonly hasNextPage: boolean;

  constructor({ pageOptionsDto, totalItemCount }: PageMetaDtoParameters) {
    this.page = pageOptionsDto.page ?? 1;
    this.limit = pageOptionsDto.limit ?? 10;
    this.totalItemCount = totalItemCount;
    this.pageCount = Math.ceil(totalItemCount / this.limit);
    this.hasPreviousPage = this.page > 1;
    this.hasNextPage = this.page < this.pageCount;
  }
}

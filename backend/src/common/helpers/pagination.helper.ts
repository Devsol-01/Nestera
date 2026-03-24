import { ObjectLiteral, SelectQueryBuilder } from 'typeorm';
import { PageOptionsDto } from '../dto/page-options.dto';
import { PageMetaDto } from '../dto/page-meta.dto';
import { PageDto } from '../dto/page.dto';

/**
 * Applies pagination to a TypeORM SelectQueryBuilder and returns
 * a typed PageDto with data and metadata.
 *
 * @example
 * const query = this.userRepository.createQueryBuilder('user');
 * return paginate(query, pageOptionsDto);
 */
export async function paginate<T extends ObjectLiteral>(
  queryBuilder: SelectQueryBuilder<T>,
  pageOptionsDto: PageOptionsDto,
): Promise<PageDto<T>> {
  const { skip, limit, order } = pageOptionsDto;

  queryBuilder
    .orderBy(`${queryBuilder.alias}.createdAt`, order)
    .skip(skip)
    .take(limit);

  const [data, totalItemCount] = await queryBuilder.getManyAndCount();

  const meta = new PageMetaDto({ pageOptionsDto, totalItemCount });

  return new PageDto(data, meta);
}

/**
 * Returns TypeORM skip/take values from a PageOptionsDto.
 * Use this for simple repository queries that do not use QueryBuilder.
 *
 * @example
 * const { skip, take } = getSkipTake(pageOptionsDto);
 * return this.userRepository.findAndCount({ skip, take });
 */
export function getSkipTake(pageOptionsDto: PageOptionsDto): {
  skip: number;
  take: number;
} {
  return {
    skip: pageOptionsDto.skip,
    take: pageOptionsDto.limit ?? 10,
  };
}

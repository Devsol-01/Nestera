import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, SelectQueryBuilder, Brackets, IsNull } from 'typeorm';
import { Readable } from 'stream';
import { format as csvFormat } from '@fast-csv/format';
import {
  LedgerTransaction,
  LedgerTransactionStatus,
} from '../blockchain/entities/transaction.entity';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';
import { PageDto } from '../../common/dto/page.dto';
import { PageMetaDto } from '../../common/dto/page-meta.dto';
import { AutoCategorizationService } from './auto-categorization.service';
import { TransactionSearchCriteriaDto } from './dto/transaction-search-criteria.dto';
import { Order } from '../../common/dto/page-options.dto';
import { TransactionSavedSearch } from './entities/transaction-saved-search.entity';
import { CreateSavedSearchDto } from './dto/create-saved-search.dto';
import { UpdateSavedSearchDto } from './dto/update-saved-search.dto';
import { SavedSearchResponseDto } from './dto/saved-search-response.dto';
import {
  decodeCursor,
  encodeCursor,
} from '../../common/helpers/cursor-pagination.helper';
import { TransactionSortBy } from './dto/transaction-search-criteria.dto';

@Injectable()
export class TransactionsService {
  private static readonly SEARCH_QUERY_TIMEOUT_MS = 2000;
  private static readonly SEARCH_MAX_RESULTS = 50;

  private readonly sortableColumns = {
    createdAt: 'transaction.createdAt',
    amount: 'transaction.amount',
    type: 'transaction.type',
    status: 'transaction.status',
  } as const;

  constructor(
    @InjectRepository(LedgerTransaction)
    private readonly transactionRepository: Repository<LedgerTransaction>,
    @InjectRepository(TransactionSavedSearch)
    private readonly savedSearchRepository: Repository<TransactionSavedSearch>,
    private readonly autoCategorizationService: AutoCategorizationService,
  ) {}

  async findAllForUser(
    userId: string,
    queryDto: TransactionQueryDto,
  ): Promise<PageDto<TransactionResponseDto>> {
    if (queryDto.cursor && queryDto.sortBy !== TransactionSortBy.CREATED_AT) {
      throw new BadRequestException(
        'Cursor pagination is only supported when sortBy=createdAt',
      );
    }

    const queryBuilder = this.buildQuery(userId, queryDto);
    const pageSize = this.getSafePageSize(queryDto);
    const skip = this.getSafeSkip(queryDto, pageSize);

    if (queryDto.cursor) {
      const cursor = decodeCursor(queryDto.cursor);
      const order = queryDto.order ?? Order.DESC;
      const operator = order === Order.ASC ? '>' : '<';
      queryBuilder.andWhere(
        `(transaction.createdAt ${operator} :cursorCreatedAt OR (transaction.createdAt = :cursorCreatedAt AND transaction.id ${operator} :cursorId))`,
        {
          cursorCreatedAt: new Date(cursor.createdAt),
          cursorId: cursor.id,
        },
      );
    } else {
      queryBuilder.skip(skip);
    }
    queryBuilder.take(pageSize + 1);

    const rows = await queryBuilder.getMany();
    const hasMore = rows.length > pageSize;
    const data = hasMore ? rows.slice(0, pageSize) : rows;
    const transformedData = data.map((transaction) =>
      this.transformToResponseDto(transaction),
    );
    const nextCursor =
      hasMore && data.length > 0
        ? encodeCursor({
            createdAt: data[data.length - 1].createdAt.toISOString(),
            id: data[data.length - 1].id,
          })
        : null;
    const totalItemCount = queryDto.shouldIncludeTotal
      ? await this.buildQuery(userId, queryDto).getCount()
      : undefined;

    const meta = new PageMetaDto({
      pageOptionsDto: queryDto,
      totalItemCount,
      nextCursor,
    });

    return new PageDto(transformedData, meta);
  }

  async exportTransactions(
    userId: string,
    queryDto: TransactionQueryDto,
  ): Promise<TransactionResponseDto[]> {
    const data = await this.buildQuery(userId, queryDto).getMany();
    return data.map((transaction) => this.transformToResponseDto(transaction));
  }

  async streamTransactionsCsv(
    userId: string,
    queryDto: TransactionQueryDto,
  ): Promise<Readable> {
    const chunkSize = Math.min(Number(queryDto.limit ?? 1000), 1000);
    let offset = 0;

    const csvStream = csvFormat({ headers: true, quoteColumns: true });

    (async () => {
      try {
        while (true) {
          const batch = await this.buildQuery(userId, queryDto)
            .skip(offset)
            .take(chunkSize)
            .getMany();

          if (!batch.length) {
            break;
          }

          for (const tx of batch) {
            const dto = this.transformToResponseDto(tx);
            csvStream.write({
              id: dto.id,
              userId: dto.userId,
              type: dto.type,
              status: dto.status,
              amount: dto.amount,
              amountFormatted: dto.amountFormatted?.display ?? '',
              publicKey: dto.publicKey ?? '',
              eventId: dto.eventId,
              transactionHash: dto.transactionHash ?? '',
              category: dto.category ?? '',
              tags: dto.tags ? dto.tags.join(';') : '',
              ledgerSequence: dto.ledgerSequence ?? '',
              poolId: dto.poolId ?? '',
              assetId: dto.assetId ?? '',
              metadata: dto.metadata ? JSON.stringify(dto.metadata) : '',
              createdAt: dto.createdAt,
            });
          }

          offset += chunkSize;
        }
      } catch (error) {
        csvStream.destroy(error as Error);
      } finally {
        csvStream.end();
      }
    })();

    return csvStream;
  }

  async createSavedSearch(
    userId: string,
    dto: CreateSavedSearchDto,
  ): Promise<SavedSearchResponseDto> {
    if (dto.isDefault) {
      await this.clearDefaultSavedSearch(userId);
    }

    const savedSearch = this.savedSearchRepository.create({
      userId,
      name: dto.name.trim(),
      description: dto.description?.trim() ?? null,
      query: this.normalizeSearchCriteria(dto.query),
      isDefault: dto.isDefault ?? false,
    });

    const saved = await this.savedSearchRepository.save(savedSearch);
    return this.toSavedSearchResponse(saved);
  }

  async listSavedSearches(userId: string): Promise<SavedSearchResponseDto[]> {
    // Stable sort: isDefault first, then most recently updated, then id as a
    // tie-breaker so concurrent updates at the same millisecond are deterministic.
    const rows = await this.savedSearchRepository.find({
      where: { userId },
      order: { isDefault: 'DESC', updatedAt: 'DESC', id: 'ASC' },
    });

    return rows.map((row) => this.toSavedSearchResponse(row));
  }

  async updateSavedSearch(
    userId: string,
    id: string,
    dto: UpdateSavedSearchDto,
  ): Promise<SavedSearchResponseDto | { ok: false; message: string }> {
    const savedSearch = await this.savedSearchRepository.findOne({
      where: { id, userId },
    });

    if (!savedSearch) {
      return { ok: false, message: 'Saved search not found' };
    }

    if (dto.isDefault) {
      await this.clearDefaultSavedSearch(userId, id);
    }

    if (typeof dto.name === 'string') {
      savedSearch.name = dto.name.trim();
    }
    if (dto.description !== undefined) {
      savedSearch.description = dto.description?.trim() ?? null;
    }
    if (dto.query) {
      savedSearch.query = this.normalizeSearchCriteria(dto.query);
    }
    if (dto.isDefault !== undefined) {
      savedSearch.isDefault = dto.isDefault;
    }

    const updated = await this.savedSearchRepository.save(savedSearch);
    return this.toSavedSearchResponse(updated);
  }

  async deleteSavedSearch(
    userId: string,
    id: string,
  ): Promise<{ ok: boolean; message?: string }> {
    const result = await this.savedSearchRepository.delete({ id, userId });
    if (!result.affected) {
      return { ok: false, message: 'Saved search not found' };
    }
    return { ok: true };
  }

  async runSavedSearch(
    userId: string,
    id: string,
    pagination?: Pick<TransactionQueryDto, 'page' | 'limit'>,
  ): Promise<PageDto<TransactionResponseDto> | { ok: false; message: string }> {
    const savedSearch = await this.savedSearchRepository.findOne({
      where: { id, userId },
    });

    if (!savedSearch) {
      return { ok: false, message: 'Saved search not found' };
    }

    const queryDto = Object.assign(
      new TransactionQueryDto(),
      savedSearch.query,
      {
        page: pagination?.page ?? 1,
        limit: pagination?.limit ?? 10,
        order: (savedSearch.query.order as Order | undefined) ?? Order.DESC,
      },
    );

    return this.findAllForUser(userId, queryDto);
  }

  private buildQuery(
    userId: string,
    queryDto: TransactionSearchCriteriaDto,
  ): SelectQueryBuilder<LedgerTransaction> {
    const queryBuilder = this.transactionRepository
      .createQueryBuilder('transaction')
      .where('transaction.userId = :userId', { userId });

    if (queryDto.type?.length) {
      queryBuilder.andWhere('transaction.type IN (:...types)', {
        types: queryDto.type,
      });
    }

    if (queryDto.status?.length) {
      queryBuilder.andWhere('transaction.status IN (:...statuses)', {
        statuses: queryDto.status,
      });
    }

    if (queryDto.startDate) {
      queryBuilder.andWhere('transaction.createdAt >= :startDate', {
        startDate: new Date(queryDto.startDate),
      });
    }

    if (queryDto.endDate) {
      queryBuilder.andWhere('transaction.createdAt <= :endDate', {
        endDate: new Date(queryDto.endDate),
      });
    }

    if (queryDto.minAmount) {
      queryBuilder.andWhere('transaction.amount >= :minAmount', {
        minAmount: queryDto.minAmount,
      });
    }

    if (queryDto.maxAmount) {
      queryBuilder.andWhere('transaction.amount <= :maxAmount', {
        maxAmount: queryDto.maxAmount,
      });
    }

    if (queryDto.poolId) {
      queryBuilder.andWhere('transaction.poolId = :poolId', {
        poolId: queryDto.poolId,
      });
    }

    if (queryDto.category) {
      queryBuilder.andWhere('transaction.category = :category', {
        category: queryDto.category,
      });
    }

    if (queryDto.tags?.length) {
      queryBuilder.andWhere('transaction.tags && :tags', {
        tags: queryDto.tags,
      });
    }

    if (queryDto.search?.trim()) {
      const searchText = queryDto.search.trim();
      const searchLike = `%${searchText}%`;

      queryBuilder.andWhere(
        new Brackets((qb) => {
          qb.where(
            `to_tsvector('simple',
              concat_ws(' ',
                coalesce(transaction."txHash", ''),
                coalesce(transaction."eventId", ''),
                coalesce(transaction."publicKey", ''),
                coalesce(transaction."poolId", ''),
                coalesce(transaction.category, ''),
                coalesce(transaction.status::text, ''),
                coalesce(transaction.type::text, ''),
                coalesce(transaction.metadata::text, ''),
                array_to_string(transaction.tags, ' ')
              )
            ) @@ websearch_to_tsquery('simple', :searchText)`,
            { searchText },
          )
            .orWhere('transaction.txHash ILIKE :searchLike', { searchLike })
            .orWhere('transaction.eventId ILIKE :searchLike', { searchLike })
            .orWhere('transaction.publicKey ILIKE :searchLike', {
              searchLike,
            })
            .orWhere('transaction.poolId ILIKE :searchLike', { searchLike })
            .orWhere('transaction.category ILIKE :searchLike', { searchLike })
            .orWhere('transaction.status::text ILIKE :searchLike', {
              searchLike,
            })
            .orWhere('transaction.type::text ILIKE :searchLike', { searchLike })
            .orWhere('CAST(transaction.amount AS TEXT) ILIKE :searchLike', {
              searchLike,
            })
            .orWhere(
              "COALESCE(transaction.metadata::text, '') ILIKE :searchLike",
              {
                searchLike,
              },
            )
            .orWhere(
              `array_to_string(transaction.tags, ' ') ILIKE :searchLike`,
              { searchLike },
            );
        }),
      );
    }

    const sortBy = queryDto.sortBy ?? 'createdAt';
    const orderByColumn =
      this.sortableColumns[sortBy] ?? this.sortableColumns.createdAt;
    const order = queryDto.order ?? Order.DESC;

    if (queryDto.search?.trim()) {
      const searchText = queryDto.search.trim();
      const searchLike = `%${searchText}%`;
      const searchPrefix = `${searchText}%`;

      (queryBuilder as unknown as { timeout: (ms: number) => void }).timeout(
        TransactionsService.SEARCH_QUERY_TIMEOUT_MS,
      );
      queryBuilder.orderBy(
        `CASE
          WHEN LOWER(COALESCE(transaction."txHash", '')) = LOWER(:searchText) THEN 120
          WHEN LOWER(COALESCE(transaction."txHash", '')) LIKE LOWER(:searchPrefix) THEN 110
          WHEN LOWER(COALESCE(transaction."eventId", '')) = LOWER(:searchText) THEN 105
          WHEN LOWER(COALESCE(transaction."eventId", '')) LIKE LOWER(:searchPrefix) THEN 100
          WHEN LOWER(COALESCE(transaction."publicKey", '')) = LOWER(:searchText) THEN 95
          WHEN LOWER(COALESCE(transaction."publicKey", '')) LIKE LOWER(:searchPrefix) THEN 90
          WHEN LOWER(COALESCE(transaction."poolId", '')) = LOWER(:searchText) THEN 85
          WHEN LOWER(COALESCE(transaction."poolId", '')) LIKE LOWER(:searchPrefix) THEN 80
          WHEN LOWER(COALESCE(transaction.category, '')) = LOWER(:searchText) THEN 75
          WHEN LOWER(COALESCE(transaction.category, '')) LIKE LOWER(:searchPrefix) THEN 70
          WHEN LOWER(COALESCE(transaction.metadata->>'memo', '')) = LOWER(:searchText) THEN 65
          WHEN LOWER(COALESCE(transaction.metadata->>'memo', '')) LIKE LOWER(:searchPrefix) THEN 60
          WHEN LOWER(COALESCE(transaction.metadata->>'description', '')) = LOWER(:searchText) THEN 55
          WHEN LOWER(COALESCE(transaction.metadata->>'description', '')) LIKE LOWER(:searchPrefix) THEN 50
          WHEN LOWER(COALESCE(transaction.metadata->>'referenceId', '')) = LOWER(:searchText) THEN 48
          WHEN LOWER(COALESCE(transaction.metadata->>'referenceId', '')) LIKE LOWER(:searchPrefix) THEN 46
          WHEN LOWER(COALESCE(transaction.metadata->>'reference_id', '')) = LOWER(:searchText) THEN 44
          WHEN LOWER(COALESCE(transaction.metadata->>'reference_id', '')) LIKE LOWER(:searchPrefix) THEN 42
          WHEN LOWER(COALESCE(transaction.metadata->>'userReferenceId', '')) = LOWER(:searchText) THEN 40
          WHEN LOWER(COALESCE(transaction.metadata->>'userReferenceId', '')) LIKE LOWER(:searchPrefix) THEN 38
          WHEN LOWER(COALESCE(transaction.metadata->>'user_reference_id', '')) = LOWER(:searchText) THEN 36
          WHEN LOWER(COALESCE(transaction.metadata->>'user_reference_id', '')) LIKE LOWER(:searchPrefix) THEN 34
          WHEN LOWER(COALESCE(transaction.metadata::text, '')) LIKE LOWER(:searchLike) THEN 20
          WHEN LOWER(COALESCE(transaction.status::text, '')) LIKE LOWER(:searchLike) THEN 15
          WHEN LOWER(COALESCE(transaction.type::text, '')) LIKE LOWER(:searchLike) THEN 12
          WHEN LOWER(CAST(transaction.amount AS TEXT)) LIKE LOWER(:searchLike) THEN 10
          WHEN LOWER(COALESCE(array_to_string(transaction.tags, ' '), '')) LIKE LOWER(:searchLike) THEN 8
          ELSE 0
        END`,
        'DESC',
      );
      queryBuilder.addOrderBy(orderByColumn, order);
      queryBuilder.addOrderBy('transaction.id', order);

      queryBuilder.setParameters({
        searchText,
        searchPrefix,
        searchLike,
      });

      return queryBuilder;
    }

    queryBuilder.orderBy(orderByColumn, order);
    queryBuilder.addOrderBy('transaction.id', order);

    return queryBuilder;
  }

  private getSafePageSize(queryDto: TransactionQueryDto): number {
    const maxResults = queryDto.search?.trim()
      ? TransactionsService.SEARCH_MAX_RESULTS
      : 100;

    return Math.min(Math.max(queryDto.pageSize, 1), maxResults);
  }

  private getSafeSkip(queryDto: TransactionQueryDto, pageSize: number): number {
    return ((queryDto.page ?? 1) - 1) * pageSize;
  }

  private transformToResponseDto(
    transaction: LedgerTransaction,
  ): TransactionResponseDto {
    const createdAt = new Date(transaction.createdAt);
    const assetId = this.extractAssetId(transaction);

    return {
      id: transaction.id,
      userId: transaction.userId,
      type: transaction.type,
      status: transaction.status ?? LedgerTransactionStatus.COMPLETED,
      amount: transaction.amount,
      publicKey: transaction.publicKey,
      eventId: transaction.eventId ?? '',
      transactionHash: transaction.transactionHash,
      category: transaction.category ?? null,
      tags: transaction.tags ?? [],
      ledgerSequence: transaction.ledgerSequence,
      poolId: transaction.poolId,
      metadata: transaction.metadata,
      createdAt: createdAt.toISOString(),
      formattedDate: createdAt.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      }),
      formattedTime: createdAt.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      assetId,
    } as TransactionResponseDto;
  }

  async tagTransaction(userId: string, transactionId: string, payload: any) {
    const tx = await this.transactionRepository.findOne({
      where: { id: transactionId, userId },
    });

    if (!tx) {
      return { ok: false, message: 'Transaction not found' };
    }

    if (payload?.tags) {
      const current = tx.tags ?? [];
      const incoming = Array.isArray(payload.tags) ? payload.tags : [];

      if (payload.action === 'remove') {
        tx.tags = current.filter((t) => !incoming.includes(t));
      } else if (payload.action === 'set') {
        tx.tags = incoming;
      } else {
        const set = new Set(current.concat(incoming));
        tx.tags = Array.from(set);
      }
    }

    if (typeof payload?.category === 'string') {
      tx.category = payload.category;
    }

    await this.transactionRepository.save(tx);

    return { ok: true, transaction: this.transformToResponseDto(tx) };
  }

  async listCategories(userId: string) {
    const rows = await this.transactionRepository
      .createQueryBuilder('transaction')
      .select('DISTINCT transaction.category', 'category')
      .where('transaction.userId = :userId', { userId })
      .andWhere('transaction.category IS NOT NULL')
      .orderBy('transaction.category', 'ASC')
      .getRawMany();

    return rows.map((r) => r.category);
  }

  async bulkTag(userId: string, body: any) {
    if (!body?.ids || !Array.isArray(body.ids) || !body.ids.length) {
      return { ok: false, message: 'No ids provided' };
    }

    const txs = await this.transactionRepository.findBy({
      id: body.ids,
      userId,
    });

    for (const tx of txs) {
      if (body.tags) {
        const current = tx.tags ?? [];
        const incoming = Array.isArray(body.tags) ? body.tags : [];

        if (body.action === 'remove') {
          tx.tags = current.filter((t) => !incoming.includes(t));
        } else if (body.action === 'set') {
          tx.tags = incoming;
        } else {
          const set = new Set(current.concat(incoming));
          tx.tags = Array.from(set);
        }
      }

      if (typeof body.category === 'string') {
        tx.category = body.category;
      }
    }

    await this.transactionRepository.save(txs);
    return { ok: true, count: txs.length };
  }

  private extractAssetId(transaction: LedgerTransaction): string {
    if (transaction.metadata?.assetId) {
      return transaction.metadata.assetId as string;
    }

    if (transaction.metadata?.contractId) {
      return transaction.metadata.contractId as string;
    }

    return 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA';
  }

  async autoCategorizeTransaction(userId: string, transactionId: string) {
    const tx = await this.transactionRepository.findOne({
      where: { id: transactionId, userId },
    });

    if (!tx) {
      return { ok: false, message: 'Transaction not found' };
    }

    const categorization = this.autoCategorizationService.categorize(tx);
    if (categorization) {
      tx.category = categorization.category;
      tx.tags = Array.from(
        new Set([...(tx.tags ?? []), ...categorization.tags]),
      );
      await this.transactionRepository.save(tx);
    }

    return { ok: true, transaction: this.transformToResponseDto(tx) };
  }

  async autoCategorizeAll(userId: string) {
    const txs = await this.transactionRepository.findBy({
      userId,
      category: IsNull(),
    });

    let updated = 0;
    for (const tx of txs) {
      const categorization = this.autoCategorizationService.categorize(tx);
      if (categorization) {
        tx.category = categorization.category;
        tx.tags = Array.from(
          new Set([...(tx.tags ?? []), ...categorization.tags]),
        );
        updated += 1;
      }
    }

    if (updated > 0) {
      await this.transactionRepository.save(txs);
    }

    return { ok: true, count: updated };
  }

  async getTagAnalytics(userId: string) {
    const tagCounts = await this.transactionRepository
      .createQueryBuilder('transaction')
      .select('unnest(transaction.tags)', 'tag')
      .addSelect('COUNT(*)', 'count')
      .where('transaction.userId = :userId', { userId })
      .groupBy('tag')
      .orderBy('count', 'DESC')
      .getRawMany();

    const categoryStats = await this.transactionRepository
      .createQueryBuilder('transaction')
      .select('transaction.category', 'category')
      .addSelect('COUNT(*)', 'count')
      .where('transaction.userId = :userId', { userId })
      .andWhere('transaction.category IS NOT NULL')
      .groupBy('transaction.category')
      .orderBy('count', 'DESC')
      .getRawMany();

    return {
      tags: tagCounts.map((row) => ({
        tag: row.tag,
        count: Number(row.count),
      })),
      categories: categoryStats.map((row) => ({
        category: row.category,
        count: Number(row.count),
      })),
    };
  }

  private normalizeSearchCriteria(
    query: TransactionSearchCriteriaDto,
  ): Record<string, unknown> {
    return Object.fromEntries(
      Object.entries(query).filter(([, value]) => value !== undefined),
    );
  }

  private toSavedSearchResponse(
    savedSearch: TransactionSavedSearch,
  ): SavedSearchResponseDto {
    return {
      id: savedSearch.id,
      userId: savedSearch.userId,
      name: savedSearch.name,
      description: savedSearch.description,
      query: savedSearch.query,
      isDefault: savedSearch.isDefault,
      createdAt: savedSearch.createdAt.toISOString(),
      updatedAt: savedSearch.updatedAt.toISOString(),
    };
  }

  private async clearDefaultSavedSearch(
    userId: string,
    excludeId?: string,
  ): Promise<void> {
    const query = this.savedSearchRepository
      .createQueryBuilder()
      .update(TransactionSavedSearch)
      .set({ isDefault: false })
      .where('userId = :userId', { userId });

    if (excludeId) {
      query.andWhere('id != :excludeId', { excludeId });
    }

    await query.execute();
  }
}

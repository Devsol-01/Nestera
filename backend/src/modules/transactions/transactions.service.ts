import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, SelectQueryBuilder } from 'typeorm';
import { Readable } from 'stream';
import { format as csvFormat } from '@fast-csv/format';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';
import { TransactionQueryDto } from './dto/transaction-query.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';
import { PageDto } from '../../common/dto/page.dto';
import { PageMetaDto } from '../../common/dto/page-meta.dto';
import { CurrencyService } from '../currency/currency.service';

@Injectable()
export class TransactionsService {
  constructor(
    @InjectRepository(LedgerTransaction)
    private readonly transactionRepository: Repository<LedgerTransaction>,
    private readonly currencyService: CurrencyService,
  ) {}

  async findAllForUser(
    userId: string,
    queryDto: TransactionQueryDto,
  ): Promise<PageDto<TransactionResponseDto>> {
    const queryBuilder = this.buildQuery(userId, queryDto);

    // Apply pagination
    queryBuilder.skip(queryDto.skip).take(queryDto.limit ?? 10);

    const [data, totalItemCount] = await queryBuilder.getManyAndCount();

    // Transform to response DTOs with formatted dates
    const transformedData = data.map((transaction) =>
      this.transformToResponseDto(transaction),
    );

    const meta = new PageMetaDto({
      pageOptionsDto: queryDto,
      totalItemCount,
    });

    return new PageDto(transformedData, meta);
  }

  async streamTransactionsCsv(
    userId: string,
    queryDto: TransactionQueryDto,
  ): Promise<Readable> {
    const chunkSize = Number(queryDto.limit ?? 1000);
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
              amount: dto.amount,
              currencyCode: dto.currencyCode,
              amountBaseCurrency: dto.amountBaseCurrency ?? '',
              conversionRateToBase: dto.conversionRateToBase ?? '',
              amountFormatted: dto.amountFormatted?.display ?? '',
              publicKey: dto.publicKey ?? '',
              eventId: dto.eventId,
              transactionHash: dto.transactionHash ?? '',
              category: dto.category ?? '',
              tags: dto.tags ? dto.tags.join(';') : '',
              ledgerSequence: dto.ledgerSequence ?? '',
              poolId: dto.poolId ?? '',
              assetId: dto.assetId ?? '',
              assetCode: dto.assetCode ?? '',
              assetIssuer: dto.assetIssuer ?? '',
              metadata: dto.metadata ? JSON.stringify(dto.metadata) : '',
              createdAt: dto.createdAt,
            });
          }

          offset += chunkSize;
        }
      } catch (error) {
        csvStream.destroy(error);
      } finally {
        csvStream.end();
      }
    })();

    return csvStream;
  }

  private buildQuery(
    userId: string,
    queryDto: TransactionQueryDto,
  ): SelectQueryBuilder<LedgerTransaction> {
    const queryBuilder = this.transactionRepository
      .createQueryBuilder('transaction')
      .where('transaction.userId = :userId', { userId });

    // Filter by transaction types
    if (queryDto.type && queryDto.type.length > 0) {
      queryBuilder.andWhere('transaction.type IN (:...types)', {
        types: queryDto.type,
      });
    }

    // Filter by date range
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

    // Filter by pool ID
    if (queryDto.poolId) {
      queryBuilder.andWhere('transaction.poolId = :poolId', {
        poolId: queryDto.poolId,
      });
    }

    // Filter by category
    if (queryDto.category) {
      queryBuilder.andWhere('transaction.category = :category', {
        category: queryDto.category,
      });
    }

    if (queryDto.currencyCode) {
      queryBuilder.andWhere('transaction.currencyCode = :currencyCode', {
        currencyCode: queryDto.currencyCode,
      });
    }

    // Filter by tags (any overlap)
    if (queryDto.tags && queryDto.tags.length > 0) {
      // Use Postgres array overlap operator (&&)
      queryBuilder.andWhere('transaction.tags && :tags', {
        tags: queryDto.tags,
      });
    }

    // Apply ordering
    queryBuilder.orderBy('transaction.createdAt', queryDto.order ?? 'DESC');

    return queryBuilder;
  }

  private transformToResponseDto(
    transaction: LedgerTransaction,
  ): TransactionResponseDto {
    const createdAt = new Date(transaction.createdAt);

    const currency = this.currencyService.resolveCurrencyFromAsset({
      currencyCode: transaction.currencyCode,
      assetCode: transaction.assetCode,
      assetContractId:
        transaction.assetContractId ?? this.extractAssetId(transaction),
    });

    const normalized =
      Number(transaction.amount) > 0
        ? this.currencyService.normalizeAmount(
            transaction.amount,
            currency.code,
          )
        : {
            amountBaseCurrency: transaction.amount,
            conversionRateToBase: currency.conversion.rateToBase,
          };

    return {
      id: transaction.id,
      userId: transaction.userId,
      type: transaction.type,
      amount: transaction.amount,
      currencyCode: currency.code,
      amountBaseCurrency:
        transaction.amountBaseCurrency ?? normalized.amountBaseCurrency,
      conversionRateToBase:
        transaction.conversionRateToBase ?? normalized.conversionRateToBase,
      publicKey: transaction.publicKey,
      eventId: transaction.eventId,
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
      // Add assetId for interceptor formatting (will be enriched by interceptor)
      assetId:
        transaction.assetContractId ??
        currency.contractId ??
        this.extractAssetId(transaction),
      assetCode: transaction.assetCode ?? currency.stellarAssetCode,
      assetIssuer: transaction.assetIssuer ?? currency.issuer ?? null,
    } as TransactionResponseDto;
  }

  async tagTransaction(userId: string, transactionId: string, payload: any) {
    const tx = await this.transactionRepository.findOne({
      where: { id: transactionId, userId },
    });

    if (!tx) {
      return { ok: false, message: 'Transaction not found' };
    }

    // Handle tags
    if (payload?.tags) {
      const current = tx.tags ?? [];
      const incoming = Array.isArray(payload.tags) ? payload.tags : [];

      if (payload.action === 'remove') {
        tx.tags = current.filter((t) => !incoming.includes(t));
      } else if (payload.action === 'set') {
        tx.tags = incoming;
      } else {
        // add
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
    // Support ids-based operations for now
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

  /**
   * Extract asset ID from transaction metadata or return default
   */
  private extractAssetId(transaction: LedgerTransaction): string {
    if (transaction.assetContractId) {
      return transaction.assetContractId;
    }

    // Check metadata for asset information
    if (transaction.metadata?.assetId) {
      return transaction.metadata.assetId as string;
    }

    if (transaction.metadata?.contractId) {
      return transaction.metadata.contractId as string;
    }

    // Check if poolId corresponds to a known asset
    // For now, default to USDC as it's the primary asset
    return 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA';
  }
}

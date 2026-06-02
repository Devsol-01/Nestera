import { createHash } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { scValToNative, xdr } from '@stellar/stellar-sdk';
import {
  LedgerTransaction,
  LedgerTransactionType,
} from '../entities/transaction.entity';
import {
  SubscriptionStatus,
  UserSubscription,
} from '../../savings/entities/user-subscription.entity';
import { User } from '../../user/entities/user.entity';
import { SavingsProduct } from '../../savings/entities/savings-product.entity';
import { CurrencyService } from '../../currency/currency.service';

interface IndexerEvent {
  id?: string;
  topic?: unknown[];
  value?: unknown;
  txHash?: string;
  ledger?: number;
  [key: string]: unknown;
}

interface DepositPayload {
  publicKey: string;
  amount: string;
  currencyCode: string;
  assetCode: string | null;
  assetIssuer: string | null;
  assetContractId: string | null;
}

@Injectable()
export class DepositHandler {
  private readonly logger = new Logger(DepositHandler.name);
  private static readonly DEPOSIT_HASH_HEX = createHash('sha256')
    .update('Deposit')
    .digest('hex');

  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
    private readonly currencyService: CurrencyService,
  ) {}

  async handle(event: IndexerEvent): Promise<boolean> {
    if (!this.isDepositTopic(event.topic)) {
      return false;
    }

    const payload = this.extractPayload(event.value);
    const currency = this.currencyService.resolveCurrencyFromAsset(payload);
    const normalizedAmount = this.currencyService.normalizeAmount(
      payload.amount,
      currency.code,
    );
    const eventId = this.resolveEventId(event);

    await this.dataSource.transaction(async (manager) => {
      const userRepo = manager.getRepository(User);
      const txRepo = manager.getRepository(LedgerTransaction);
      const subRepo = manager.getRepository(UserSubscription);
      const productRepo = manager.getRepository(SavingsProduct);

      const user = await userRepo.findOne({
        where: [
          { publicKey: payload.publicKey },
          { walletAddress: payload.publicKey },
        ],
      });

      if (!user) {
        throw new Error(
          `Cannot map deposit payload publicKey to user: ${payload.publicKey}`,
        );
      }

      const existingTx = await txRepo.findOne({ where: { eventId } });
      if (existingTx) {
        this.logger.debug(
          `Deposit event ${eventId} already persisted. Skipping.`,
        );
        return;
      }

      await txRepo.save(
        txRepo.create({
          userId: user.id,
          type: LedgerTransactionType.DEPOSIT,
          amount: payload.amount,
          currencyCode: currency.code,
          assetCode: payload.assetCode ?? currency.stellarAssetCode,
          assetIssuer: payload.assetIssuer ?? currency.issuer ?? null,
          assetContractId:
            payload.assetContractId ?? currency.contractId ?? null,
          amountBaseCurrency: normalizedAmount.amountBaseCurrency,
          conversionRateToBase: normalizedAmount.conversionRateToBase,
          publicKey: payload.publicKey,
          eventId,
          transactionHash:
            typeof event.txHash === 'string' ? event.txHash : null,
          ledgerSequence:
            typeof event.ledger === 'number' ? String(event.ledger) : null,
          metadata: {
            topic: event.topic,
            rawValueType: typeof event.value,
            currencyCode: currency.code,
          },
        }),
      );

      const amountAsNumber = Number(payload.amount);

      let subscription = await subRepo.findOne({
        where: {
          userId: user.id,
          status: SubscriptionStatus.ACTIVE,
        },
        order: { createdAt: 'DESC' },
      });

      if (!subscription) {
        const defaultProduct = user.defaultSavingsProductId
          ? await productRepo.findOne({
              where: { id: user.defaultSavingsProductId },
            })
          : await productRepo.findOne({
              where: { isActive: true },
              order: { createdAt: 'ASC' },
            });

        if (!defaultProduct) {
          throw new Error(
            'No savings product found to create subscription aggregate.',
          );
        }

        subscription = subRepo.create({
          userId: user.id,
          productId: defaultProduct.id,
          amount: amountAsNumber,
          currencyCode: currency.code,
          status: SubscriptionStatus.ACTIVE,
          startDate: new Date(),
          endDate: null,
        });
      } else {
        subscription.amount = Number(subscription.amount) + amountAsNumber;
      }

      await subRepo.save(subscription);
    });

    return true;
  }

  private isDepositTopic(topic: unknown[] | undefined): boolean {
    if (!Array.isArray(topic) || topic.length === 0) {
      return false;
    }

    const first = topic[0];
    const normalized = this.toHex(first);

    // Some contracts emit the symbol 'Deposit' directly, others emit its SHA256 hash
    // We handle both cases for robustness
    if (normalized === DepositHandler.DEPOSIT_HASH_HEX) {
      return true;
    }

    // Check if it's the symbol 'Deposit' (base64 XDR for Symbol("Deposit") is 'AAAADAAAAAAHrgAA')
    if (typeof first === 'string') {
      try {
        const scVal = xdr.ScVal.fromXDR(first, 'base64');
        if (scValToNative(scVal) === 'Deposit') {
          return true;
        }
      } catch {
        // Not XDR, ignore
      }
    }

    return false;
  }

  private extractPayload(value: unknown): DepositPayload {
    const decoded = this.decodeScVal(value);
    const asRecord = this.ensureObject(decoded);

    const publicKey =
      this.pickString(asRecord, [
        'publicKey',
        'userPublicKey',
        'user',
        'address',
        'to',
      ]) ?? '';

    const amountRaw =
      asRecord['amount'] ?? asRecord['value'] ?? asRecord['amt'];

    const amount =
      typeof amountRaw === 'bigint'
        ? amountRaw.toString()
        : typeof amountRaw === 'number'
          ? String(amountRaw)
          : typeof amountRaw === 'string'
            ? amountRaw
            : '';

    if (!publicKey || !amount || Number.isNaN(Number(amount))) {
      throw new Error(
        `Invalid Deposit payload: expected publicKey + numeric amount. Got: PK=${publicKey}, Amt=${amount}`,
      );
    }

    return { publicKey, amount, ...this.extractCurrencyFields(asRecord) };
  }

  private extractCurrencyFields(record: Record<string, unknown>) {
    return {
      currencyCode:
        this.pickString(record, ['currencyCode', 'currency', 'asset']) ??
        'USDC',
      assetCode: this.pickString(record, ['assetCode', 'code']),
      assetIssuer: this.pickString(record, ['assetIssuer', 'issuer']),
      assetContractId: this.pickString(record, [
        'assetContractId',
        'contractId',
        'assetId',
      ]),
    };
  }

  private resolveEventId(event: IndexerEvent): string {
    if (typeof event.id === 'string' && event.id.length > 0) {
      return event.id;
    }

    const txHash = typeof event.txHash === 'string' ? event.txHash : 'unknown';
    const ledger = typeof event.ledger === 'number' ? event.ledger : 0;
    return `${txHash}:${ledger}:deposit`;
  }

  private decodeScVal(value: unknown): unknown {
    if (
      value &&
      typeof value === 'object' &&
      'toXDR' in value &&
      typeof (value as { toXDR?: unknown }).toXDR === 'function'
    ) {
      const base64 = (value as { toXDR: (encoding?: string) => string }).toXDR(
        'base64',
      );
      const scVal = xdr.ScVal.fromXDR(base64, 'base64');
      return scValToNative(scVal);
    }

    if (typeof value === 'string') {
      try {
        const scVal = xdr.ScVal.fromXDR(value, 'base64');
        return scValToNative(scVal);
      } catch {
        return value;
      }
    }

    return value;
  }

  private ensureObject(value: unknown): Record<string, unknown> {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }

    throw new Error('Unexpected Deposit payload shape.');
  }

  private pickString(
    record: Record<string, unknown>,
    keys: string[],
  ): string | null {
    for (const key of keys) {
      const value = record[key];
      if (typeof value === 'string' && value.trim().length > 0) {
        return value;
      }
    }

    return null;
  }

  private toHex(topicPart: unknown): string | null {
    if (typeof topicPart === 'string') {
      const clean = topicPart.toLowerCase().replace(/^0x/, '');
      if (/^[0-9a-f]{64}$/i.test(clean)) {
        return clean;
      }

      try {
        return Buffer.from(topicPart, 'base64').toString('hex');
      } catch {
        return null;
      }
    }

    if (
      topicPart &&
      typeof topicPart === 'object' &&
      'toXDR' in topicPart &&
      typeof (topicPart as { toXDR?: unknown }).toXDR === 'function'
    ) {
      try {
        const base64 = (
          topicPart as { toXDR: (encoding?: string) => string }
        ).toXDR('base64');
        return Buffer.from(base64, 'base64').toString('hex');
      } catch {
        return null;
      }
    }

    return null;
  }
}

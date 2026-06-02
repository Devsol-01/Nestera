import { createHash } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { scValToNative, xdr } from '@stellar/stellar-sdk';
import {
  LedgerTransaction,
  LedgerTransactionStatus,
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

interface YieldPayload {
  publicKey: string;
  amount: string; // This represents the interest earned
  currencyCode: string;
  assetCode: string | null;
  assetIssuer: string | null;
  assetContractId: string | null;
}

@Injectable()
export class YieldHandler {
  private readonly logger = new Logger(YieldHandler.name);
  private static readonly YIELD_HASH_HEX = createHash('sha256')
    .update('Yield')
    .digest('hex');

  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
    private readonly currencyService: CurrencyService,
  ) {}

  async handle(event: IndexerEvent): Promise<boolean> {
    if (!this.isYieldTopic(event.topic)) {
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

      const user = await userRepo.findOne({
        where: [
          { publicKey: payload.publicKey },
          { walletAddress: payload.publicKey },
        ],
      });

      if (!user) {
        throw new Error(
          `Cannot map yield payload publicKey to user: ${payload.publicKey}`,
        );
      }

      const existingTx = await txRepo.findOne({ where: { eventId } });
      if (existingTx) {
        this.logger.debug(
          `Yield event ${eventId} already persisted. Skipping.`,
        );
        return;
      }

      await txRepo.save(
        txRepo.create({
          userId: user.id,
          type: LedgerTransactionType.YIELD,
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
          status: LedgerTransactionStatus.COMPLETED,
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

      const subscription = await subRepo.findOne({
        where: {
          userId: user.id,
          status: SubscriptionStatus.ACTIVE,
        },
        order: { createdAt: 'DESC' },
      });

      if (subscription) {
        // Increment the totalInterestEarned natively in the database to ensure absolute precision
        await manager.increment(
          UserSubscription,
          { id: subscription.id },
          'totalInterestEarned',
          amountAsNumber,
        );
      } else {
        this.logger.warn(
          `No active subscription found for user ${user.id} to apply yield to.`,
        );
      }
    });

    return true;
  }

  private isYieldTopic(topic: unknown[] | undefined): boolean {
    if (!Array.isArray(topic) || topic.length === 0) {
      return false;
    }

    const first = topic[0];
    const normalized = this.toHex(first);

    // Common topic hashes for yield events
    const YLD_DIST_HASH_HEX = createHash('sha256')
      .update('yld_dist')
      .digest('hex');

    const YIELD_PAYOUT_HASH_HEX = createHash('sha256')
      .update('YieldPayout') // Some contracts use YieldPayout explicitly
      .digest('hex');

    if (
      normalized === YieldHandler.YIELD_HASH_HEX ||
      normalized === YLD_DIST_HASH_HEX ||
      normalized === YIELD_PAYOUT_HASH_HEX
    ) {
      return true;
    }

    // Check if it's a Symbol XDR (Yield, YieldPayout, or yld_dist)
    if (typeof first === 'string') {
      try {
        const scVal = xdr.ScVal.fromXDR(first, 'base64');
        const symbol = scValToNative(scVal);
        return (
          symbol === 'Yield' ||
          symbol === 'YieldPayout' ||
          symbol === 'yld_dist'
        );
      } catch {
        // Not XDR, ignore
      }
    }

    return false;
  }

  private extractPayload(value: unknown): YieldPayload {
    const decoded = this.decodeScVal(value);
    const asRecord = this.ensureObject(decoded);

    const publicKey =
      this.pickString(asRecord, [
        'publicKey',
        'userPublicKey',
        'user',
        'address',
      ]) ?? '';
    const amountRaw =
      asRecord['amount'] ??
      asRecord['yield'] ??
      asRecord['interest'] ??
      asRecord['user_yield'] ??
      asRecord['actual_yield'] ??
      asRecord['payout'];

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
        'Invalid Yield payload: expected publicKey + numeric amount',
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
    return `${txHash}:${ledger}:yield`;
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

    // Handle the case where value is an array (like in yld_dist event containing [strategy, actual_yield, treasury_fee, user_yield])
    if (Array.isArray(value)) {
      // If it's an array without keys, we need to map it carefully.
      // yld_dist typically: [publicKey, total_yield, fee, net_yield]
      if (value.length >= 2) {
        return {
          publicKey: value[0],
          amount: value[3] ?? value[1], // Try the net_yield (index 3) first, else total (index 1)
        };
      }
    }

    throw new Error('Unexpected Yield payload shape.');
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

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
import { TransactionStateMachineService } from '../../transactions/transaction-state-machine.service';
import { ContractEventValidatorService } from '../contract-event-validator.service';

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
}

@Injectable()
export class YieldHandler {
  private readonly logger = new Logger(YieldHandler.name);
  private static readonly YIELD_HASH_HEX = createHash('sha256')
    .update('Yield')
    .digest('hex');

  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
    private readonly transactionStateMachine: TransactionStateMachineService,
    private readonly contractEventValidator: ContractEventValidatorService,
  ) {}

  async handle(event: RawBlockchainEvent): Promise<boolean> {
    if (!this.isYieldTopic(event.topic)) {
      return false;
    }

    const eventId = this.resolveEventId(event);
    const ledgerSequence =
      typeof event.ledger === 'number' ? event.ledger : null;
    const contractId =
      typeof event.contractId === 'string' ? event.contractId : null;
    const validationCtx = {
      handlerName: 'YieldHandler',
      eventId,
      ledgerSequence,
      contractId,
    };

    // Validate the raw event envelope before any decoding
    this.contractEventValidator.validateEnvelope(event, validationCtx);

    let payload: YieldPayload;
    try {
      payload = this.extractPayload(event.value);
    } catch (err) {
      this.logger.error('YieldHandler: failed to extract payload', {
        handlerName: 'YieldHandler',
        eventId,
        ledgerSequence,
        error: (err as Error).message,
      });
      throw err;
    }

    // Validate the decoded payload against the Yield schema
    this.contractEventValidator.validatePayload(
      'Yield',
      payload as unknown as Record<string, unknown>,
      validationCtx,
    );

    await this.dataSource.transaction(async (manager) => {
      const userRepo = manager.getRepository(User);
      const txRepo = manager.getRepository(LedgerTransaction);
      const subRepo = manager.getRepository(UserSubscription);

    if (!parseResult.ok) {
      await this.eventParser.quarantineEvent(
        event,
        parseResult.reason,
        parseResult.errorDetails,
        'Yield',
      );
      return true;
    }

    const { publicKey, amount, eventId, txHash, ledgerSequence, rawMeta } =
      parseResult.payload;

    // ── Business logic ───────────────────────────────────────────────────────
    try {
      await this.dataSource.transaction(async (manager) => {
        const userRepo = manager.getRepository(User);
        const txRepo = manager.getRepository(LedgerTransaction);
        const subRepo = manager.getRepository(UserSubscription);

        const user = await userRepo.findOne({
          where: [
            { publicKey },
            { walletAddress: publicKey },
          ],
        });

      const createdTx = await this.transactionStateMachine.createTransaction(
        {
          userId: user.id,
          type: LedgerTransactionType.YIELD,
          amount: payload.amount,
          publicKey: payload.publicKey,
          eventId,
          txHash: typeof event.txHash === 'string' ? event.txHash : null,
          ledgerSequence:
            typeof event.ledger === 'number' ? String(event.ledger) : null,
          metadata: {
            topic: event.topic,
            rawValueType: typeof event.value,
          },
          {
            manager,
            actor: 'blockchain-indexer',
            reason: 'Yield event ingested',
            metadata: { eventId },
          },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.PENDING_CONFIRMATION,
          { manager, actor: 'blockchain-indexer', reason: 'Yield pending confirmation' },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.CONFIRMED,
          { manager, actor: 'blockchain-indexer', reason: 'Yield confirmed on ledger' },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.COMPLETED,
          { manager, actor: 'blockchain-indexer', reason: 'Yield workflow completed' },
        );

        const subscription = await subRepo.findOne({
          where: { userId: user.id, status: SubscriptionStatus.ACTIVE },
          order: { createdAt: 'DESC' },
        });

        if (subscription) {
          await manager.increment(
            UserSubscription,
            { id: subscription.id },
            'totalInterestEarned',
            Number(amount),
          );
        } else {
          this.logger.warn(
            `No active subscription found for user ${user.id} to apply yield to.`,
          );
        }
      });
    } catch (err) {
      await this.eventParser.quarantineEvent(
        event,
        QuarantineReason.HANDLER_ERROR,
        (err as Error).message,
        'Yield',
      );
    }

    return true;
  }

  // ─── Topic detection ──────────────────────────────────────────────────────

  private isYieldTopic(topic: unknown): boolean {
    if (!Array.isArray(topic) || topic.length === 0) {
      return false;
    }

    const first = topic[0];
    const normalized = this.toHex(first);

    const YLD_DIST_HASH_HEX = createHash('sha256').update('yld_dist').digest('hex');
    const YIELD_PAYOUT_HASH_HEX = createHash('sha256').update('YieldPayout').digest('hex');

    if (
      normalized === YieldHandler.YIELD_HASH_HEX ||
      normalized === YLD_DIST_HASH_HEX ||
      normalized === YIELD_PAYOUT_HASH_HEX
    ) {
      return true;
    }

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
        const base64 = (topicPart as { toXDR: (enc?: string) => string }).toXDR('base64');
        return Buffer.from(base64, 'base64').toString('hex');
      } catch {
        return null;
      }
    }

    return null;
  }
}

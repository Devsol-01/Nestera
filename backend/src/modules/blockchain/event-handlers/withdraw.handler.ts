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

interface WithdrawPayload {
  publicKey: string;
  amount: string;
}

@Injectable()
export class WithdrawHandler {
  private readonly logger = new Logger(WithdrawHandler.name);
  private static readonly WITHDRAW_HASH_HEX = createHash('sha256')
    .update('Withdraw')
    .digest('hex');

  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
    private readonly transactionStateMachine: TransactionStateMachineService,
    private readonly contractEventValidator: ContractEventValidatorService,
  ) {}

  async handle(event: RawBlockchainEvent): Promise<boolean> {
    if (!this.isWithdrawTopic(event.topic)) {
      return false;
    }

    const eventId = this.resolveEventId(event);
    const ledgerSequence =
      typeof event.ledger === 'number' ? event.ledger : null;
    const contractId =
      typeof event.contractId === 'string' ? event.contractId : null;
    const validationCtx = {
      handlerName: 'WithdrawHandler',
      eventId,
      ledgerSequence,
      contractId,
    };

    // Validate the raw event envelope before any decoding
    this.contractEventValidator.validateEnvelope(event, validationCtx);

    let payload: WithdrawPayload;
    try {
      payload = this.extractPayload(event.value);
    } catch (err) {
      this.logger.error('WithdrawHandler: failed to extract payload', {
        handlerName: 'WithdrawHandler',
        eventId,
        ledgerSequence,
        error: (err as Error).message,
      });
      throw err;
    }

    // Validate the decoded payload against the Withdraw schema
    this.contractEventValidator.validatePayload(
      'Withdraw',
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
        'Withdraw',
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
          type: LedgerTransactionType.WITHDRAW,
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
        },
        {
          manager,
          actor: 'blockchain-indexer',
          reason: 'Withdraw event ingested',
          metadata: { eventId },
        },
      );
      await this.transactionStateMachine.transitionStatus(
        createdTx.id,
        LedgerTransactionStatus.PENDING_CONFIRMATION,
        {
          manager,
          actor: 'blockchain-indexer',
          reason: 'Withdraw pending confirmation',
        },
      );
      await this.transactionStateMachine.transitionStatus(
        createdTx.id,
        LedgerTransactionStatus.CONFIRMED,
        {
          manager,
          actor: 'blockchain-indexer',
          reason: 'Withdraw confirmed on ledger',
        },
      );
      await this.transactionStateMachine.transitionStatus(
        createdTx.id,
        LedgerTransactionStatus.COMPLETED,
        {
          manager,
          actor: 'blockchain-indexer',
          reason: 'Withdraw workflow completed',
        },
      );

        const existingTx = await txRepo.findOne({ where: { eventId } });
        if (existingTx) {
          this.logger.debug(
            `Withdraw event ${eventId} already persisted. Skipping.`,
          );
          return;
        }

        const createdTx = await this.transactionStateMachine.createTransaction(
          {
            userId: user.id,
            type: LedgerTransactionType.WITHDRAW,
            amount,
            publicKey,
            eventId,
            txHash,
            ledgerSequence,
            metadata: rawMeta,
          },
          {
            manager,
            actor: 'blockchain-indexer',
            reason: 'Withdraw event ingested',
            metadata: { eventId },
          },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.PENDING_CONFIRMATION,
          { manager, actor: 'blockchain-indexer', reason: 'Withdraw pending confirmation' },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.CONFIRMED,
          { manager, actor: 'blockchain-indexer', reason: 'Withdraw confirmed on ledger' },
        );
        await this.transactionStateMachine.transitionStatus(
          createdTx.id,
          LedgerTransactionStatus.COMPLETED,
          { manager, actor: 'blockchain-indexer', reason: 'Withdraw workflow completed' },
        );

        const subscription = await subRepo.findOne({
          where: { userId: user.id, status: SubscriptionStatus.ACTIVE },
          order: { createdAt: 'DESC' },
        });

        if (!subscription) {
          throw new Error(
            `No active subscription found for user ${user.id} to decrement withdrawal`,
          );
        }

        await manager.decrement(
          UserSubscription,
          { id: subscription.id },
          'amount',
          Number(amount),
        );
      });
    } catch (err) {
      await this.eventParser.quarantineEvent(
        event,
        QuarantineReason.HANDLER_ERROR,
        (err as Error).message,
        'Withdraw',
      );
    }

    return true;
  }

  // ─── Topic detection ──────────────────────────────────────────────────────

  private isWithdrawTopic(topic: unknown): boolean {
    if (!Array.isArray(topic) || topic.length === 0) {
      return false;
    }

    const first = topic[0];
    const normalized = this.toHex(first);

    if (normalized === WithdrawHandler.WITHDRAW_HASH_HEX) {
      return true;
    }

    if (typeof first === 'string') {
      try {
        const scVal = xdr.ScVal.fromXDR(first, 'base64');
        if (scValToNative(scVal) === 'Withdraw') {
          return true;
        }
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

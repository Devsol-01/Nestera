export const BALANCE_CHANGED_EVENT = 'balance.changed';
export const REORG_DETECTED_EVENT = 'balance.reorg.detected';
export const REORG_RESOLVED_EVENT = 'balance.reorg.resolved';
export const BALANCE_ROLLBACK_EVENT = 'balance.rollback';
export const BALANCE_CONFIRMED_EVENT = 'balance.confirmed';

/**
 * Emitted via @nestjs/event-emitter whenever a balance change is detected
 * for a subscribed Stellar account.
 *
 * Requirements: 3.1, 3.3, 3.4, 2.3 (confirmation depth)
 */
export class BalanceChangedEvent {
  /** Stellar G... public key of the account */
  accountId: string;
  /** Asset code: 'native' for XLM, otherwise the asset code string */
  assetCode: string;
  /** Balance before this update (string to avoid float precision loss) */
  previousBalance: string;
  /** Balance after this update */
  newBalance: string;
  /** UTC timestamp of the change */
  changedAt: Date;
  /** Ledger sequence number where this change occurred */
  ledgerSequence: number;
  /** Number of confirmations (blocks deep) when this event was emitted */
  confirmations: number;
  /** Whether this change is considered confirmed (≥ confirmationDepth) */
  isConfirmed: boolean;
  /** Transaction hash that caused this change (if applicable) */
  transactionHash?: string;
  /** Source of this balance change event */
  source: 'stream' | 'reconciliation' | 'rollback' | 'correction';
}

/**
 * Per-account connection health counters tracked by BalanceSyncService.
 * Requirement 6.1, extended with pending/confirmation tracking (2.3)
 */
export interface AccountMetrics {
  publicKey: string;
  streamUptimeSeconds: number;
  reconnectCount: number;
  fallbackActive: boolean;
  connectedAt: Date | null;
  /** Number of unconfirmed balance updates pending */
  pendingUpdateCount: number;
  /** Last processed ledger sequence */
  lastLedgerSequence: number;
  /** Last confirmed ledger sequence (confirmed depth behind head) */
  lastConfirmedLedger: number;
}

/**
 * Aggregated metrics summary returned by getMetricsSummary().
 * Requirement 6.1, 6.4, extended with reorg tracking (2.1)
 */
export interface ConnectionMetricsSummary {
  accounts: AccountMetrics[];
  anyFallbackActive: boolean;
  totalReconnects: number;
  /** Total number of unconfirmed updates across all accounts */
  totalPendingUpdates: number;
  /** Last detected reorg ledger (0 if none) */
  lastReorgDetectedAt: number;
  /** Number of reorgs detected since service start */
  totalReorgsDetected: number;
}

/**
 * In-memory handle for a single subscribed account's stream state.
 * Never persisted — lives only in the BalanceSyncService Map.
 */
export interface StreamHandle {
  /** Close function returned by Stellar SDK stream() */
  close: () => void;
  /** Whether the stream is currently considered connected */
  connected: boolean;
  /** Reconnect back-off state */
  reconnect: {
    delayMs: number;
    attempt: number;
    timer: NodeJS.Timeout | null;
  };
  /** Polling fallback interval handle */
  pollTimer: NodeJS.Timeout | null;
  /** Metrics for this account */
  metrics: AccountMetrics;
  /** Queue of unconfirmed balance updates awaiting confirmation */
  pendingQueue: PendingBalanceUpdate[];
  /** Highest ledger sequence seen for this account */
  highestLedgerSeen: number;
}

/**
 * Unconfirmed balance update waiting for confirmation depth.
 * Stored in the pending queue until enough blocks have passed.
 *
 * Requirements: 2.3 (queue balance updates until confirmed)
 */
export interface PendingBalanceUpdate {
  accountId: string;
  assetCode: string;
  newBalance: string;
  ledgerSequence: number;
  transactionHash?: string;
  queuedAt: Date;
}

/**
 * Emitted when a chain reorganization is detected.
 * Signals that balance state may need to be rolled back.
 *
 * Requirements: 2.1 (reorgs detected automatically)
 */
export class ReorgDetectedEvent {
  /** Ledger where reorg was detected */
  detectedAtLedger: number;
  /** Last known good ledger before reorg (rollback target) */
  rollbackToLedger: number;
  /** List of affected account IDs */
  affectedAccounts: string[];
  /** Description of the reorg cause */
  description?: string;
  /** Detection timestamp */
  detectedAt: Date;
}

/**
 * Emitted when a reorg has been fully resolved and state is consistent.
 */
export class ReorgResolvedEvent {
  reorgId: string;
  resolvedAt: Date;
  rolledBackCount: number;
  reappliedCount: number;
}

/**
 * Emitted for each balance that was rolled back due to a reorg.
 * Allows downstream services to adjust their state.
 */
export class BalanceRollbackEvent {
  accountId: string;
  assetCode: string;
  rolledBackToBalance: string;
  fromLedger: number;
  toLedger: number;
  rolledBackAt: Date;
}

/**
 * Configuration for balance synchronization with reorg handling
 */
export interface BalanceSyncConfig {
  /** Number of ledger confirmations required before treating balance as final (default: 3) */
  confirmationDepth: number;
  /** Maximum number of pending updates to queue per account (default: 100) */
  maxPendingQueueSize: number;
  /** Whether reorg detection is enabled (default: true) */
  enableReorgDetection: boolean;
  /** Cron expression for daily reconciliation job (default: '0 2 * * *' = 2am UTC) */
  reconciliationCron: string;
}

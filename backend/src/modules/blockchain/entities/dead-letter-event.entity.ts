import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('dead_letter_events')
export class DeadLetterEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Ledger sequence number at the time of failure */
  @Column({ type: 'bigint' })
  ledgerSequence: number;

  /** Raw Soroban event payload serialised to JSON string */
  @Column({ type: 'text' })
  rawEvent: string;

  /** Error message captured from the thrown exception */
  @Column({ type: 'text', nullable: true })
  errorMessage: string;

  /** Number of times this event has been retried */
  @Column({ type: 'integer', default: 0 })
  retryCount: number;

  /** When the next retry attempt should occur (null = retry immediately) */
  @Column({ type: 'timestamp', nullable: true })
  @Index()
  nextRetryAt: Date | null;

  /** The most recent error from the last retry attempt */
  @Column({ type: 'text', nullable: true })
  lastError: string | null;

  @CreateDateColumn()
  createdAt: Date;

  /** Timestamp of the last retry attempt */
  @Column({ type: 'timestamp', nullable: true })
  lastRetryAt: Date | null;
}

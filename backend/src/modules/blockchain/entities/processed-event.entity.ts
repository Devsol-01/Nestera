import { Entity, Column, PrimaryColumn, CreateDateColumn, Index } from 'typeorm';

@Entity('processed_stellar_events')
@Index(['contractId', 'eventId'], { unique: true })
export class ProcessedStellarEvent {
    @PrimaryColumn()
    eventId: string;

    @Column()
    contractId: string;

    @Column()
    transactionHash: string;

    @Column()
    ledger: number;

    @Column()
    eventType: string;

    @Column('jsonb')
    eventData: Record<string, any>;

    @Column({ nullable: true })
    claimId: string | null;

    @CreateDateColumn()
    processedAt: Date;
}

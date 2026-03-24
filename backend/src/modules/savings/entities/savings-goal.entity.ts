import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';

// ── Status enum ────────────────────────────────────────────────────────────────

export enum SavingsGoalStatus {
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED   = 'COMPLETED',
}

// ── Optional JSONB metadata shape ──────────────────────────────────────────────

/**
 * Arbitrary frontend-controlled metadata attached to a savings goal.
 *
 * All properties are optional so frontends can attach only what they need.
 * The interface is intentionally open (`[key: string]: unknown`) so new
 * fields (e.g. icon names, color tokens, progress animations) can be added
 * without a schema migration.
 *
 * Example values stored by a frontend:
 * ```json
 * {
 *   "imageUrl": "https://cdn.nestera.io/goals/car.jpg",
 *   "iconRef":  "car-icon",
 *   "color":    "#4F46E5"
 * }
 * ```
 */
export interface SavingsGoalMetadata {
  /** Full URL of a cover image chosen by the user */
  imageUrl?: string;
  /** Short icon identifier (maps to a frontend icon library key) */
  iconRef?: string;
  /** Hex or CSS color token for UI theming */
  color?: string;
  /** Allow any additional frontend-defined keys */
  [key: string]: unknown;
}

// ── Entity ──────────────────────────────────────────────────────────────────────

/**
 * SavingsGoal — off-chain vault metadata enabling users to set localised
 * savings goals ("Buy a Car", "Summer Vacation") connected to their yield
 * pools / UserSubscriptions.
 *
 * Table: savings_goals
 *
 * Relationships:
 *  - ManyToOne → users (userId FK)
 *    One user can have many goals; each goal belongs to exactly one user.
 *    The relation is lazy by default (not eager loaded) to keep profile
 *    queries fast — callers opt-in via QueryBuilder or `relations` option.
 */
@Entity('savings_goals')
export class SavingsGoal {
  // ── Primary key ─────────────────────────────────────────────────────────────

  @PrimaryGeneratedColumn('uuid')
  id: string;

  // ── Foreign key – owner ─────────────────────────────────────────────────────

  /**
   * UUID of the owning user.
   * Stored as a bare column (matches the FK convention used in UserSubscription).
   * The ManyToOne relation below maps the object-level `user` property.
   */
  @Column('uuid')
  userId: string;

  // ── Goal parameters ─────────────────────────────────────────────────────────

  /**
   * Human-readable label set by the user.
   * e.g. "Buy a Car", "Emergency Fund", "Summer Vacation 2026"
   */
  @Column({ type: 'varchar', length: 255 })
  goalName: string;

  /**
   * The monetary amount the user is aiming to accumulate.
   * Stored as decimal(14, 2) — consistent with other money columns in this
   * codebase (SavingsProduct.minAmount, UserSubscription.amount, etc.).
   */
  @Column('decimal', { precision: 14, scale: 2 })
  targetAmount: number;

  /**
   * Date by which the user wants to reach `targetAmount`.
   * Stored as DATE (no time component) to match the `startDate`/`endDate`
   * convention in UserSubscription.
   */
  @Column({ type: 'date' })
  targetDate: Date;

  /**
   * Lifecycle status of the goal.
   * Defaults to IN_PROGRESS on creation; transitions to COMPLETED when the
   * user (or a background job) marks it done.
   */
  @Column({
    type: 'enum',
    enum: SavingsGoalStatus,
    default: SavingsGoalStatus.IN_PROGRESS,
  })
  status: SavingsGoalStatus;

  // ── Optional rich metadata ──────────────────────────────────────────────────

  /**
   * Arbitrary JSON blob for frontend-controlled display metadata.
   *
   * Stored as PostgreSQL JSONB so the DB can index and query individual keys
   * without migrating the schema. Nullable — omitted entirely when not set.
   *
   * Typed as `SavingsGoalMetadata | null` on the application side;
   * at runtime TypeORM transparently serialises / deserialises the object.
   *
   * Example usage by a frontend:
   * ```ts
   * metadata: {
   *   imageUrl: 'https://cdn.nestera.io/goals/car.jpg',
   *   iconRef:  'car-icon',
   *   color:    '#4F46E5',
   * }
   * ```
   */
  @Column({ type: 'jsonb', nullable: true })
  metadata: SavingsGoalMetadata | null;

  // ── Audit timestamps ────────────────────────────────────────────────────────

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // ── Relations ───────────────────────────────────────────────────────────────

  /**
   * The User who owns this goal.
   * Not eager-loaded; use `{ relations: ['user'] }` or a QueryBuilder
   * `leftJoinAndSelect` when you need the full user object.
   */
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}

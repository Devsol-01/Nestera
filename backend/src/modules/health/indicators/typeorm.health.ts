import { Injectable } from '@nestjs/common';
import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { DataSource } from 'typeorm';
import { snapshotPgPool } from '../../../config/connection-pool.config';

type PgDriverLike = {
  isReplicated?: boolean;
  master?: { totalCount: number; idleCount: number; waitingCount: number };
  slaves?: Array<{
    totalCount: number;
    idleCount: number;
    waitingCount: number;
  }>;
};

/**
 * TypeORM + PostgreSQL health: verifies primary connectivity, optionally checks a read replica,
 * and surfaces `pg` pool queue metrics for monitoring.
 */
@Injectable()
export class TypeOrmHealthIndicator extends HealthIndicator {
  constructor(private readonly dataSource: DataSource) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    const driver = this.dataSource.driver as PgDriverLike;
    const pools: Record<string, unknown> = {};

    if (driver.master) {
      pools.master = snapshotPgPool(driver.master);
    }
    if (driver.slaves?.length) {
      pools.replicas = driver.slaves.map((s) => snapshotPgPool(s));
    }

    const overallStart = Date.now();

    try {
      const masterStart = Date.now();
      const masterRunner = this.dataSource.createQueryRunner('master');
      try {
        await masterRunner.query('SELECT 1');
      } finally {
        await masterRunner.release();
      }
      const masterResponseTime = Date.now() - masterStart;

      let replicaCheck: 'skipped' | 'ok' = 'skipped';
      if (driver.isReplicated && driver.slaves?.length) {
        const replicaRunner = this.dataSource.createQueryRunner('slave');
        try {
          await replicaRunner.query('SELECT 1');
          replicaCheck = 'ok';
        } finally {
          await replicaRunner.release();
        }
      }

      const totalElapsed = Date.now() - overallStart;
      const isWithinBounds = masterResponseTime <= 200;

      const result = this.getStatus(key, isWithinBounds, {
        responseTime: `${masterResponseTime}ms`,
        totalElapsed: `${totalElapsed}ms`,
        threshold: '200ms',
        pools,
        replicaCheck,
      });

      if (!isWithinBounds) {
        throw new HealthCheckError(
          `Database primary query exceeded acceptable response time (${masterResponseTime}ms > 200ms)`,
          result,
        );
      }

      return result;
    } catch (error) {
      const totalElapsed = Date.now() - overallStart;
      const result = this.getStatus(key, false, {
        message: error instanceof Error ? error.message : 'Unknown error',
        totalElapsed: `${totalElapsed}ms`,
        pools,
      });

      throw new HealthCheckError('Database health check failed', result);
    }
  }
}

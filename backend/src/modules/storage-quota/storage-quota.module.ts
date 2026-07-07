import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { StorageQuota } from './entities/storage-quota.entity';
import { StorageQuotaLedger } from './entities/storage-quota-ledger.entity';
import { StorageQuotaService } from './storage-quota.service';
import { StorageQuotaCleanupService } from './storage-quota-cleanup.service';
import { StorageQuotaConfig } from './storage-quota.types';

/**
 * @Global so that {@link StorageQuotaService} can be injected by any feature
 * module without each one having to import this. Entity / provider factories
 * are still encapsulated inside the module.
 */
@Global()
@Module({
  imports: [TypeOrmModule.forFeature([StorageQuota, StorageQuotaLedger])],
  providers: [
    StorageQuotaConfig,
    StorageQuotaService,
    StorageQuotaCleanupService,
  ],
  exports: [StorageQuotaService, StorageQuotaConfig],
})
export class StorageQuotaModule {}

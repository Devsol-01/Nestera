import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { StorageService } from './storage.service';
import { StorageAccessService } from './storage-access.service';
import { StorageController } from './storage.controller';
import { LocalStorageProvider } from './providers/local-storage.provider';
import { S3StorageProvider } from './providers/s3-storage.provider';
import { FileUploadConfigService } from './file-upload-config.service';
import { StorageCleanupService } from './storage-cleanup.service';
import { AuthModule } from '../../auth/auth.module';

@Module({
  imports: [ConfigModule, AuthModule],
  controllers: [StorageController],
  providers: [
    StorageService,
    StorageAccessService,
    LocalStorageProvider,
    S3StorageProvider,
    FileUploadConfigService,
    StorageCleanupService,
  ],
  exports: [StorageService, StorageAccessService, FileUploadConfigService],
})
export class StorageModule {}

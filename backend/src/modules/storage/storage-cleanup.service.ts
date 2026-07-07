import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { DataSource } from 'typeorm';
import { StorageAccessService } from './storage-access.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class StorageCleanupService {
  private readonly logger = new Logger(StorageCleanupService.name);
  private readonly retentionPeriodHours: number;

  constructor(
    private readonly storageAccess: StorageAccessService,
    private readonly dataSource: DataSource,
    private readonly configService: ConfigService,
  ) {
    this.retentionPeriodHours = this.configService.get<number>('upload.orphanRetentionHours') || 24;
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupOrphanedFiles() {
    this.logger.log('Starting orphaned storage files cleanup job...');
    
    try {
      // 1. Get all files in storage
      const provider = this.storageAccess.getProvider();
      const allFiles = await provider.listAll();
      
      this.logger.log(`Found ${allFiles.length} files in storage provider: ${provider.name}`);
      
      if (allFiles.length === 0) {
        return;
      }

      // 2. Fetch all referenced file URLs/keys from the database
      const referencedKeys = await this.getAllReferencedKeys();
      
      let deletedCount = 0;
      const now = new Date();
      
      // 3. Check each file
      for (const file of allFiles) {
        const isReferenced = referencedKeys.has(file.key);
        
        if (!isReferenced) {
          // Check if it's older than retention period
          const fileAgeHours = (now.getTime() - file.lastModified.getTime()) / (1000 * 60 * 60);
          
          if (fileAgeHours > this.retentionPeriodHours) {
            try {
              this.logger.debug(`Deleting orphaned file: ${file.key} (Age: ${Math.round(fileAgeHours)}h)`);
              await provider.delete(file.key);
              deletedCount++;
            } catch (deleteError) {
              this.logger.error(`Failed to delete orphaned file ${file.key}:`, deleteError);
            }
          }
        }
      }
      
      this.logger.log(`Cleanup complete. Deleted ${deletedCount} orphaned files.`);
    } catch (error) {
      this.logger.error('Error during storage cleanup job:', error);
    }
  }
  
  /**
   * Queries known tables for columns that store file references.
   * Returns a Set of keys/urls to allow for fast O(1) lookups.
   */
  private async getAllReferencedKeys(): Promise<Set<string>> {
    const keys = new Set<string>();
    
    // Safety check: verify if tables exist before querying them to avoid errors in tests/empty dbs
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    
    try {
      // Users table: avatarUrl and kycDocumentUrl
      if (await queryRunner.hasTable('users')) {
        const users = await queryRunner.query('SELECT "avatarUrl", "kycDocumentUrl" FROM users');
        for (const user of users) {
          if (user.avatarUrl) keys.add(user.avatarUrl);
          if (user.kycDocumentUrl) keys.add(user.kycDocumentUrl);
        }
      }
      
      // Feedback submissions: screenshotUrl
      if (await queryRunner.hasTable('feedback_submissions')) {
        const feedbacks = await queryRunner.query('SELECT "screenshotUrl" FROM feedback_submissions WHERE "screenshotUrl" IS NOT NULL');
        for (const feedback of feedbacks) {
          if (feedback.screenshotUrl) keys.add(feedback.screenshotUrl);
        }
      }
      
      // Dispute messages: evidenceUrl
      if (await queryRunner.hasTable('dispute_messages')) {
        const messages = await queryRunner.query('SELECT "evidenceUrl" FROM dispute_messages WHERE "evidenceUrl" IS NOT NULL');
        for (const msg of messages) {
          if (msg.evidenceUrl) keys.add(msg.evidenceUrl);
        }
      }
    } finally {
      await queryRunner.release();
    }
    
    return keys;
  }
}

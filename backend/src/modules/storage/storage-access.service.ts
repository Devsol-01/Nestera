import {
  Injectable,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
  Optional,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { extname } from 'path';
import { randomUUID } from 'crypto';
import { StorageProvider } from './providers/storage-provider.interface';
import { LocalStorageProvider } from './providers/local-storage.provider';
import { S3StorageProvider } from './providers/s3-storage.provider';
import { TestModeService } from '../../common/test-mode/test-mode.service';

export interface FileAccessRule {
  key: string;
  ownerId: string;
  visibility: 'private' | 'public';
}

@Injectable()
export class StorageAccessService {
  private readonly signedUrlTtl: number;
  private readonly accessRules = new Map<string, FileAccessRule>();

  constructor(
    private readonly configService: ConfigService,
    private readonly localProvider: LocalStorageProvider,
    private readonly s3Provider: S3StorageProvider,
    @Optional() private readonly testModeService?: TestModeService,
  ) {
    this.signedUrlTtl = this.configService.get<number>(
      'upload.signedUrlTtlSeconds',
      3600,
    );
  }

  getProvider(): StorageProvider {
    if (this.testModeService?.isEnabled) {
      return this.testModeService.storageProvider;
    }
    const providerName =
      this.configService.get<string>('upload.provider') || 'local';
    return providerName === 's3' ? this.s3Provider : this.localProvider;
  }

  registerAccessRule(rule: FileAccessRule): void {
    this.accessRules.set(rule.key, rule);
  }

  async getSignedDownloadUrl(
    key: string,
    requesterId: string,
    isAdmin = false,
  ): Promise<string> {
    await this.assertAccess(key, requesterId, 'read', isAdmin);
    return this.getProvider().getSignedUrl(key, {
      operation: 'read',
      expiresInSeconds: this.signedUrlTtl,
      ownerId: requesterId,
    });
  }

  async getSignedUploadUrl(
    originalName: string,
    ownerId: string,
    contentType: string,
  ): Promise<{ key: string; uploadUrl: string; expiresIn: number }> {
    const key = this.buildKey(originalName);
    this.registerAccessRule({ key, ownerId, visibility: 'private' });

    const uploadUrl = await this.getProvider().getSignedUrl(key, {
      operation: 'write',
      expiresInSeconds: this.signedUrlTtl,
      ownerId,
    });

    return { key, uploadUrl, expiresIn: this.signedUrlTtl };
  }

  async assertAccess(
    key: string,
    requesterId: string,
    operation: 'read' | 'write',
    isAdmin = false,
  ): Promise<void> {
    const rule = this.accessRules.get(key);
    if (!rule) {
      const exists = await this.getProvider().exists(key);
      if (!exists) {
        throw new NotFoundException(`File not found: ${key}`);
      }
      return;
    }

    if (rule.visibility === 'public' && operation === 'read') {
      return;
    }

    if (!isAdmin && rule.ownerId !== requesterId) {
      throw new ForbiddenException('Access denied to this file');
    }
  }

  verifyLocalSignedUrl(params: {
    key: string;
    operation: string;
    ownerId?: string;
    expiresAt: number;
    nonce: string;
    signature: string;
  }): boolean {
    if (this.testModeService?.isEnabled) {
      return true;
    }
    return this.localProvider.verifySignedUrl(params);
  }

  readLocalFile(key: string): Buffer {
    if (this.testModeService?.isEnabled) {
      return this.testModeService.storageProvider.readFile(key);
    }
    return this.localProvider.readFile(key);
  }

  buildKey(originalName: string, prefix = 'files'): string {
    const ext = extname(originalName);
    return `${prefix}/${randomUUID()}${ext}`;
  }
}

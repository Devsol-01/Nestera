import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { existsSync, mkdirSync, writeFileSync, unlinkSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { createHmac, randomUUID } from 'crypto';
import { StorageProvider, StoredFile } from './storage-provider.interface';

@Injectable()
export class LocalStorageProvider implements StorageProvider {
  readonly name = 'local';
  private readonly baseDir: string;
  private readonly signingSecret: string;

  constructor(private readonly configService: ConfigService) {
    this.baseDir =
      this.configService.get<string>('upload.localDir') || './uploads';
    this.signingSecret =
      this.configService.get<string>('jwt.secret') || 'local-storage-secret';
    this.ensureDir(this.baseDir);
  }

  async save(
    buffer: Buffer,
    options: {
      key: string;
      contentType: string;
      ownerId?: string;
      visibility?: 'private' | 'public';
    },
  ): Promise<StoredFile> {
    const filePath = join(this.baseDir, options.key);
    this.ensureDir(dirname(filePath));
    writeFileSync(filePath, buffer);

    return {
      key: options.key,
      path: `/uploads/${options.key}`,
      size: buffer.length,
      contentType: options.contentType,
    };
  }

  async delete(key: string): Promise<void> {
    const filePath = join(this.baseDir, key);
    if (existsSync(filePath)) {
      unlinkSync(filePath);
    }
  }

  async exists(key: string): Promise<boolean> {
    return existsSync(join(this.baseDir, key));
  }

  async getSignedUrl(
    key: string,
    options: {
      operation: 'read' | 'write';
      expiresInSeconds: number;
      ownerId?: string;
    },
  ): Promise<string> {
    const expiresAt = Math.floor(Date.now() / 1000) + options.expiresInSeconds;
    const nonce = randomUUID();
    const payload = `${key}:${options.operation}:${options.ownerId ?? ''}:${expiresAt}:${nonce}`;
    const signature = createHmac('sha256', this.signingSecret)
      .update(payload)
      .digest('hex');

    const params = new URLSearchParams({
      key,
      op: options.operation,
      exp: String(expiresAt),
      nonce,
      sig: signature,
      ...(options.ownerId ? { owner: options.ownerId } : {}),
    });

    return `/api/storage/signed?${params.toString()}`;
  }

  verifySignedUrl(params: {
    key: string;
    operation: string;
    ownerId?: string;
    expiresAt: number;
    nonce: string;
    signature: string;
  }): boolean {
    if (Date.now() / 1000 > params.expiresAt) {
      return false;
    }

    const payload = `${params.key}:${params.operation}:${params.ownerId ?? ''}:${params.expiresAt}:${params.nonce}`;
    const expected = createHmac('sha256', this.signingSecret)
      .update(payload)
      .digest('hex');

    return expected === params.signature;
  }

  readFile(key: string): Buffer {
    return readFileSync(join(this.baseDir, key));
  }

  private ensureDir(dir: string) {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  async listAll(): Promise<{ key: string; lastModified: Date }[]> {
    const files: { key: string; lastModified: Date }[] = [];

    const walk = (dir: string, currentPrefix: string = '') => {
      if (!existsSync(dir)) return;
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        const key = currentPrefix ? `${currentPrefix}/${entry.name}` : entry.name;
        
        if (entry.isDirectory()) {
          walk(fullPath, key);
        } else {
          const stats = statSync(fullPath);
          files.push({ key, lastModified: stats.mtime });
        }
      }
    };

    walk(this.baseDir);
    return files;
  }
}
